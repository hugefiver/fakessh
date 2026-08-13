//go:build !no_fakeshell && !plan9
// +build !no_fakeshell,!plan9

package fakeshell

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/hugefiver/fakessh/modules/fakeshell/conf"
	"github.com/spf13/afero"
)

// RootFS resource caps. These guard against resource-exhaustion / zip-bomb
// style attacks by bounding the number of inodes and the length of any single
// path materialized in the in-memory filesystem. Fail closed on overflow.
const (
	// MaxRootFSEntries bounds the total number of entries (files + dirs)
	// materialized from a rootfs source. A larger archive is rejected.
	MaxRootFSEntries = 10000

	// MaxRootFSPathLen bounds the cleaned POSIX-relative length of any single
	// entry path. Longer paths are rejected.
	MaxRootFSPathLen = 512

	// MaxRootFSFileBodyBytes bounds the body of a single regular-file entry
	// read from a tar/tar.gz/tgz source during loading. Regular-file contents
	// are NEVER stored in the fake filesystem (only zero-byte placeholders are
	// created), but the loader still has to drain each body to keep the tar
	// stream aligned. Without a per-file cap, a single header advertising a
	// huge Size could force the loader to read gigabytes of (decompressed)
	// bytes from disk/network, causing startup I/O, CPU and decompression
	// DoS. This cap bounds the per-file drain only.
	MaxRootFSFileBodyBytes = 16 << 20 // 16 MiB

	// MaxRootFSTotalBodyBytes bounds the total regular-file body bytes drained
	// across all entries of a single tar/tar.gz/tgz source. Same rationale as
	// MaxRootFSFileBodyBytes but for many-files cumulative DoS. Regular-file
	// contents are still never stored.
	MaxRootFSTotalBodyBytes = 64 << 20 // 64 MiB

	// MaxRootFSTarStreamBytes bounds the total number of decompressed tar
	// stream bytes consumed by loadRootFSFromReader, including bytes that
	// archive/tar.Reader.Next() reads internally while parsing PAX/GNU
	// metadata headers (TypeXHeader / TypeXGlobalHeader / TypeGNULongName /
	// TypeGNULongLink) and the block padding between entries. Next() consumes
	// those metadata bodies before it returns, so the per-file and cumulative
	// body caps in drainTarBody cannot see them; a malicious archive with
	// many large PAX/GNU metadata headers could otherwise force unbounded
	// decompressed I/O before any existing cap fires.
	//
	// The value is intentionally large enough to admit any archive that
	// respects MaxRootFSEntries, MaxRootFSFileBodyBytes and
	// MaxRootFSTotalBodyBytes: the worst-case valid archive drains at most
	// MaxRootFSTotalBodyBytes of regular-file body bytes, plus at most
	// MaxRootFSEntries headers/padding (each ~512 bytes plus up to 1 KiB of
	// PAX/GNU metadata). The extra 1024 bytes of slack covers the final
	// two zero blocks and any trailing padding. Choosing a smaller value
	// would reject legitimate under-cap archives.
	MaxRootFSTarStreamBytes = MaxRootFSTotalBodyBytes + int64(MaxRootFSEntries)*1024 + 1024

	// MaxRootFSZipCentralDirectoryBytes bounds the size of the zip central
	// directory that loadRootFSFromZip is willing to let archive/zip parse.
	// archive/zip's zip.NewReader reads and parses the entire central
	// directory up front (allocating one *zip.File per entry), so an attacker
	// could craft an archive with a huge central directory to exhaust memory
	// before the per-entry cap is enforced. preflightZipDirectory reads only
	// the EOCD tail and rejects archives whose central directory exceeds this
	// cap before zip.NewReader is called. The value is intentionally larger
	// than MaxRootFSEntries * (MaxRootFSPathLen + fixed-overhead) so that a
	// maximally-deep but otherwise valid archive still loads, while a
	// pathological central directory is rejected.
	MaxRootFSZipCentralDirectoryBytes = 8 << 20 // 8 MiB

	// rootFSDirReadBatchSize is the batch size used by loadRootFSFromDir when
	// streaming directory entries via (*os.File).ReadDir. It bounds the
	// per-directory allocation and lets the loader fail closed on entry-count
	// overflow as soon as a batch crosses the cap, without reading the entire
	// huge directory into memory at once.
	rootFSDirReadBatchSize = 256
)

// LoadRootFS loads the fakeshell root filesystem for the given config.
//
// If c.RootFS is empty, the embedded assets/rootfs.tar.gz (embeddedFsGzip from
// module.go) is decoded into an isolated afero.NewMemMapFs(). If c.RootFS is
// non-empty, it must already have been validated by conf.CheckAndFillConfig
// and point to an existing directory or supported archive on the host. The
// supported archive types are: directory, ".tar", ".tar.gz", ".tgz", ".zip".
//
// Only directories and regular-file *names* are materialized; regular files
// are created as zero-byte placeholders. File contents are never copied from
// the host or from archives, which keeps memory bounded regardless of the
// size of the source rootfs. Symlinks, hardlinks, device nodes, FIFOs,
// sockets, reparse points and any other special file types are rejected
// (fail closed) rather than skipped.
//
// Any decode/load failure returns a non-nil error and the resulting fs is not
// usable; the caller must abort shell startup rather than fall back to an
// empty filesystem.
func LoadRootFS(c *conf.FakeshellConfig) (afero.Fs, error) {
	if c == nil {
		return nil, errors.New("fakeshell: LoadRootFS called with nil config")
	}

	memfs := afero.NewMemMapFs()

	if c.RootFS == "" {
		if err := loadRootFSFromReader(memfs, "embedded:assets/rootfs.tar.gz", bytes.NewReader(embeddedFsGzip)); err != nil {
			return nil, fmt.Errorf("fakeshell: load embedded rootfs: %w", err)
		}
		return memfs, nil
	}

	info, err := lstatRootFS(c.RootFS)
	if err != nil {
		return nil, fmt.Errorf("fakeshell: rootfs %q is not accessible: %w", c.RootFS, err)
	}
	if err := rejectSpecial(info, c.RootFS); err != nil {
		return nil, fmt.Errorf("fakeshell: rootfs %q rejected: %w", c.RootFS, err)
	}
	if info.IsDir() {
		if err := loadRootFSFromDir(memfs, c.RootFS, info); err != nil {
			return nil, fmt.Errorf("fakeshell: load rootfs dir %q: %w", c.RootFS, err)
		}
		return memfs, nil
	}

	if err := loadRootFSFromFile(memfs, c.RootFS, info); err != nil {
		return nil, fmt.Errorf("fakeshell: load rootfs archive %q: %w", c.RootFS, err)
	}
	return memfs, nil
}

// nodeCounter tracks every fake-FS node materialized by a loader — both
// explicit entries (from archive headers or directory walks) and the implicit
// parent directories created by MkdirAll / Create. Paths are de-duplicated so
// that repeated headers or shared ancestors are counted only once, and the
// root "." / "" is never counted.
//
// This closes a counting gap where a tar or zip containing many deep file
// paths but no directory headers could materialize far more in-memory nodes
// than MaxRootFSEntries while the raw header count stayed under the cap. For
// example, 5001 entries like "d00000/file" have a header count of 5001 but
// materialize 10002 nodes (5001 implicit dirs + 5001 files).
type nodeCounter struct {
	seen  map[string]struct{}
	count int
}

func newNodeCounter() *nodeCounter {
	return &nodeCounter{seen: make(map[string]struct{})}
}

// add records clean (a POSIX-relative path already validated and cleaned by
// cleanArchivePath) together with every not-yet-seen ancestor directory as a
// materialized node. The root "." / "" is ignored. Returns an error if the
// total node count would exceed MaxRootFSEntries (fail closed).
func (nc *nodeCounter) add(clean string) error {
	if clean == "" || clean == "." {
		return nil
	}
	// Walk from the topmost ancestor down to the path itself so that parents
	// are counted before the leaf. clean is already POSIX-style with no
	// leading slash and no ".." segments.
	parts := strings.Split(clean, "/")
	cur := ""
	for _, seg := range parts {
		if seg == "" {
			continue
		}
		if cur == "" {
			cur = seg
		} else {
			cur = cur + "/" + seg
		}
		if _, ok := nc.seen[cur]; ok {
			continue
		}
		nc.seen[cur] = struct{}{}
		nc.count++
		if nc.count > MaxRootFSEntries {
			return fmt.Errorf("exceeds MaxRootFSEntries (%d)", MaxRootFSEntries)
		}
	}
	return nil
}

// limitedRootFSTarReader wraps an io.Reader and fails closed once more than
// MaxRootFSTarStreamBytes bytes have been read. It is used by
// loadRootFSFromReader to bound the TOTAL decompressed tar stream consumed by
// tar.Reader.Next() and tar.Reader.Read(), including PAX/GNU metadata bodies
// that archive/tar.Reader.Next() reads internally before returning (and which
// the per-file / cumulative body caps in drainTarBody therefore cannot see).
//
// Read returns a non-io.EOF error once the cap is exceeded so that the tar
// reader surfaces a real failure rather than a silent truncated EOF. The cap
// is checked after each Read so that an exactly-cap-sized stream is allowed
// (the next Read past the cap returns the error). This means a stream of
// exactly MaxRootFSTarStreamBytes bytes is accepted; the (cap+1)th byte trips
// the guard.
type limitedRootFSTarReader struct {
	r       io.Reader
	read    int64
	maxRead int64
}

// newLimitedRootFSTarReader returns a reader that fails closed after
// MaxRootFSTarStreamBytes decompressed bytes have been consumed.
func newLimitedRootFSTarReader(r io.Reader) *limitedRootFSTarReader {
	return &limitedRootFSTarReader{r: r, maxRead: MaxRootFSTarStreamBytes}
}

func (l *limitedRootFSTarReader) Read(p []byte) (int, error) {
	if l.read >= l.maxRead {
		return 0, fmt.Errorf("exceeds MaxRootFSTarStreamBytes (%d) decompressed tar stream bytes", l.maxRead)
	}
	n, err := l.r.Read(p)
	l.read += int64(n)
	if l.read > l.maxRead {
		// Cap exceeded by this Read. Surface a fail-closed error. Use the
		// cap-exceeded error in preference to any err from the underlying
		// reader (including io.EOF) so the caller cannot mistake a
		// truncated-over-cap stream for a clean end-of-archive.
		return n, fmt.Errorf("exceeds MaxRootFSTarStreamBytes (%d) decompressed tar stream bytes", l.maxRead)
	}
	return n, err
}

// loadRootFSFromReader decodes a tar stream (optionally gzip-compressed) from r
// into fs. It is used for the embedded rootfs as well as ".tar", ".tar.gz" and
// ".tgz" archive files. name is used only for error attribution.
//
// The reader is consumed incrementally; regular-file bodies are discarded and
// never copied into fs, so memory use is bounded by MaxRootFSEntries and
// MaxRootFSPathLen rather than by the size of the archive contents. The total
// regular-file body bytes drained is bounded by MaxRootFSFileBodyBytes (per
// file) and MaxRootFSTotalBodyBytes (cumulative), preventing startup I/O/CPU/
// decompression DoS from a header advertising a huge Size or many large files.
// In addition the TOTAL decompressed tar stream consumed by tar.Reader.Next()
// and tar.Reader.Read() - including PAX/GNU metadata bodies that Next() reads
// internally before returning - is bounded by MaxRootFSTarStreamBytes, so a
// malicious archive with many large metadata headers cannot bypass the
// regular-file body caps. Regular-file contents are never stored regardless of
// the caps.
func loadRootFSFromReader(out afero.Fs, name string, r io.Reader) error {
	// Peek the first two bytes to decide gzip vs. plain tar. gzip magic is
	// 0x1f 0x8b. This lets the embedded .tar.gz and on-disk .tar/.tgz share
	// one code path without relying on the filename extension.
	br := newPeekReader(r)
	magic, err := br.peekN(2)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("%s: read magic: %w", name, err)
	}

	var tr *tar.Reader
	if len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gzr, gzErr := gzip.NewReader(br)
		if gzErr != nil {
			return fmt.Errorf("%s: gzip header: %w", name, gzErr)
		}
		// Bound the decompressed tar stream BEFORE handing it to
		// tar.NewReader. tar.Reader.Next() consumes PAX/GNU metadata header
		// bodies internally before returning, so the per-file and cumulative
		// body caps in drainTarBody cannot see those bytes. Wrapping the
		// decompressed reader bounds ALL bytes Next() and Read() pull,
		// including metadata bodies and block padding. Apply the wrapper
		// AFTER gzip.NewReader so we count decompressed (not compressed)
		// bytes.
		tr = tar.NewReader(newLimitedRootFSTarReader(gzr))
	} else {
		// Plain tar: bound the raw reader the same way so metadata bodies
		// consumed inside Next() are counted against the global cap.
		tr = tar.NewReader(newLimitedRootFSTarReader(br))
	}

	count := newNodeCounter()
	// rawHeaders bounds the number of tar headers processed regardless of
	// whether they materialize a fake-FS node. It is independent of
	// nodeCounter, which de-dups by path: an attacker can submit many
	// duplicate headers for the same safe path (or many root "." / metadata
	// entries that never materialize) to exhaust processing while keeping
	// the materialized-node count under the cap. Fail closed on overflow.
	rawHeaders := 0
	// totalBodyBytes tracks the cumulative regular-file body bytes drained
	// so we can fail closed on MaxRootFSTotalBodyBytes. Regular-file contents
	// are never stored; this only bounds loader I/O/decompression.
	totalBodyBytes := int64(0)
	for {
		hdr, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("%s: tar read: %w", name, err)
		}

		// Count every header returned by tr.Next() before any cleaning,
		// de-dup, or type dispatch so duplicates and root entries are
		// included.
		rawHeaders++
		if rawHeaders > MaxRootFSEntries {
			return fmt.Errorf("%s: exceeds MaxRootFSEntries (%d) raw tar headers", name, MaxRootFSEntries)
		}

		clean, err := cleanArchivePath(hdr.Name)
		if err != nil {
			return fmt.Errorf("%s: entry %q: %w", name, hdr.Name, err)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if clean == "" || clean == "." {
				// Root directory entries are validated but never materialized or
				// counted as fake-FS nodes.
				continue
			}
			// Count the explicit directory and any implicit parents BEFORE
			// materializing, so we fail closed without creating nodes beyond
			// the cap.
			if err := count.add(clean); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			if err := out.MkdirAll(memPath(clean), 0o755); err != nil {
				return fmt.Errorf("%s: mkdir %q: %w", name, clean, err)
			}
		case tar.TypeReg, tar.TypeRegA:
			// Drain every regular body exactly once before materialization. This
			// also applies to root-cleaning entries, which are never materialized
			// but must not bypass size and short-body validation.
			if err := drainTarBody(name, clean, tr, hdr.Size, &totalBodyBytes); err != nil {
				return err
			}
			if clean == "" || clean == "." {
				continue
			}
			// Regular files become zero-byte placeholders. Do NOT copy hdr.Size
			// bytes from tr into the fake filesystem.
			if err := count.add(clean); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			f, err := out.Create(memPath(clean))
			if err != nil {
				return fmt.Errorf("%s: create %q: %w", name, clean, err)
			}
			if err := f.Close(); err != nil {
				return fmt.Errorf("%s: close %q: %w", name, clean, err)
			}
		case tar.TypeSymlink, tar.TypeLink:
			return fmt.Errorf("%s: entry %q: symlink/hardlink not allowed", name, hdr.Name)
		case tar.TypeChar, tar.TypeBlock:
			return fmt.Errorf("%s: entry %q: device node not allowed", name, hdr.Name)
		case tar.TypeFifo:
			return fmt.Errorf("%s: entry %q: fifo not allowed", name, hdr.Name)
		case tar.TypeCont:
			return fmt.Errorf("%s: entry %q: reserved type not allowed", name, hdr.Name)
		case tar.TypeGNUSparse:
			return fmt.Errorf("%s: entry %q: sparse file not allowed", name, hdr.Name)
		case tar.TypeXHeader, tar.TypeXGlobalHeader, tar.TypeGNULongName, tar.TypeGNULongLink:
			// PAX/GNU metadata headers are consumed by the tar package itself
			// and should never appear here, but ignore them defensively
			// rather than failing. They do not materialize fake FS nodes.
			continue
		default:
			return fmt.Errorf("%s: entry %q: unsupported tar type %q", name, hdr.Name, string(hdr.Typeflag))
		}
	}

	return nil
}

// drainTarBody drains exactly size bytes of a regular-file body from tr into
// io.Discard, enforcing the per-file cap (MaxRootFSFileBodyBytes) and the
// cumulative cap (MaxRootFSTotalBodyBytes via *total). It never stores the
// body. size < 0 is rejected (a tar header Size field should never be
// negative). size == 0 skips the read entirely. If the underlying reader
// yields fewer than size bytes the tar stream is malformed and an error is
// returned so the caller fails closed.
func drainTarBody(name, clean string, tr *tar.Reader, size int64, total *int64) error {
	if size < 0 {
		return fmt.Errorf("%s: drain %q: negative size %d", name, clean, size)
	}
	if size == 0 {
		return nil
	}
	if size > MaxRootFSFileBodyBytes {
		return fmt.Errorf("%s: drain %q: body size %d exceeds MaxRootFSFileBodyBytes (%d)", name, clean, size, MaxRootFSFileBodyBytes)
	}
	if *total+size > MaxRootFSTotalBodyBytes {
		return fmt.Errorf("%s: drain %q: cumulative body bytes %d+%d would exceed MaxRootFSTotalBodyBytes (%d)", name, clean, *total, size, MaxRootFSTotalBodyBytes)
	}
	// io.CopyN with a positive N reads exactly N bytes from tr (which is a
	// *tar.Reader; its Read serves the current entry's body and advances the
	// tar stream). If the body is shorter than N, CopyN returns io.ErrUnexpectedEOF
	// which we surface as a malformed-archive error.
	n, err := io.CopyN(io.Discard, tr, size)
	if err != nil {
		return fmt.Errorf("%s: drain %q: short read (%d/%d bytes): %w", name, clean, n, size, err)
	}
	if n != size {
		// Defensive: CopyN reported no error but under-read. Treat as corrupt.
		return fmt.Errorf("%s: drain %q: short read (%d/%d bytes)", name, clean, n, size)
	}
	*total += n
	return nil
}

// loadRootFSFromDir walks the host directory at root and materializes its
// directory tree and regular-file *names* into fs as zero-byte placeholders.
//
// It uses os.Lstat (not Stat) so symlinks and other reparse points are
// detected rather than followed. Symlinks, device nodes, FIFOs, sockets and
// any non-regular/non-directory entry are rejected (fail closed). The host
// root itself is rejected if it is a symlink or special file.
//
// Traversal is a bounded streaming walk using os.Open(dir).ReadDir(batch)
// chunks rather than filepath.WalkDir. filepath.WalkDir reads an entire
// directory into memory via ReadDir(-1) before visiting its entries, so a
// single huge directory (millions of entries) could exhaust memory and delay
// the MaxRootFSEntries cap check. The streaming walk reads at most
// rootFSDirReadBatchSize entries at a time, runs the node counter / cap check
// after each batch, and fails closed as soon as the cap is exceeded. Host
// file contents are never read; regular files become zero-byte placeholders.
func loadRootFSFromDir(out afero.Fs, root string, expected os.FileInfo) error {
	count := newNodeCounter()

	// walkItem is a directory whose entries still need to be streamed. The
	// hostAbs path is opened and ReadDir'd in batches; the fakeClean path is
	// the POSIX-relative path used to materialize entries inside fs (and is
	// the key used for the node counter).
	type walkItem struct {
		hostAbs   string // absolute host path to open+ReadDir
		fakeClean string // POSIX-relative cleaned path ("" for root)
		expected  os.FileInfo
	}

	stack := []walkItem{{hostAbs: root, fakeClean: "", expected: expected}}
	for len(stack) > 0 {
		item := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		d, err := openRootFSChecked(item.hostAbs, item.expected)
		if err != nil {
			return err
		}
		if item.fakeClean != "" {
			// A queued directory is materialized only after its saved Lstat
			// identity has been checked against the opened handle.
			if err := out.MkdirAll(memPath(item.fakeClean), 0o755); err != nil {
				_ = d.Close()
				return fmt.Errorf("mkdir %q: %w", item.fakeClean, err)
			}
		}
		// Stream the directory in batches so a single huge directory cannot
		// exhaust memory. Each batch is bounded to rootFSDirReadBatchSize
		// entries; the node counter / cap check runs after every batch.
		for {
			entries, rerr := d.ReadDir(rootFSDirReadBatchSize)
			for _, e := range entries {
				hostFull := filepath.Join(item.hostAbs, e.Name())
				info, err := lstatRootFS(hostFull)
				if err != nil {
					d.Close()
					return fmt.Errorf("lstat %q: %w", hostFull, err)
				}
				if err := rejectSpecial(info, hostFull); err != nil {
					d.Close()
					return err
				}
				rel := filepath.ToSlash(filepath.Join(item.fakeClean, e.Name()))
				clean, err := cleanArchivePath(rel)
				if err != nil {
					d.Close()
					return fmt.Errorf("entry %q: %w", rel, err)
				}

				// Count (and cap-check) BEFORE materializing so we fail
				// closed without creating nodes beyond the cap.
				if err := count.add(clean); err != nil {
					d.Close()
					return err
				}

				mode := info.Mode()
				if mode.IsDir() {
					// Materialize only after the Lstat identity is rechecked on the
					// opened child directory below.
					// Push the subdirectory onto the stack so its entries are
					// streamed after the current directory is fully read. Keep the
					// Lstat result to bind that later open to this exact object.
					stack = append(stack, walkItem{hostAbs: hostFull, fakeClean: clean, expected: info})
					continue
				}
				if mode.IsRegular() {
					checked, err := openRootFSChecked(hostFull, info)
					if err != nil {
						d.Close()
						return err
					}
					if err := checked.Close(); err != nil {
						d.Close()
						return fmt.Errorf("close %q: %w", hostFull, err)
					}
					// Zero-byte placeholder; never read host file contents.
					f, err := out.Create(memPath(clean))
					if err != nil {
						d.Close()
						return fmt.Errorf("create %q: %w", clean, err)
					}
					if err := f.Close(); err != nil {
						d.Close()
						return fmt.Errorf("close %q: %w", clean, err)
					}
					continue
				}

				// rejectSpecial already covered this, but be defensive.
				d.Close()
				return fmt.Errorf("entry %q: unsupported file type", rel)
			}
			if rerr != nil {
				if !errors.Is(rerr, io.EOF) {
					d.Close()
					return fmt.Errorf("readdir %q: %w", item.hostAbs, rerr)
				}
				break
			}
			if len(entries) == 0 {
				// Some implementations return (nil, io.EOF) only on the final
				// call; others return (nil, nil) at EOF. Guard against an
				// infinite loop on the latter by breaking when a batch is
				// empty without error.
				break
			}
		}
		if err := d.Close(); err != nil {
			return fmt.Errorf("close %q: %w", item.hostAbs, err)
		}
	}
	return nil
}

// loadRootFSFromFile opens a supported archive file on disk and decodes it
// into fs. Zip files use the os.File as an io.ReaderAt so the archive bytes are
// not copied into memory; tar and gzip streams are consumed incrementally. File
// contents are never copied into the fake filesystem.
func loadRootFSFromFile(out afero.Fs, file string, expected os.FileInfo) error {
	f, err := openRootFSChecked(file, expected)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}

	var magic [4]byte
	n, _ := f.ReadAt(magic[:], 0)
	lower := strings.ToLower(file)
	isZipExt := strings.HasSuffix(lower, ".zip")
	isZipMagic := n >= 4 && magic[0] == 0x50 && magic[1] == 0x4b && (magic[2] == 0x03 || magic[2] == 0x05 || magic[2] == 0x07) && (magic[3] == 0x04 || magic[3] == 0x06 || magic[3] == 0x08)

	if isZipExt || isZipMagic {
		return loadRootFSFromZip(out, file, f, info.Size())
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return loadRootFSFromReader(out, file, f)
}

// openRootFSChecked opens path and proves that the opened object is the same
// one previously inspected with os.Lstat. It deliberately relies only on
// portable os.FileInfo/os.SameFile behavior, so it neither follows an
// Lstat-to-open replacement silently nor depends on Unix-only open flags.
func openRootFSChecked(path string, expected os.FileInfo) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", path, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("open %q: stat: %w", path, err)
	}
	if err := rejectSpecial(info, path); err != nil {
		_ = f.Close()
		return nil, err
	}
	if !os.SameFile(expected, info) {
		_ = f.Close()
		return nil, fmt.Errorf("open %q: changed after lstat", path)
	}
	return f, nil
}

// loadRootFSFromZip decodes a zip archive from r into fs. Symlinks, device
// nodes and other non-regular/non-directory entries are rejected. Regular
// files become zero-byte placeholders; their bodies are never copied.
//
// Before calling zip.NewReader (which parses the entire central directory and
// allocates one *zip.File per entry up front), preflightZipDirectory reads
// only the EOCD tail and rejects archives that use Zip64 sentinel values, have
// too many entries, or have a central directory larger than
// MaxRootFSZipCentralDirectoryBytes. This prevents a crafted central directory
// from exhausting memory before the per-entry cap in the body of this function
// can fire.
func loadRootFSFromZip(out afero.Fs, name string, r io.ReaderAt, size int64) error {
	if err := preflightZipDirectory(r, size); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}

	zr, err := zip.NewReader(r, size)
	if err != nil {
		return fmt.Errorf("%s: zip header: %w", name, err)
	}

	count := newNodeCounter()
	// len(zr.File) is the raw entry count from the central directory, which
	// includes duplicate entries and entries that clean to the root ".".
	// It is independent of nodeCounter, which de-dups by path: an attacker
	// can submit many duplicate entries for the same safe path (or many
	// root entries) to exhaust processing while keeping the materialized-
	// node count under the cap. Fail closed on overflow. preflightZipDirectory
	// already bounded this, but we keep the defensive check in case the
	// preflight and archive/zip ever disagree on the entry count.
	if len(zr.File) > MaxRootFSEntries {
		return fmt.Errorf("%s: exceeds MaxRootFSEntries (%d) raw zip entries", name, MaxRootFSEntries)
	}
	for _, zf := range zr.File {
		clean, err := cleanArchivePath(zf.Name)
		if err != nil {
			return fmt.Errorf("%s: entry %q: %w", name, zf.Name, err)
		}
		if clean == "" || clean == "." {
			continue
		}

		mode := os.FileMode(zf.Mode())
		switch {
		case mode.IsDir():
			// Count the directory and implicit parents before materializing.
			if err := count.add(clean); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			if err := out.MkdirAll(memPath(clean), 0o755); err != nil {
				return fmt.Errorf("%s: mkdir %q: %w", name, clean, err)
			}
		case mode.IsRegular():
			if err := count.add(clean); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			f, err := out.Create(memPath(clean))
			if err != nil {
				return fmt.Errorf("%s: create %q: %w", name, clean, err)
			}
			if err := f.Close(); err != nil {
				return fmt.Errorf("%s: close %q: %w", name, clean, err)
			}
		case mode&os.ModeSymlink != 0:
			return fmt.Errorf("%s: entry %q: symlink not allowed", name, zf.Name)
		case mode&os.ModeDevice != 0:
			return fmt.Errorf("%s: entry %q: device node not allowed", name, zf.Name)
		case mode&os.ModeNamedPipe != 0:
			return fmt.Errorf("%s: entry %q: fifo not allowed", name, zf.Name)
		case mode&os.ModeSocket != 0:
			return fmt.Errorf("%s: entry %q: socket not allowed", name, zf.Name)
		case mode&os.ModeIrregular != 0:
			return fmt.Errorf("%s: entry %q: irregular file not allowed", name, zf.Name)
		default:
			return fmt.Errorf("%s: entry %q: unsupported zip mode %v", name, zf.Name, mode)
		}
	}
	return nil
}

// rejectSpecial returns an error if info describes a symlink, device node,
// named pipe, socket, or any other non-regular, non-directory file. It is
// applied to every entry produced by os.Lstat so reparse points (including
// Windows symlinks/junctions) are detected and rejected rather than followed.
func rejectSpecial(info os.FileInfo, label string) error {
	mode := info.Mode()
	if mode&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: symlink not allowed", label)
	}
	if mode&os.ModeDevice != 0 {
		return fmt.Errorf("%s: device node not allowed", label)
	}
	if mode&os.ModeNamedPipe != 0 {
		return fmt.Errorf("%s: named pipe not allowed", label)
	}
	if mode&os.ModeSocket != 0 {
		return fmt.Errorf("%s: socket not allowed", label)
	}
	if mode&os.ModeIrregular != 0 {
		return fmt.Errorf("%s: irregular file not allowed", label)
	}
	return nil
}

// cleanArchivePath validates and cleans an archive/rootfs entry path.
//
// It rejects:
//   - empty paths
//   - absolute POSIX paths (leading '/')
//   - Windows drive letters (e.g. "C:", "c:/")
//   - any raw ".." segment, including inside a path like "safe/../escape"
//   - backslashes (enforce POSIX-only separators inside archives)
//   - any byte < 0x20 or 0x7f (control characters, including NUL)
//   - a colon anywhere in the path (prevents "C:" and stream-namespace abuse)
//
// It permits "." segments and repeated '/' and collapses them via path.Clean.
// The returned path is POSIX-style, relative, has no leading slash, and is
// bounded in length by MaxRootFSPathLen.
func cleanArchivePath(name string) (string, error) {
	if name == "" {
		return "", errors.New("empty path")
	}
	if len(name) > MaxRootFSPathLen {
		return "", fmt.Errorf("path length %d exceeds MaxRootFSPathLen (%d)", len(name), MaxRootFSPathLen)
	}

	// Reject control characters and NUL across the whole path.
	for i := 0; i < len(name); i++ {
		b := name[i]
		if b < 0x20 || b == 0x7f {
			return "", fmt.Errorf("control character at index %d", i)
		}
	}

	// Reject backslashes: archives use POSIX separators. A backslash is a
	// legal filename char on POSIX and can be used to smuggle Windows-style
	// traversal past naive cleaners.
	if strings.Contains(name, "\\") {
		return "", errors.New("backslash not allowed")
	}

	// Reject absolute POSIX paths.
	if strings.HasPrefix(name, "/") {
		return "", errors.New("absolute path not allowed")
	}

	// Reject Windows drive letters and any colon (drive separator or NTFS
	// alternate data stream separator). A leading single letter followed by
	// ':' is a drive; a colon anywhere else is also suspect, so reject all.
	if strings.Contains(name, ":") {
		return "", errors.New("colon not allowed")
	}

	// Reject any raw ".." segment. path.Clean would resolve "safe/../escape"
	// to "escape", but we want to fail closed on traversal attempts rather
	// than silently rewrite them.
	parts := strings.Split(name, "/")
	for _, seg := range parts {
		if seg == ".." {
			return "", errors.New("\"..\" segment not allowed")
		}
	}

	clean := path.Clean(name)
	// path.Clean(".") is "."; path.Clean("") is ".". An entry that cleans to
	// "." is the archive root and is allowed (callers may skip it).
	if clean == "." {
		return clean, nil
	}
	// Defensive: after cleaning, an absolute result or traversal would
	// indicate a logic bug; reject just in case.
	if strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, "../") || clean == ".." {
		return "", errors.New("cleaned path escapes root")
	}
	return clean, nil
}

// memPath converts a POSIX-relative cleaned path (as returned by
// cleanArchivePath) into an absolute, root-anchored path suitable for use as
// a key in afero.NewMemMapFs(). On Windows, afero normalizes paths with
// filepath.Clean, which turns "/" into "\"; storing entries under an absolute
// "/" prefix keeps them addressable by absolute POSIX paths like "/etc/passwd"
// regardless of host OS.
func memPath(clean string) string {
	if clean == "" || clean == "." {
		return "/"
	}
	if strings.HasPrefix(clean, "/") {
		return clean
	}
	return "/" + clean
}

// Zip EOCD (End Of Central Directory) and Zip64 EOCD locator constants.
//
// A ZIP archive ends with:
//
//	[optional file data ...]
//	[central directory entries ...]   <- bounded by preflight
//	[optional Zip64 EOCD record]      <- rejected if present
//	[optional Zip64 EOCD locator]     <- rejected if present
//	EOCD record (22 bytes minimum)    <- parsed here
//
// The EOCD record signature is 0x06054b50. Its minimum size is 22 bytes; when
// a zip comment is present the EOCD sits at file_size - 22 - len(comment).
// To locate the EOCD we read the last min(size, maxComment+eocdSize) bytes
// and scan backwards for the signature.
const (
	zipEOCDSignature   uint32 = 0x06054b50
	zipEOCDMinSize            = 22
	zipMaxCommentSize         = 65535
	zipEOCDEndScanSize        = zipMaxCommentSize + zipEOCDMinSize // 65557

	// zip64EOCDLocatorSignature is the signature of the Zip64 EOCD locator
	// record that appears immediately before the EOCD when a Zip64 archive
	// is used. We reject Zip64 archives (fail closed) because the loader
	// does not need to support >4GB / >65535-entry archives and Zip64
	// parsing adds complexity and attack surface.
	zip64EOCDLocatorSignature uint32 = 0x07064b50
	zip64EOCDLocatorSize             = 20

	// zipCentralDirectoryHeaderSignature is the signature of each central
	// directory file header. We scan central-directory headers before calling
	// archive/zip.NewReader so a forged EOCD cannot under-report the actual
	// number of headers and force archive/zip to parse/allocate unbounded
	// entries before our len(zr.File) cap runs.
	zipCentralDirectoryHeaderSignature uint32 = 0x02014b50
	zipCentralDirectoryHeaderSize             = 46
)

// preflightZipDirectory reads only the EOCD tail of a zip archive from r (of
// total size bytes) and rejects archives that would force zip.NewReader to
// parse an unbounded central directory before the per-entry cap in
// loadRootFSFromZip can fire. Specifically it rejects:
//
//   - Archives smaller than the minimum EOCD size (too small to be a zip).
//   - Archives whose EOCD cannot be located (no signature in the tail scan).
//   - Archives using Zip64 extensions (Zip64 EOCD locator present, or the
//     EOCD entry-count / central-directory-size / central-directory-offset
//     fields carry the 0xffff / 0xffffffff sentinel values). Fail closed.
//   - Archives whose total entry count exceeds MaxRootFSEntries.
//   - Archives whose central directory size exceeds
//     MaxRootFSZipCentralDirectoryBytes.
//   - Archives whose central directory offset/size is inconsistent with the
//     file size (offset < 0, size < 0, or offset+size > fileSize).
//
// On success the central directory has been scanned with bounded reads and the
// archive is still handed to zip.NewReader, which performs its own structural
// validation. The scan is intentionally shallow: it validates central-directory
// header framing and counts entries/bytes, but leaves file-name/path semantics
// and local-header details to zip.NewReader and the rootfs loader.
func preflightZipDirectory(r io.ReaderAt, size int64) error {
	if size < int64(zipEOCDMinSize) {
		return errors.New("zip too small to contain EOCD")
	}

	// Read the last min(size, zipEOCDEndScanSize) bytes.
	tailLen := size
	if tailLen > int64(zipEOCDEndScanSize) {
		tailLen = int64(zipEOCDEndScanSize)
	}
	tail := make([]byte, tailLen)
	off := size - tailLen
	if _, err := r.ReadAt(tail, off); err != nil {
		return fmt.Errorf("zip read tail: %w", err)
	}

	// Scan backwards for the EOCD signature. The signature is little-endian
	// 0x06054b50 (bytes: 50 4b 05 06).
	//
	// For each candidate signature we validate the comment length the same
	// way stdlib's archive/zip.findSignatureInBlock does: the EOCD record is
	// 22 bytes (zipEOCDMinSize) and is followed by a comment of length
	// `commentLen` stored at EOCD offset 20. A candidate is the real EOCD
	// only if candidateIndex + 22 + commentLen lands exactly at the end of
	// the tail (which extends to EOF). If it does not, the candidate is a
	// forged signature embedded inside the real EOCD's comment (or inside the
	// central directory) and must not be honored; preflight must keep
	// scanning earlier candidates. Without this check a forged PK\x05\x06
	// placed inside the real EOCD's comment could satisfy preflight while
	// archive/zip (which also validates comment length) later selects the
	// real earlier EOCD - letting an attacker smuggle an oversized/invalid
	// central directory past preflight.
	eocdIdx := -1
	for i := len(tail) - zipEOCDMinSize; i >= 0; i-- {
		if tail[i] != 0x50 || tail[i+1] != 0x4b || tail[i+2] != 0x05 || tail[i+3] != 0x06 {
			continue
		}
		// The loop bound guarantees i+zipEOCDMinSize <= len(tail), so we can
		// safely read commentLen at offset 20..22.
		commentLen := int(binary.LittleEndian.Uint16(tail[i+20 : i+22]))
		if i+zipEOCDMinSize+commentLen != len(tail) {
			// Comment does not land at EOF; this is not the real EOCD.
			// Keep scanning earlier candidates.
			continue
		}
		eocdIdx = i
		break
	}
	if eocdIdx < 0 {
		return errors.New("zip EOCD signature not found")
	}
	eocd := tail[eocdIdx:]
	if len(eocd) < zipEOCDMinSize {
		return errors.New("zip EOCD truncated")
	}

	// Reject Zip64. A Zip64 archive has a Zip64 EOCD locator record
	// immediately before the EOCD; if the bytes just before the EOCD carry
	// the Zip64-EOCD-locator signature, fail closed. We also fail closed on
	// the sentinel values in the EOCD itself (entry count == 0xffff,
	// central-directory size == 0xffffffff, central-directory offset ==
	// 0xffffffff) which indicate the real values live in a Zip64 EOCD record
	// we do not parse.
	if eocdIdx >= zip64EOCDLocatorSize {
		loc := tail[eocdIdx-zip64EOCDLocatorSize : eocdIdx]
		if binary.LittleEndian.Uint32(loc[0:4]) == zip64EOCDLocatorSignature {
			return errors.New("zip64 not allowed (Zip64 EOCD locator present)")
		}
	}

	// EOCD layout (little-endian):
	//   0  4  signature            0x06054b50
	//   4  2  disk number
	//   6  2  disk with CD start
	//   8  2  entries on this disk
	//  10  2  total entries        <- we check this
	//  12  4  central dir size     <- we check this
	//  16  4  central dir offset   <- we check this
	//  20  2  comment length
	totalEntries := binary.LittleEndian.Uint16(eocd[10:12])
	cdSize := uint64(binary.LittleEndian.Uint32(eocd[12:16]))
	cdOffset := uint64(binary.LittleEndian.Uint32(eocd[16:20]))

	// Sentinel checks. The ZIP spec uses 0xffff / 0xffffffff to signal
	// "real value is in the Zip64 EOCD record". Reject any sentinel rather
	// than parsing Zip64.
	if totalEntries == 0xffff {
		return errors.New("zip64 not allowed (total entries sentinel)")
	}
	if cdSize == 0xffffffff {
		return errors.New("zip64 not allowed (central directory size sentinel)")
	}
	if cdOffset == 0xffffffff {
		return errors.New("zip64 not allowed (central directory offset sentinel)")
	}

	// Multi-disk archives are not supported by archive/zip and are suspicious.
	diskNum := binary.LittleEndian.Uint16(eocd[4:6])
	cdDisk := binary.LittleEndian.Uint16(eocd[6:8])
	if diskNum != 0 || cdDisk != 0 {
		return errors.New("zip disk spanning not allowed")
	}

	if int64(totalEntries) > int64(MaxRootFSEntries) {
		return fmt.Errorf("exceeds MaxRootFSEntries (%d) raw zip entries (EOCD total=%d)", MaxRootFSEntries, totalEntries)
	}
	if cdSize > uint64(MaxRootFSZipCentralDirectoryBytes) {
		return fmt.Errorf("central directory size %d exceeds MaxRootFSZipCentralDirectoryBytes (%d)", cdSize, MaxRootFSZipCentralDirectoryBytes)
	}

	// Structural sanity: the central directory must fit inside the file and
	// must end exactly at the actual EOCD position. cdOffset is the byte
	// offset of the first central-directory entry from the start of the archive.
	// archive/zip reads directory headers from cdOffset until a bad header, not
	// merely for the EOCD-declared cdSize bytes, so accepting cdOffset+cdSize <
	// EOCD would let an archive under-report cdSize / entry count and force
	// zip.NewReader to parse extra headers before our post-NewReader cap runs.
	if cdOffset+cdSize > uint64(size) {
		return fmt.Errorf("zip central directory (%d+%d) exceeds file size %d", cdOffset, cdSize, size)
	}
	eocdAbs := uint64(off) + uint64(eocdIdx)
	if cdOffset+cdSize > eocdAbs {
		return fmt.Errorf("zip central directory (%d+%d) overlaps EOCD at %d", cdOffset, cdSize, eocdAbs)
	}
	if cdOffset+cdSize != eocdAbs {
		return fmt.Errorf("zip central directory (%d+%d) does not end at EOCD %d", cdOffset, cdSize, eocdAbs)
	}

	actualEntries, err := scanZipCentralDirectory(r, cdOffset, cdSize)
	if err != nil {
		return err
	}
	if actualEntries != int(totalEntries) {
		return fmt.Errorf("zip central directory entry count %d does not match EOCD total %d", actualEntries, totalEntries)
	}
	return nil
}

// scanZipCentralDirectory walks the actual central-directory header stream with
// bounded fixed-size reads. It does this before zip.NewReader runs so a crafted
// EOCD cannot under-report entry count or size and make archive/zip parse many
// more entries before our post-NewReader checks run.
func scanZipCentralDirectory(r io.ReaderAt, cdOffset uint64, cdSize uint64) (int, error) {
	if cdSize == 0 {
		return 0, nil
	}
	if cdSize > uint64(MaxRootFSZipCentralDirectoryBytes) {
		return 0, fmt.Errorf("central directory size %d exceeds MaxRootFSZipCentralDirectoryBytes (%d)", cdSize, MaxRootFSZipCentralDirectoryBytes)
	}

	consumed := uint64(0)
	entries := 0
	var hdr [zipCentralDirectoryHeaderSize]byte
	for consumed < cdSize {
		remaining := cdSize - consumed
		if remaining < zipCentralDirectoryHeaderSize {
			return 0, fmt.Errorf("zip central directory truncated: %d trailing bytes", remaining)
		}
		off := cdOffset + consumed
		if off > uint64(^uint64(0)>>1) {
			return 0, fmt.Errorf("zip central directory offset %d overflows int64", off)
		}
		if _, err := r.ReadAt(hdr[:], int64(off)); err != nil {
			return 0, fmt.Errorf("zip read central directory header at %d: %w", off, err)
		}
		if binary.LittleEndian.Uint32(hdr[0:4]) != zipCentralDirectoryHeaderSignature {
			return 0, fmt.Errorf("zip central directory header at %d has invalid signature", off)
		}

		nameLen := uint64(binary.LittleEndian.Uint16(hdr[28:30]))
		extraLen := uint64(binary.LittleEndian.Uint16(hdr[30:32]))
		commentLen := uint64(binary.LittleEndian.Uint16(hdr[32:34]))
		entryLen := uint64(zipCentralDirectoryHeaderSize) + nameLen + extraLen + commentLen
		if entryLen > remaining {
			return 0, fmt.Errorf("zip central directory entry at %d length %d exceeds remaining %d", off, entryLen, remaining)
		}

		entries++
		if entries > MaxRootFSEntries {
			return 0, fmt.Errorf("exceeds MaxRootFSEntries (%d) actual zip central-directory entries", MaxRootFSEntries)
		}
		consumed += entryLen
		if consumed > uint64(MaxRootFSZipCentralDirectoryBytes) {
			return 0, fmt.Errorf("central directory bytes %d exceed MaxRootFSZipCentralDirectoryBytes (%d)", consumed, MaxRootFSZipCentralDirectoryBytes)
		}
	}
	if consumed != cdSize {
		return 0, fmt.Errorf("zip central directory consumed %d bytes, want %d", consumed, cdSize)
	}
	return entries, nil
}

// peekReader wraps an io.Reader and allows peeking at the first N bytes
// without consuming them. It is used to sniff gzip vs. zip vs. plain tar so
// the caller does not need to rely on filename extensions.
type peekReader struct {
	src    io.Reader
	peeked []byte
	buf    [16]byte
}

func newPeekReader(r io.Reader) *peekReader {
	return &peekReader{src: r}
}

// peekN returns up to n bytes from the start of the stream without consuming
// them. If fewer than n bytes are available, it returns what it could read.
// An io.EOF is not returned in that case; only real read errors propagate.
func (p *peekReader) peekN(n int) ([]byte, error) {
	if n > len(p.buf) {
		n = len(p.buf)
	}
	if len(p.peeked) >= n {
		return p.peeked[:n], nil
	}
	need := n - len(p.peeked)
	off := len(p.peeked)
	read, err := io.ReadFull(p.src, p.buf[off:off+need])
	p.peeked = append(p.peeked, p.buf[off:off+read]...)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return p.peeked, err
	}
	return p.peeked, nil
}

// Read drains the peeked bytes first, then reads from src.
func (p *peekReader) Read(dst []byte) (int, error) {
	if len(p.peeked) > 0 {
		n := copy(dst, p.peeked)
		p.peeked = p.peeked[n:]
		return n, nil
	}
	return p.src.Read(dst)
}
