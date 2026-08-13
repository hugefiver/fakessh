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
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	fsconf "github.com/hugefiver/fakessh/modules/fakeshell/conf"
	"github.com/spf13/afero"
)

// ---------------------------------------------------------------------------
// cleanArchivePath
// ---------------------------------------------------------------------------

func TestCleanArchivePath_AcceptsValid(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want string
	}{
		{"etc/passwd", "etc/passwd"},
		{"home/root/.profile", "home/root/.profile"},
		{"etc//passwd", "etc/passwd"},  // repeated slash -> cleaned
		{"./etc/passwd", "etc/passwd"}, // leading dot segment -> cleaned
		{"etc/./passwd", "etc/passwd"}, // inner dot segment -> cleaned
		{"etc/passwd/", "etc/passwd"},  // trailing slash -> cleaned
		{".", "."},                     // root dot is allowed
	}

	for _, tc := range cases {
		got, err := cleanArchivePath(tc.in)
		if err != nil {
			t.Errorf("cleanArchivePath(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("cleanArchivePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCleanArchivePath_RejectsUnsafe(t *testing.T) {
	t.Parallel()

	cases := []string{
		"../escape",
		"/abs",
		"C:/x",
		"c:/x",
		"C:\\x",
		"team\\x",        // backslash anywhere
		"safe/../escape", // traversal buried in path
		"..",             // bare dotdot
		"foo/..",         // trailing dotdot
		"../foo",         // leading dotdot
		"foo/:bar",       // colon
		"etc/passwd\x00", // NUL
		"etc/\x01passwd", // control char
		"etc/\x7fpasswd", // DEL
		"",               // empty
	}
	for _, in := range cases {
		if _, err := cleanArchivePath(in); err == nil {
			t.Errorf("cleanArchivePath(%q) expected error, got nil", in)
		}
	}
}

func TestCleanArchivePath_RejectsOverlong(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("a", MaxRootFSPathLen+1)
	if _, err := cleanArchivePath(long); err == nil {
		t.Errorf("cleanArchivePath(len=%d) expected error", len(long))
	}
}

// ---------------------------------------------------------------------------
// LoadRootFS - embedded
// ---------------------------------------------------------------------------

func TestLoadRootFS_EmbeddedContainsExpectedDirs(t *testing.T) {
	t.Parallel()

	cfg := &fsconf.FakeshellConfig{} // RootFS == "" -> embedded
	f, err := LoadRootFS(cfg)
	if err != nil {
		t.Fatalf("LoadRootFS(empty) error = %v", err)
	}

	for _, dir := range []string{"/bin", "/home", "/usr", "/var"} {
		ok, err := afero.Exists(f, dir)
		if err != nil {
			t.Fatalf("Exists(%s) error = %v", dir, err)
		}
		if !ok {
			t.Errorf("embedded rootfs missing expected directory %s", dir)
		}
		isDir, err := afero.IsDir(f, dir)
		if err != nil {
			t.Fatalf("IsDir(%s) error = %v", dir, err)
		}
		if !isDir {
			t.Errorf("embedded rootfs %s is not a directory", dir)
		}
	}
}

func TestLoadRootFS_EmbeddedFilesAreZeroByte(t *testing.T) {
	t.Parallel()

	cfg := &fsconf.FakeshellConfig{}
	f, err := LoadRootFS(cfg)
	if err != nil {
		t.Fatalf("LoadRootFS(empty) error = %v", err)
	}

	// Walk the whole fs and assert every regular file is zero bytes.
	count := 0
	walkErr := afero.Walk(f, "/", func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		count++
		if info.Size() != 0 {
			return errors.New("regular file " + p + " is not zero bytes")
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk embedded rootfs: %v", walkErr)
	}
	if count == 0 {
		// The embedded rootfs currently has only directories, so count==0 is
		// fine. We just want the walk to succeed.
	}
}

// ---------------------------------------------------------------------------
// LoadRootFS - directory fixture
// ---------------------------------------------------------------------------

// writeDirFixture creates a directory tree on the host with etc/passwd and
// home/root/.profile plus some subdirectories, returning its path.
func writeDirFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	paths := []string{
		"etc",
		"home/root",
		"var/log",
	}
	for _, p := range paths {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(full, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", p, err)
		}
	}
	files := []string{
		"etc/passwd",
		"home/root/.profile",
		"var/log/messages",
	}
	for _, p := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		// Write some bytes; the loader must ignore them and produce a
		// zero-byte placeholder.
		if err := os.WriteFile(full, []byte("this content must NOT be copied\n"), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	return dir
}

func TestLoadRootFS_DirectoryLoadsPathsAndZeroByteFiles(t *testing.T) {
	t.Parallel()

	dir := writeDirFixture(t)
	cfg := &fsconf.FakeshellConfig{RootFS: dir}
	f, err := LoadRootFS(cfg)
	if err != nil {
		t.Fatalf("LoadRootFS(dir) error = %v", err)
	}

	// Directories exist
	for _, p := range []string{"/etc", "/home", "/home/root", "/var", "/var/log"} {
		ok, err := afero.IsDir(f, p)
		if err != nil {
			t.Fatalf("IsDir(%s) error = %v", p, err)
		}
		if !ok {
			t.Errorf("expected directory %s", p)
		}
	}

	// Regular files exist and are zero bytes
	for _, p := range []string{"/etc/passwd", "/home/root/.profile", "/var/log/messages"} {
		info, err := f.Stat(p)
		if err != nil {
			t.Fatalf("Stat(%s) error = %v", p, err)
		}
		if info.IsDir() {
			t.Errorf("%s is a directory, want regular file", p)
		}
		if info.Size() != 0 {
			t.Errorf("%s size = %d, want 0 (placeholder must not copy content)", p, info.Size())
		}
	}
}

func TestLoadRootFS_DirectoryRejectsSymlink(t *testing.T) {
	t.Parallel()

	// Symlinks are hard to create on Windows without admin. Skip on Windows
	// if we cannot create one.
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("cannot create symlink on windows: %v", err)
		}
		t.Fatalf("symlink: %v", err)
	}

	// Root itself is a symlink -> must be rejected.
	cfg := &fsconf.FakeshellConfig{RootFS: link}
	if _, err := LoadRootFS(cfg); err == nil {
		t.Errorf("LoadRootFS(symlink root) expected error, got nil")
	}

	// Symlink inside a directory tree -> must be rejected.
	inner := t.TempDir()
	if err := os.Symlink(target, filepath.Join(inner, "evil")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("cannot create symlink on windows: %v", err)
		}
		t.Fatalf("inner symlink: %v", err)
	}
	cfg2 := &fsconf.FakeshellConfig{RootFS: inner}
	if _, err := LoadRootFS(cfg2); err == nil {
		t.Errorf("LoadRootFS(dir with symlink) expected error, got nil")
	}
}

func TestLoadRootFS_ArchiveSymlinkRootRejected(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "root.tar")
	entries := []tarEntry{{"etc/passwd", tar.TypeReg, []byte("x"), ""}}
	if err := os.WriteFile(target, buildTarBytes(t, entries), 0o644); err != nil {
		t.Fatalf("write target tar: %v", err)
	}
	link := filepath.Join(dir, "link.tar")
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("cannot create symlink on windows: %v", err)
		}
		t.Fatalf("symlink archive: %v", err)
	}

	if _, err := LoadRootFS(&fsconf.FakeshellConfig{RootFS: link}); err == nil {
		t.Fatal("LoadRootFS(symlink archive root) expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// LoadRootFS - archive fixtures
// ---------------------------------------------------------------------------

// buildTarBytes builds a tar archive in memory containing the given entries.
// Regular files get a non-empty body to prove the loader does NOT copy it.
func buildTarBytes(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Mode:     0o644,
			Typeflag: e.typ,
			Size:     int64(len(e.body)),
		}
		if e.typ == tar.TypeDir {
			hdr.Mode = 0o755
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader(%s): %v", e.name, err)
		}
		if e.typ == tar.TypeReg || e.typ == tar.TypeRegA {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatalf("Write(%s): %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	return buf.Bytes()
}

// buildRawTarHeader writes exactly hdr, returning the bytes even when a
// deliberately oversized regular body is absent. That lets cap tests prove the
// loader rejects the header before attempting to consume its advertised body.
func buildRawTarHeader(t *testing.T, hdr *tar.Header) []byte {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("WriteHeader(%q): %v", hdr.Name, err)
	}
	err := tw.Close()
	if (hdr.Typeflag == tar.TypeReg || hdr.Typeflag == tar.TypeRegA) && hdr.Size > 0 {
		if err == nil {
			t.Fatalf("tar close for incomplete regular body unexpectedly succeeded")
		}
	} else if err != nil {
		t.Fatalf("tar close: %v", err)
	}
	return buf.Bytes()
}

type tarEntry struct {
	name string
	typ  byte
	body []byte
	link string
}

func TestLoadRootFS_TarLoadsZeroBytePlaceholders(t *testing.T) {
	t.Parallel()

	entries := []tarEntry{
		{"etc", tar.TypeDir, nil, ""},
		{"etc/passwd", tar.TypeReg, []byte("root:x:0:0\n"), ""},
		{"home", tar.TypeDir, nil, ""},
		{"home/root", tar.TypeDir, nil, ""},
		{"home/root/.profile", tar.TypeReg, []byte("export PATH=/bin\n"), ""},
	}
	tarBytes := buildTarBytes(t, entries)

	dir := t.TempDir()
	tarPath := filepath.Join(dir, "root.tar")
	if err := os.WriteFile(tarPath, tarBytes, 0o644); err != nil {
		t.Fatalf("write tar: %v", err)
	}

	cfg := &fsconf.FakeshellConfig{RootFS: tarPath}
	f, err := LoadRootFS(cfg)
	if err != nil {
		t.Fatalf("LoadRootFS(tar) error = %v", err)
	}

	assertLoadedPaths(t, f)
}

func TestLoadRootFS_TarGzLoadsZeroBytePlaceholders(t *testing.T) {
	t.Parallel()

	entries := []tarEntry{
		{"etc", tar.TypeDir, nil, ""},
		{"etc/passwd", tar.TypeReg, []byte("root:x:0:0\n"), ""},
		{"home", tar.TypeDir, nil, ""},
		{"home/root", tar.TypeDir, nil, ""},
		{"home/root/.profile", tar.TypeReg, []byte("export PATH=/bin\n"), ""},
	}
	tarBytes := buildTarBytes(t, entries)

	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	if _, err := gw.Write(tarBytes); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	dir := t.TempDir()
	for _, name := range []string{"root.tar.gz", "root.tgz"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, gzBuf.Bytes(), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		cfg := &fsconf.FakeshellConfig{RootFS: p}
		f, err := LoadRootFS(cfg)
		if err != nil {
			t.Fatalf("LoadRootFS(%s) error = %v", name, err)
		}
		assertLoadedPaths(t, f)
	}
}

// TestLoadRootFS_TarGzFromReader verifies loadRootFSFromReader directly,
// including the embedded-code path (gzip-sniffed tar from an io.Reader).
func TestLoadRootFS_TarGzFromReader(t *testing.T) {
	t.Parallel()

	entries := []tarEntry{
		{"etc", tar.TypeDir, nil, ""},
		{"etc/passwd", tar.TypeReg, []byte("root:x:0:0\n"), ""},
		{"home/root/.profile", tar.TypeReg, []byte("x\n"), ""},
	}
	tarBytes := buildTarBytes(t, entries)
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	gw.Write(tarBytes)
	gw.Close()

	out := afero.NewMemMapFs()
	if err := loadRootFSFromReader(out, "test.tgz", bytes.NewReader(gzBuf.Bytes())); err != nil {
		t.Fatalf("loadRootFSFromReader: %v", err)
	}
	assertLoadedPaths(t, out)
}

func TestLoadRootFS_PlainTarFromReader(t *testing.T) {
	t.Parallel()

	entries := []tarEntry{
		{"etc", tar.TypeDir, nil, ""},
		{"etc/passwd", tar.TypeReg, []byte("root:x:0:0\n"), ""},
		{"home/root/.profile", tar.TypeReg, []byte("x\n"), ""},
	}
	tarBytes := buildTarBytes(t, entries)

	out := afero.NewMemMapFs()
	if err := loadRootFSFromReader(out, "test.tar", bytes.NewReader(tarBytes)); err != nil {
		t.Fatalf("loadRootFSFromReader: %v", err)
	}
	assertLoadedPaths(t, out)
}

// buildZipBytes builds a zip archive in memory.
func buildZipBytes(t *testing.T, entries []zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		fh := &zip.FileHeader{
			Name:   e.name,
			Method: zip.Store,
		}
		fh.SetMode(e.mode)
		fw, err := zw.CreateHeader(fh)
		if err != nil {
			t.Fatalf("zip Create(%s): %v", e.name, err)
		}
		if e.body != nil {
			if _, err := fw.Write(e.body); err != nil {
				t.Fatalf("zip Write(%s): %v", e.name, err)
			}
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

type zipEntry struct {
	name string
	body []byte
	mode os.FileMode
}

func TestLoadRootFS_ZipLoadsZeroBytePlaceholders(t *testing.T) {
	t.Parallel()

	entries := []zipEntry{
		{"etc/", nil, 0o755 | os.ModeDir},
		{"etc/passwd", []byte("root:x:0:0\n"), 0o644},
		{"home/", nil, 0o755 | os.ModeDir},
		{"home/root/", nil, 0o755 | os.ModeDir},
		{"home/root/.profile", []byte("export PATH=/bin\n"), 0o644},
	}
	zipBytes := buildZipBytes(t, entries)

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "root.zip")
	if err := os.WriteFile(zipPath, zipBytes, 0o644); err != nil {
		t.Fatalf("write zip: %v", err)
	}

	cfg := &fsconf.FakeshellConfig{RootFS: zipPath}
	f, err := LoadRootFS(cfg)
	if err != nil {
		t.Fatalf("LoadRootFS(zip) error = %v", err)
	}
	assertLoadedPaths(t, f)
}

func TestLoadRootFS_EmptyZipSucceeds(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "empty.zip")
	if err := os.WriteFile(zipPath, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write zip: %v", err)
	}

	if _, err := LoadRootFS(&fsconf.FakeshellConfig{RootFS: zipPath}); err != nil {
		t.Fatalf("LoadRootFS(empty zip) error = %v", err)
	}
}

// assertLoadedPaths checks that the standard fixture paths exist and regular
// files are zero bytes.
func assertLoadedPaths(t *testing.T, f afero.Fs) {
	t.Helper()

	for _, p := range []string{"/etc", "/home", "/home/root"} {
		ok, err := afero.IsDir(f, p)
		if err != nil {
			t.Fatalf("IsDir(%s) error = %v", p, err)
		}
		if !ok {
			t.Errorf("expected directory %s", p)
		}
	}
	for _, p := range []string{"/etc/passwd", "/home/root/.profile"} {
		info, err := f.Stat(p)
		if err != nil {
			t.Errorf("Stat(%s) error = %v", p, err)
			continue
		}
		if info.IsDir() {
			t.Errorf("%s is a directory, want regular file", p)
			continue
		}
		if info.Size() != 0 {
			t.Errorf("%s size = %d, want 0 (content must not be copied)", p, info.Size())
		}
	}
}

// ---------------------------------------------------------------------------
// Fail-closed tests
// ---------------------------------------------------------------------------

func TestLoadRootFS_TarRejectsSymlink(t *testing.T) {
	t.Parallel()

	entries := []tarEntry{
		{"etc", tar.TypeDir, nil, ""},
		{"etc/passwd", tar.TypeReg, []byte("x"), ""},
		{"evil", tar.TypeSymlink, nil, "/etc/passwd"},
	}
	tarBytes := buildTarBytes(t, entries)
	out := afero.NewMemMapFs()
	err := loadRootFSFromReader(out, "evil.tar", bytes.NewReader(tarBytes))
	if err == nil {
		t.Fatal("expected error for tar with symlink, got nil")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("error should mention symlink, got: %v", err)
	}
}

func TestLoadRootFS_TarRejectsHardlink(t *testing.T) {
	t.Parallel()

	entries := []tarEntry{
		{"etc/passwd", tar.TypeReg, []byte("x"), ""},
		{"etc/link", tar.TypeLink, nil, "etc/passwd"},
	}
	tarBytes := buildTarBytes(t, entries)
	out := afero.NewMemMapFs()
	if err := loadRootFSFromReader(out, "evil.tar", bytes.NewReader(tarBytes)); err == nil {
		t.Fatal("expected error for tar with hardlink, got nil")
	}
}

// TestLoadRootFS_TarRootEntryRejectsSpecialType proves a root-cleaning entry
// receives the same type validation as a materialized entry.
func TestLoadRootFS_TarRootEntryRejectsSpecialType(t *testing.T) {
	t.Parallel()

	for _, typ := range []byte{tar.TypeSymlink, tar.TypeLink} {
		t.Run(string([]byte{typ}), func(t *testing.T) {
			tarBytes := buildRawTarHeader(t, &tar.Header{Name: ".", Typeflag: typ})
			err := loadRootFSFromReader(afero.NewMemMapFs(), "root-special.tar", bytes.NewReader(tarBytes))
			if err == nil {
				t.Fatal("expected root special entry rejection, got nil")
			}
			if !strings.Contains(err.Error(), "symlink/hardlink") {
				t.Fatalf("error = %v, want symlink/hardlink rejection", err)
			}
		})
	}
}

// TestLoadRootFS_TarRootRegularEntryEnforcesBodyCap proves a root-cleaning
// regular entry receives size validation before it is skipped.
func TestLoadRootFS_TarRootRegularEntryEnforcesBodyCap(t *testing.T) {
	t.Parallel()

	tarBytes := buildRawTarHeader(t, &tar.Header{
		Name:     ".",
		Typeflag: tar.TypeReg,
		Size:     MaxRootFSFileBodyBytes + 1,
	})
	err := loadRootFSFromReader(afero.NewMemMapFs(), "root-large.tar", bytes.NewReader(tarBytes))
	if err == nil {
		t.Fatal("expected root regular body cap rejection, got nil")
	}
	if !strings.Contains(err.Error(), "MaxRootFSFileBodyBytes") {
		t.Fatalf("error = %v, want MaxRootFSFileBodyBytes", err)
	}
}

// renameWithinTempDirOrSkip makes the Lstat-to-open replacement deterministic
// without symlinks or cross-volume behavior. All callers use siblings within
// one t.TempDir and skip only when that filesystem refuses a valid rename.
func renameWithinTempDirOrSkip(t *testing.T, oldPath, newPath string) {
	t.Helper()
	if err := os.Rename(oldPath, newPath); err != nil {
		t.Skipf("filesystem refuses same-volume rename %q -> %q: %v", oldPath, newPath, err)
	}
}

func TestLoadRootFS_ArchiveChangedAfterLstatRejected(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	archive := filepath.Join(dir, "root.tar")
	replacement := filepath.Join(dir, "replacement.zip")
	if err := os.WriteFile(archive, buildTarBytes(t, []tarEntry{{"original", tar.TypeReg, []byte("original"), ""}}), 0o644); err != nil {
		t.Fatalf("write original archive: %v", err)
	}
	if err := os.WriteFile(replacement, buildZipBytes(t, []zipEntry{{"replacement", []byte("replacement"), 0o644}}), 0o644); err != nil {
		t.Fatalf("write replacement archive: %v", err)
	}
	expected, err := lstatRootFS(archive)
	if err != nil {
		t.Fatalf("lstat original archive: %v", err)
	}
	renameWithinTempDirOrSkip(t, archive, filepath.Join(dir, "original.tar"))
	renameWithinTempDirOrSkip(t, replacement, archive)

	out := afero.NewMemMapFs()
	err = loadRootFSFromFile(out, archive, expected)
	if err == nil || !strings.Contains(err.Error(), "changed after lstat") {
		t.Fatalf("load stale archive error = %v, want changed after lstat", err)
	}
	if ok, existsErr := afero.Exists(out, "/replacement"); existsErr != nil || ok {
		t.Fatalf("replacement archive was decoded despite identity mismatch: exists=%v err=%v", ok, existsErr)
	}
}

func TestLoadRootFS_DirectoryChangedAfterLstatRejected(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "original"), []byte("original"), 0o644); err != nil {
		t.Fatalf("write original root fixture: %v", err)
	}
	replacement := filepath.Join(dir, "replacement-source")
	if err := os.Mkdir(replacement, 0o755); err != nil {
		t.Fatalf("mkdir replacement: %v", err)
	}
	if err := os.WriteFile(filepath.Join(replacement, "replacement"), []byte("replacement"), 0o644); err != nil {
		t.Fatalf("write replacement root fixture: %v", err)
	}
	expected, err := lstatRootFS(root)
	if err != nil {
		t.Fatalf("lstat original root: %v", err)
	}
	renameWithinTempDirOrSkip(t, root, filepath.Join(dir, "original-root"))
	renameWithinTempDirOrSkip(t, replacement, root)

	out := afero.NewMemMapFs()
	err = loadRootFSFromDir(out, root, expected)
	if err == nil || !strings.Contains(err.Error(), "changed after lstat") {
		t.Fatalf("load stale directory error = %v, want changed after lstat", err)
	}
	if ok, existsErr := afero.Exists(out, "/replacement"); existsErr != nil || ok {
		t.Fatalf("replacement directory was materialized despite identity mismatch: exists=%v err=%v", ok, existsErr)
	}
}

func TestOpenRootFSChecked_SubdirectoryChangedAfterLstatRejected(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	subdir := filepath.Join(root, "subdir")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}
	replacement := filepath.Join(root, "replacement-source")
	if err := os.Mkdir(replacement, 0o755); err != nil {
		t.Fatalf("mkdir replacement: %v", err)
	}
	expected, err := lstatRootFS(subdir)
	if err != nil {
		t.Fatalf("lstat original subdir: %v", err)
	}
	renameWithinTempDirOrSkip(t, subdir, filepath.Join(root, "original-subdir"))
	renameWithinTempDirOrSkip(t, replacement, subdir)

	f, err := openRootFSChecked(subdir, expected)
	if f != nil {
		_ = f.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "changed after lstat") {
		t.Fatalf("open stale subdirectory error = %v, want changed after lstat", err)
	}
}

// TestOpenRootFSChecked_FreezeCannotRebindStaleLstat captures the Windows
// regression: resolving os.Lstat identity after a replacement must not let the
// stale value bind itself to the replacement object.
func TestOpenRootFSChecked_LstatIdentityCannotRebind(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("os.Lstat identities are already stable on non-Windows platforms")
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	replacement := filepath.Join(dir, "replacement")
	if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
		t.Fatalf("write original: %v", err)
	}
	if err := os.WriteFile(replacement, []byte("replacement"), 0o644); err != nil {
		t.Fatalf("write replacement: %v", err)
	}
	expected, err := lstatRootFS(target)
	if err != nil {
		t.Fatalf("lstat original: %v", err)
	}
	renameWithinTempDirOrSkip(t, target, filepath.Join(dir, "original"))
	renameWithinTempDirOrSkip(t, replacement, target)

	f, err := openRootFSChecked(target, expected)
	if f != nil {
		_ = f.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "changed after lstat") {
		t.Fatalf("open stale lstat error = %v, want changed after lstat", err)
	}
}

func TestLoadRootFS_QueuedSubdirectoryChangedAfterLstatRejected(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	subdir := filepath.Join(root, "subdir")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(subdir, "original"), []byte("original"), 0o644); err != nil {
		t.Fatalf("write original subdir fixture: %v", err)
	}
	// The child is queued after the root's ReadDir. Replacing it from the
	// root's path must be rejected when its queued open checks the saved Lstat
	// identity, before replacement entries are materialized.
	replacement := filepath.Join(root, "replacement-source")
	if err := os.Mkdir(replacement, 0o755); err != nil {
		t.Fatalf("mkdir replacement: %v", err)
	}
	if err := os.WriteFile(filepath.Join(replacement, "replacement"), []byte("replacement"), 0o644); err != nil {
		t.Fatalf("write replacement subdir fixture: %v", err)
	}

	rootExpected, err := lstatRootFS(root)
	if err != nil {
		t.Fatalf("lstat root: %v", err)
	}
	// This tests the same stale identity that a walk item stores: capture it,
	// replace the path, and invoke the checked open used when it is popped.
	subdirExpected, err := lstatRootFS(subdir)
	if err != nil {
		t.Fatalf("lstat subdir: %v", err)
	}
	renameWithinTempDirOrSkip(t, subdir, filepath.Join(root, "original-subdir"))
	renameWithinTempDirOrSkip(t, replacement, subdir)

	rootHandle, err := openRootFSChecked(root, rootExpected)
	if err != nil {
		t.Fatalf("open unchanged root: %v", err)
	}
	if err := rootHandle.Close(); err != nil {
		t.Fatalf("close root: %v", err)
	}
	childHandle, err := openRootFSChecked(subdir, subdirExpected)
	if childHandle != nil {
		_ = childHandle.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "changed after lstat") {
		t.Fatalf("open stale queued subdirectory error = %v, want changed after lstat", err)
	}
}

func TestOpenRootFSChecked_UnchangedIdentitiesSucceed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	file := filepath.Join(dir, "archive.tar")
	if err := os.WriteFile(file, []byte("fixture"), 0o644); err != nil {
		t.Fatalf("write file fixture: %v", err)
	}
	for _, target := range []string{file, dir} {
		target := target
		t.Run(filepath.Base(target), func(t *testing.T) {
			expected, err := lstatRootFS(target)
			if err != nil {
				t.Fatalf("lstat %q: %v", target, err)
			}
			f, err := openRootFSChecked(target, expected)
			if err != nil {
				t.Fatalf("openRootFSChecked(%q): %v", target, err)
			}
			if err := f.Close(); err != nil {
				t.Fatalf("close %q: %v", target, err)
			}
		})
	}
}

func TestLoadRootFS_TarRejectsDevice(t *testing.T) {
	t.Parallel()

	entries := []tarEntry{
		{"dev/null", tar.TypeChar, nil, ""},
	}
	tarBytes := buildTarBytes(t, entries)
	out := afero.NewMemMapFs()
	if err := loadRootFSFromReader(out, "evil.tar", bytes.NewReader(tarBytes)); err == nil {
		t.Fatal("expected error for tar with char device, got nil")
	}
}

func TestLoadRootFS_TarRejectsFifo(t *testing.T) {
	t.Parallel()

	entries := []tarEntry{
		{"pipe", tar.TypeFifo, nil, ""},
	}
	tarBytes := buildTarBytes(t, entries)
	out := afero.NewMemMapFs()
	if err := loadRootFSFromReader(out, "evil.tar", bytes.NewReader(tarBytes)); err == nil {
		t.Fatal("expected error for tar with fifo, got nil")
	}
}

func TestLoadRootFS_TarRejectsTraversal(t *testing.T) {
	t.Parallel()

	entries := []tarEntry{
		{"safe", tar.TypeDir, nil, ""},
		{"safe/../escape", tar.TypeReg, []byte("x"), ""},
	}
	tarBytes := buildTarBytes(t, entries)
	out := afero.NewMemMapFs()
	err := loadRootFSFromReader(out, "evil.tar", bytes.NewReader(tarBytes))
	if err == nil {
		t.Fatal("expected error for tar with traversal path, got nil")
	}
	if !strings.Contains(err.Error(), "..") && !strings.Contains(err.Error(), "escape") && !strings.Contains(err.Error(), "traversal") {
		t.Logf("traversal rejection error: %v", err)
	}
}

func TestLoadRootFS_TarRejectsAbsolute(t *testing.T) {
	t.Parallel()

	entries := []tarEntry{
		{"/etc/passwd", tar.TypeReg, []byte("x"), ""},
	}
	tarBytes := buildTarBytes(t, entries)
	out := afero.NewMemMapFs()
	if err := loadRootFSFromReader(out, "evil.tar", bytes.NewReader(tarBytes)); err == nil {
		t.Fatal("expected error for tar with absolute path, got nil")
	}
}

func TestLoadRootFS_ZipRejectsSymlink(t *testing.T) {
	t.Parallel()

	entries := []zipEntry{
		{"evil", nil, 0o644 | os.ModeSymlink},
	}
	zipBytes := buildZipBytes(t, entries)
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "evil.zip")
	if err := os.WriteFile(zipPath, zipBytes, 0o644); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	cfg := &fsconf.FakeshellConfig{RootFS: zipPath}
	if _, err := LoadRootFS(cfg); err == nil {
		t.Fatal("expected error for zip with symlink, got nil")
	}
}

func TestLoadRootFS_TarRejectsTooManyEntries(t *testing.T) {
	t.Parallel()

	// Build a tar with MaxRootFSEntries+1 entries.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i := 0; i <= MaxRootFSEntries; i++ {
		hdr := &tar.Header{
			Name:     "f" + itoa(i),
			Typeflag: tar.TypeReg,
			Size:     0,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader: %v", err)
		}
	}
	tw.Close()

	out := afero.NewMemMapFs()
	err := loadRootFSFromReader(out, "big.tar", bytes.NewReader(buf.Bytes()))
	if err == nil {
		t.Fatal("expected error for too many entries, got nil")
	}
	if !strings.Contains(err.Error(), "MaxRootFSEntries") {
		t.Errorf("error should mention MaxRootFSEntries, got: %v", err)
	}
}

func TestLoadRootFS_NilConfigErrors(t *testing.T) {
	t.Parallel()

	if _, err := LoadRootFS(nil); err == nil {
		t.Fatal("LoadRootFS(nil) expected error, got nil")
	}
}

func TestLoadRootFS_MissingRootFSErrors(t *testing.T) {
	t.Parallel()

	cfg := &fsconf.FakeshellConfig{RootFS: filepath.Join(t.TempDir(), "does-not-exist")}
	if _, err := LoadRootFS(cfg); err == nil {
		t.Fatal("LoadRootFS(missing) expected error, got nil")
	}
}

// itoa is a tiny dependency-free int->string to keep the test self-contained.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// ---------------------------------------------------------------------------
// Embedded rootfs smoke: corrupted gzip should fail closed
// ---------------------------------------------------------------------------

func TestLoadRootFSFromReader_CorruptGzipFails(t *testing.T) {
	t.Parallel()

	out := afero.NewMemMapFs()
	// Magic bytes 0x1f 0x8b followed by garbage -> gzip.NewReader error.
	bad := []byte{0x1f, 0x8b, 0xFF, 0xFF, 0xFF}
	err := loadRootFSFromReader(out, "bad.gz", bytes.NewReader(bad))
	if err == nil {
		t.Fatal("expected error for corrupt gzip, got nil")
	}
}

func TestLoadRootFSFromReader_EmptyTarSucceeds(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.Close()

	out := afero.NewMemMapFs()
	if err := loadRootFSFromReader(out, "empty.tar", bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("empty tar should succeed, got: %v", err)
	}
}

// Ensure embedded bytes are non-empty (sanity for the //go:embed).
func TestEmbeddedFsGzipNonEmpty(t *testing.T) {
	t.Parallel()

	if len(embeddedFsGzip) == 0 {
		t.Fatal("embeddedFsGzip is empty; embed failed")
	}
	// gzip magic
	if embeddedFsGzip[0] != 0x1f || embeddedFsGzip[1] != 0x8b {
		t.Fatalf("embeddedFsGzip does not start with gzip magic: % x", embeddedFsGzip[:2])
	}
}

// readerDrainCheck proves regular-file bodies are discarded, not stored.
func TestLoadRootFS_TarDoesNotStoreBodyContent(t *testing.T) {
	t.Parallel()

	secret := "TOPSECRET-content-that-must-not-leak-into-memfs"
	entries := []tarEntry{
		{"etc", tar.TypeDir, nil, ""},
		{"etc/secret", tar.TypeReg, []byte(secret), ""},
	}
	tarBytes := buildTarBytes(t, entries)
	out := afero.NewMemMapFs()
	if err := loadRootFSFromReader(out, "secret.tar", bytes.NewReader(tarBytes)); err != nil {
		t.Fatalf("load: %v", err)
	}
	f, err := out.Open("/etc/secret")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if bytes.Contains(got, []byte(secret)) {
		t.Errorf("regular file body was copied into memfs! got %q", got)
	}
	if len(got) != 0 {
		t.Errorf("placeholder should be zero bytes, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// Regression: MaxRootFSEntries must count implicit parent directories
// (materialized nodes), not just archive headers.
// ---------------------------------------------------------------------------

// buildDeepFileTarBytes builds a tar archive containing n regular files at
// paths "dNNNNNN/file" (a 2-level tree) WITHOUT any explicit directory headers.
// Each header materializes 2 fake-FS nodes (the implicit parent dir "dNNNNNN"
// plus the file), so the materialized node count is 2*n while the header count
// is n. With n = MaxRootFSEntries/2 + 1 the headers stay under the cap but the
// materialized nodes exceed it; the loader must fail closed.
func buildDeepFileTarBytes(t *testing.T, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i := 0; i < n; i++ {
		hdr := &tar.Header{
			Name:     "d" + itoaPad(i, 6) + "/file",
			Typeflag: tar.TypeReg,
			Size:     0,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader(%s): %v", hdr.Name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	return buf.Bytes()
}

// buildDeepFileZipBytes is the zip equivalent of buildDeepFileTarBytes.
func buildDeepFileZipBytes(t *testing.T, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < n; i++ {
		fh := &zip.FileHeader{
			Name:   "d" + itoaPad(i, 6) + "/file",
			Method: zip.Store,
		}
		fh.SetMode(0o644)
		fw, err := zw.CreateHeader(fh)
		if err != nil {
			t.Fatalf("zip Create(%s): %v", fh.Name, err)
		}
		// zero-byte body
		_ = fw
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// itoaPad zero-pads n to width w. Used to build deterministic, sortable entry
// names whose per-entry length is constant (keeps archive size linear in n).
func itoaPad(n, w int) string {
	s := itoa(n)
	for len(s) < w {
		s = "0" + s
	}
	return s
}

// TestLoadRootFS_TarImplicitParentsExceedCapRegress proves the fix for the
// MaxRootFSEntries counting gap. The archive has MaxRootFSEntries/2 + 1
// headers (under the cap) but each entry implicitly creates its parent dir,
// so the materialized node count exceeds MaxRootFSEntries and the loader must
// reject it. Before the fix, only headers were counted and this archive loaded
// successfully, blowing past the cap in memory.
func TestLoadRootFS_TarImplicitParentsExceedCapRegress(t *testing.T) {
	t.Parallel()

	n := MaxRootFSEntries/2 + 1 // headers under cap, nodes = 2*n > cap
	tarBytes := buildDeepFileTarBytes(t, n)

	out := afero.NewMemMapFs()
	err := loadRootFSFromReader(out, "deep.tar", bytes.NewReader(tarBytes))
	if err == nil {
		t.Fatal("expected error for implicit-parent node overflow, got nil")
	}
	if !strings.Contains(err.Error(), "MaxRootFSEntries") {
		t.Errorf("error should mention MaxRootFSEntries, got: %v", err)
	}
}

// TestLoadRootFS_TarImplicitParentsAtCapSucceeds proves the fix does not
// regress ordinary archives: MaxRootFSEntries/2 headers at "dNNNNNN/file"
// materialize exactly MaxRootFSEntries nodes (under cap), so loading succeeds.
func TestLoadRootFS_TarImplicitParentsAtCapSucceeds(t *testing.T) {
	t.Parallel()

	n := MaxRootFSEntries / 2 // headers under cap, nodes = 2*n == cap (OK)
	tarBytes := buildDeepFileTarBytes(t, n)

	out := afero.NewMemMapFs()
	if err := loadRootFSFromReader(out, "deep-ok.tar", bytes.NewReader(tarBytes)); err != nil {
		t.Fatalf("expected success for under-cap implicit parents, got: %v", err)
	}
	// Spot-check that both an implicit parent dir and a file were materialized.
	if ok, err := afero.IsDir(out, "/d000000"); err != nil || !ok {
		t.Errorf("expected implicit dir /d000000, ok=%v err=%v", ok, err)
	}
	if ok, err := afero.Exists(out, "/d000000/file"); err != nil || !ok {
		t.Errorf("expected file /d000000/file, ok=%v err=%v", ok, err)
	}
}

// TestLoadRootFS_ZipImplicitParentsExceedCapRegress is the zip equivalent of
// TestLoadRootFS_TarImplicitParentsExceedCapRegress.
func TestLoadRootFS_ZipImplicitParentsExceedCapRegress(t *testing.T) {
	t.Parallel()

	n := MaxRootFSEntries/2 + 1
	zipBytes := buildDeepFileZipBytes(t, n)

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "deep.zip")
	if err := os.WriteFile(zipPath, zipBytes, 0o644); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	if _, err := LoadRootFS(&fsconf.FakeshellConfig{RootFS: zipPath}); err == nil {
		t.Fatal("expected error for implicit-parent node overflow, got nil")
	}
}

// TestLoadRootFS_ZipImplicitParentsAtCapSucceeds proves ordinary under-cap zip
// archives with implicit parents still load.
func TestLoadRootFS_ZipImplicitParentsAtCapSucceeds(t *testing.T) {
	t.Parallel()

	n := MaxRootFSEntries / 2
	zipBytes := buildDeepFileZipBytes(t, n)

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "deep-ok.zip")
	if err := os.WriteFile(zipPath, zipBytes, 0o644); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	f, err := LoadRootFS(&fsconf.FakeshellConfig{RootFS: zipPath})
	if err != nil {
		t.Fatalf("expected success for under-cap implicit parents, got: %v", err)
	}
	if ok, err := afero.IsDir(f, "/d000000"); err != nil || !ok {
		t.Errorf("expected implicit dir /d000000, ok=%v err=%v", ok, err)
	}
	if ok, err := afero.Exists(f, "/d000000/file"); err != nil || !ok {
		t.Errorf("expected file /d000000/file, ok=%v err=%v", ok, err)
	}
}

// TestLoadRootFS_TarImplicitParentsNoDupCount proves that when a directory
// header and a file sharing the same parent are both present, the shared
// parent is counted only once. This archive has 3 headers ("home",
// "home/root", "home/root/.profile") but only 3 unique nodes - well under the
// cap - so it must succeed and demonstrate implicit-parent counting works for
// ordinary archives.
func TestLoadRootFS_TarImplicitParentsNoDupCount(t *testing.T) {
	t.Parallel()

	// "home/root/.profile" with no explicit "home" header proves implicit
	// parent counting AND de-dup of the shared "home" / "home/root" ancestors.
	entries := []tarEntry{
		{"home/root/.profile", tar.TypeReg, []byte("export PATH=/bin\n"), ""},
	}
	tarBytes := buildTarBytes(t, entries)

	out := afero.NewMemMapFs()
	if err := loadRootFSFromReader(out, "implicit.tar", bytes.NewReader(tarBytes)); err != nil {
		t.Fatalf("expected success for ordinary archive with implicit parents, got: %v", err)
	}
	assertImplicitProfileLoaded(t, out)
}

// TestLoadRootFS_ZipImplicitParentsNoDupCount mirrors the tar test for zip.
func TestLoadRootFS_ZipImplicitParentsNoDupCount(t *testing.T) {
	t.Parallel()

	entries := []zipEntry{
		{"home/root/.profile", []byte("export PATH=/bin\n"), 0o644},
	}
	zipBytes := buildZipBytes(t, entries)

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "implicit.zip")
	if err := os.WriteFile(zipPath, zipBytes, 0o644); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	f, err := LoadRootFS(&fsconf.FakeshellConfig{RootFS: zipPath})
	if err != nil {
		t.Fatalf("expected success for ordinary zip with implicit parents, got: %v", err)
	}
	assertImplicitProfileLoaded(t, f)
}

// assertImplicitProfileLoaded checks only the implicit-parent fixture paths
// (home/root/.profile and its ancestors). Unlike assertLoadedPaths it does
// not require /etc/passwd, because this fixture intentionally omits it to
// isolate the implicit-parent behavior.
func assertImplicitProfileLoaded(t *testing.T, f afero.Fs) {
	t.Helper()
	for _, p := range []string{"/home", "/home/root"} {
		ok, err := afero.IsDir(f, p)
		if err != nil {
			t.Fatalf("IsDir(%s) error = %v", p, err)
		}
		if !ok {
			t.Errorf("expected implicit directory %s", p)
		}
	}
	info, err := f.Stat("/home/root/.profile")
	if err != nil {
		t.Fatalf("Stat(/home/root/.profile) error = %v", err)
	}
	if info.IsDir() {
		t.Errorf("/home/root/.profile is a directory, want regular file")
	}
	if info.Size() != 0 {
		t.Errorf("/home/root/.profile size = %d, want 0 (content must not be copied)", info.Size())
	}
}

// TestNodeCounter_Add verifies the de-dup and cap-enforcement semantics of the
// shared helper directly.
func TestNodeCounter_Add(t *testing.T) {
	t.Parallel()

	nc := newNodeCounter()
	// Add a path with two ancestors: "a", "a/b", "a/b/c" -> 3 nodes.
	if err := nc.add("a/b/c"); err != nil {
		t.Fatalf("add a/b/c: %v", err)
	}
	if nc.count != 3 {
		t.Errorf("after a/b/c, count=%d want 3", nc.count)
	}
	// Re-adding a path whose ancestors are all seen must not change count.
	if err := nc.add("a/b/c"); err != nil {
		t.Fatalf("re-add a/b/c: %v", err)
	}
	if nc.count != 3 {
		t.Errorf("after re-add a/b/c, count=%d want 3", nc.count)
	}
	// Adding a sibling reuses "a" and "a/b" (already seen) and adds only the
	// new leaf.
	if err := nc.add("a/b/d"); err != nil {
		t.Fatalf("add a/b/d: %v", err)
	}
	if nc.count != 4 {
		t.Errorf("after a/b/d, count=%d want 4", nc.count)
	}
	// Root paths are ignored.
	if err := nc.add("."); err != nil {
		t.Fatalf("add .: %v", err)
	}
	if nc.count != 4 {
		t.Errorf("after ., count=%d want 4 (root not counted)", nc.count)
	}
	if err := nc.add(""); err != nil {
		t.Fatalf("add empty: %v", err)
	}
	if nc.count != 4 {
		t.Errorf("after empty, count=%d want 4 (empty not counted)", nc.count)
	}
}

// ---------------------------------------------------------------------------
// Regression: raw header/entry cap must be independent of nodeCounter.
//
// nodeCounter de-dups by path, so an archive containing many duplicate headers
// for the same safe path materializes only a handful of fake-FS nodes while
// forcing the loader to process an unbounded number of raw headers. Before the
// fix, only materialized nodes were counted, so a duplicate-header archive
// passed the cap check. The loader must fail closed on raw header/entry
// overflow regardless of the de-duped node count.
// ---------------------------------------------------------------------------

// buildDupTarBytes builds a tar archive containing n identical regular-file
// headers all naming "dup/file". They clean to the same path and thus
// materialize only 2 fake-FS nodes (the implicit "dup" dir plus the file), so
// the materialized-node count stays well under the cap while the raw header
// count is n. With n = MaxRootFSEntries+1 the loader must reject on raw headers.
func buildDupTarBytes(t *testing.T, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i := 0; i < n; i++ {
		hdr := &tar.Header{
			Name:     "dup/file",
			Typeflag: tar.TypeReg,
			Size:     0,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader(dup/file #%d): %v", i, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	return buf.Bytes()
}

// buildDupZipBytes builds a zip archive containing n identical entries all
// naming "dup/file". See buildDupTarBytes for rationale.
func buildDupZipBytes(t *testing.T, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < n; i++ {
		fh := &zip.FileHeader{
			Name:   "dup/file",
			Method: zip.Store,
		}
		fh.SetMode(0o644)
		fw, err := zw.CreateHeader(fh)
		if err != nil {
			t.Fatalf("zip Create(dup/file #%d): %v", i, err)
		}
		_ = fw
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// TestLoadRootFS_TarDuplicateHeadersExceedRawCap proves the raw tar header cap
// is enforced independently of the de-duped materialized-node count. The
// archive has MaxRootFSEntries+1 duplicate regular-file headers for the same
// safe path "dup/file", which materialize only 2 nodes (well under the cap)
// but exceed the raw header cap. The loader must reject it.
func TestLoadRootFS_TarDuplicateHeadersExceedRawCap(t *testing.T) {
	t.Parallel()

	n := MaxRootFSEntries + 1
	tarBytes := buildDupTarBytes(t, n)

	out := afero.NewMemMapFs()
	err := loadRootFSFromReader(out, "dup.tar", bytes.NewReader(tarBytes))
	if err == nil {
		t.Fatal("expected error for duplicate-header raw overflow, got nil")
	}
	if !strings.Contains(err.Error(), "MaxRootFSEntries") {
		t.Errorf("error should mention MaxRootFSEntries, got: %v", err)
	}
}

// TestLoadRootFS_ZipDuplicateEntriesExceedRawCap is the zip equivalent of
// TestLoadRootFS_TarDuplicateHeadersExceedRawCap.
func TestLoadRootFS_ZipDuplicateEntriesExceedRawCap(t *testing.T) {
	t.Parallel()

	n := MaxRootFSEntries + 1
	zipBytes := buildDupZipBytes(t, n)

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "dup.zip")
	if err := os.WriteFile(zipPath, zipBytes, 0o644); err != nil {
		t.Fatalf("write zip: %v", err)
	}
	_, err := LoadRootFS(&fsconf.FakeshellConfig{RootFS: zipPath})
	if err == nil {
		t.Fatal("expected error for duplicate-entry raw overflow, got nil")
	}
	if !strings.Contains(err.Error(), "MaxRootFSEntries") {
		t.Errorf("error should mention MaxRootFSEntries, got: %v", err)
	}
}

// TestLoadRootFS_TarDuplicateHeadersUnderCapSucceeds proves the raw cap does
// not regress ordinary duplicate-bearing archives: MaxRootFSEntries duplicate
// headers for "dup/file" (exactly at the cap, not over) still succeed and
// materialize the single expected file as a zero-byte placeholder.
func TestLoadRootFS_TarDuplicateHeadersUnderCapSucceeds(t *testing.T) {
	t.Parallel()

	n := MaxRootFSEntries // exactly at cap (not over)
	tarBytes := buildDupTarBytes(t, n)

	out := afero.NewMemMapFs()
	if err := loadRootFSFromReader(out, "dup-ok.tar", bytes.NewReader(tarBytes)); err != nil {
		t.Fatalf("expected success for at-cap duplicate headers, got: %v", err)
	}
	if ok, err := afero.IsDir(out, "/dup"); err != nil || !ok {
		t.Errorf("expected implicit dir /dup, ok=%v err=%v", ok, err)
	}
	info, err := out.Stat("/dup/file")
	if err != nil {
		t.Fatalf("Stat(/dup/file) error = %v", err)
	}
	if info.IsDir() {
		t.Fatalf("/dup/file is a directory, want regular file")
	}
	if info.Size() != 0 {
		t.Errorf("/dup/file size = %d, want 0 (placeholder must not copy content)", info.Size())
	}
}

// ---------------------------------------------------------------------------
// Regular-file body caps (tar): per-file and cumulative drain limits.
//
// Regular-file contents are never stored in the fake filesystem (only zero-byte
// placeholders are created), but the loader still drains each body to keep the
// tar stream aligned. Without caps, a header advertising a huge Size could
// force gigabytes of I/O/decompression during startup. MaxRootFSFileBodyBytes
// bounds the per-file drain; MaxRootFSTotalBodyBytes bounds the cumulative
// drain. Both are enforced before the body is read, so a too-large header is
// rejected without copying content.
// ---------------------------------------------------------------------------

// buildTarBytesStreaming writes a tar archive to buf. For each regular entry
// the body is produced by calling body(n) which must return a reader yielding
// exactly n bytes. This lets large-body tests avoid holding the full body in
// memory at once (the tar.Writer copies from the reader into buf in chunks).
func buildTarBytesStreaming(t *testing.T, entries []tarEntryStreaming) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Mode:     0o644,
			Typeflag: e.typ,
			Size:     e.size,
		}
		if e.typ == tar.TypeDir {
			hdr.Mode = 0o755
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader(%s): %v", e.name, err)
		}
		if (e.typ == tar.TypeReg || e.typ == tar.TypeRegA) && e.size > 0 {
			if e.body == nil {
				t.Fatalf("entry %s: streaming body reader is nil", e.name)
			}
			if _, err := io.Copy(tw, e.body); err != nil {
				t.Fatalf("Write body(%s): %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	return buf.Bytes()
}

type tarEntryStreaming struct {
	name string
	typ  byte
	size int64
	body io.Reader // must yield exactly `size` bytes for regular files
}

// repeatReader yields `n` copies of the single byte `b` without allocating
// the full slice. It is used to produce large regular-file bodies for the
// drain-cap tests without holding the body in memory.
type repeatReader struct {
	b byte
	n int64
}

func (r *repeatReader) Read(p []byte) (int, error) {
	if r.n <= 0 {
		return 0, io.EOF
	}
	cap := int64(len(p))
	if cap > r.n {
		cap = r.n
	}
	for i := int64(0); i < cap; i++ {
		p[i] = r.b
	}
	r.n -= cap
	return int(cap), nil
}

// TestLoadRootFS_TarRejectsPerFileBodyCap proves a single regular-file header
// advertising a body larger than MaxRootFSFileBodyBytes is rejected before any
// body bytes are drained. The body in the archive is empty; the rejection
// happens at the header-size check inside drainTarBody, which fires before
// io.CopyN, so the truncated/empty body is never read.
func TestLoadRootFS_TarRejectsPerFileBodyCap(t *testing.T) {
	t.Parallel()

	// Header advertises a body bigger than the per-file cap, but we write no
	// body bytes. drainTarBody checks hdr.Size > MaxRootFSFileBodyBytes BEFORE
	// reading, so this rejects at the header without needing the body.
	entries := []tarEntryStreaming{
		{name: "big", typ: tar.TypeReg, size: int64(MaxRootFSFileBodyBytes) + 1, body: &repeatReader{b: 'x', n: int64(MaxRootFSFileBodyBytes) + 1}},
	}
	tarBytes := buildTarBytesStreaming(t, entries)

	out := afero.NewMemMapFs()
	err := loadRootFSFromReader(out, "bigfile.tar", bytes.NewReader(tarBytes))
	if err == nil {
		t.Fatal("expected error for per-file body cap overflow, got nil")
	}
	if !strings.Contains(err.Error(), "MaxRootFSFileBodyBytes") {
		t.Errorf("error should mention MaxRootFSFileBodyBytes, got: %v", err)
	}
}

// TestLoadRootFS_TarRejectsTotalBodyCap proves that many regular files whose
// cumulative body bytes exceed MaxRootFSTotalBodyBytes are rejected. Each file
// is under the per-file cap (so the per-file check passes) but their sum
// exceeds the cumulative cap. The rejection happens at the cumulative check
// inside drainTarBody for the file that would push the total over.
//
// This test does NOT run in parallel because it materializes several
// MaxRootFSFileBodyBytes bodies into a bytes.Buffer (roughly 64 MiB+).
func TestLoadRootFS_TarRejectsTotalBodyCap(t *testing.T) {
	// Build ceil(MaxRootFSTotalBodyBytes / MaxRootFSFileBodyBytes) + 1 files,
	// each with a MaxRootFSFileBodyBytes body. The cumulative body bytes
	// exceed MaxRootFSTotalBodyBytes on the last file; the per-file check
	// passes for every file. The loader must reject on the cumulative check.
	perFile := int64(MaxRootFSFileBodyBytes)
	need := int64(MaxRootFSTotalBodyBytes)/perFile + 1 // files to exceed cap

	entries := make([]tarEntryStreaming, 0, need)
	for i := int64(0); i < need; i++ {
		entries = append(entries, tarEntryStreaming{
			name: "f" + itoaPad(int(i), 6),
			typ:  tar.TypeReg,
			size: perFile,
			body: &repeatReader{b: 'x', n: perFile},
		})
	}
	tarBytes := buildTarBytesStreaming(t, entries)

	out := afero.NewMemMapFs()
	err := loadRootFSFromReader(out, "totalcap.tar", bytes.NewReader(tarBytes))
	if err == nil {
		t.Fatal("expected error for cumulative body cap overflow, got nil")
	}
	if !strings.Contains(err.Error(), "MaxRootFSTotalBodyBytes") {
		t.Errorf("error should mention MaxRootFSTotalBodyBytes, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Regression: tar stream total cap (MaxRootFSTarStreamBytes).
//
// archive/tar.Reader.Next() consumes PAX/GNU metadata header bodies
// (TypeXHeader / TypeXGlobalHeader / TypeGNULongName / TypeGNULongLink)
// INTERNALLY before returning, so the per-file cap (MaxRootFSFileBodyBytes)
// and the cumulative regular-file body cap (MaxRootFSTotalBodyBytes) in
// drainTarBody cannot see those bytes. A malicious archive with many large
// metadata headers could therefore force unbounded decompressed I/O before
// any existing cap fires. MaxRootFSTarStreamBytes bounds the TOTAL
// decompressed tar stream consumed by Next() and Read(), including metadata
// bodies and block padding.
// ---------------------------------------------------------------------------

// TestLoadRootFS_TarStreamCapRejectsPAXGlobalHeaders proves an archive whose
// TypeXGlobalHeader metadata bodies (consumed inside tar.Reader.Next()) push
// the total decompressed tar stream past MaxRootFSTarStreamBytes is rejected.
//
// The archive contains only TypeXGlobalHeader entries - no regular files - so
// drainTarBody is never invoked and neither MaxRootFSFileBodyBytes nor
// MaxRootFSTotalBodyBytes can fire. Before the fix this archive would be
// processed unboundedly (each Next() read up to 1 MiB of PAX body internally).
// After the fix, the limited tar reader fails closed once the total
// decompressed stream exceeds MaxRootFSTarStreamBytes.
//
// The archive is gzip-compressed: the decompressed stream is ~74 MiB but the
// compressed bytes are tiny (the PAX bodies are highly repetitive), so the
// test is fast and low-memory. The tar.Writer streams entries into a gzip
// writer, so the full decompressed tar never lives in memory at once.
//
// This test does NOT run in parallel because it is intentionally heavier.
func TestLoadRootFS_TarStreamCapRejectsPAXGlobalHeaders(t *testing.T) {
	// Each TypeXGlobalHeader carries a PAX record whose value is just under
	// 1 MiB. archive/tar caps a single PAX body at maxSpecialFileSize
	// (1<<20 = 1048576 bytes) including the PAX record framing, so the raw
	// value must be slightly smaller than 1 MiB to avoid ErrFieldTooLong.
	//
	// MaxRootFSTarStreamBytes = MaxRootFSTotalBodyBytes
	//                        + MaxRootFSEntries*1024 + 1024
	//                        ≈ 64 MiB + ~9.77 MiB + 1 KiB ≈ 73.8 MiB.
	// With 80 entries of ~1 MiB each the decompressed stream is ~80 MiB,
	// comfortably above the cap. The raw entry count (80) is well below
	// MaxRootFSEntries (10000), and no regular files are present, so only
	// the tar-stream cap can catch this.
	const paxValueLen = 1<<20 - 64 // 1048512: under maxSpecialFileSize after framing
	const numEntries = 80

	// Build a gzip-compressed tar streaming into a bytes.Buffer so the full
	// decompressed tar never lives in memory.
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	tw := tar.NewWriter(gw)

	paxValue := strings.Repeat("x", paxValueLen)
	for i := 0; i < numEntries; i++ {
		// Each global header carries one PAX record. Use a unique key per
		// entry so the tar writer emits a fresh body each time.
		hdr := &tar.Header{
			Name:       "g" + itoaPad(i, 4),
			Typeflag:   tar.TypeXGlobalHeader,
			Format:     tar.FormatPAX,
			PAXRecords: map[string]string{"x.g" + itoaPad(i, 4): paxValue},
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader(%d): %v", i, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	out := afero.NewMemMapFs()
	err := loadRootFSFromReader(out, "paxstream.tar.gz", bytes.NewReader(gzBuf.Bytes()))
	if err == nil {
		t.Fatal("expected error for tar stream cap overflow, got nil (metadata bodies were not bounded)")
	}
	if !strings.Contains(err.Error(), "MaxRootFSTarStreamBytes") {
		t.Errorf("error should mention MaxRootFSTarStreamBytes, got: %v", err)
	}
}

// TestLoadRootFS_TarStreamCapAllowsValidArchive proves the tar stream cap does
// not regress ordinary archives that respect the other caps. The embedded
// rootfs fixture (a real tar.gz) is well under MaxRootFSTarStreamBytes, so
// loading it via loadRootFSFromReader must succeed.
func TestLoadRootFS_TarStreamCapAllowsValidArchive(t *testing.T) {
	t.Parallel()

	entries := []tarEntry{
		{"etc", tar.TypeDir, nil, ""},
		{"etc/passwd", tar.TypeReg, []byte("root:x:0:0\n"), ""},
		{"home/root/.profile", tar.TypeReg, []byte("export PATH=/bin\n"), ""},
	}
	tarBytes := buildTarBytes(t, entries)
	out := afero.NewMemMapFs()
	if err := loadRootFSFromReader(out, "ok.tar", bytes.NewReader(tarBytes)); err != nil {
		t.Fatalf("expected success for ordinary archive under tar stream cap, got: %v", err)
	}
	assertLoadedPaths(t, out)
}

// TestLimitedRootFSTarReader_FailsClosedAtCap is a focused unit test for the
// limited reader wrapper. It proves the reader allows up to (but not
// including) the (cap+1)th byte and returns a fail-closed error mentioning
// MaxRootFSTarStreamBytes once the cap is exceeded. It uses a reader whose
// total length is cap+2 so the (cap+1)th and (cap+2)th reads trip the guard.
func TestLimitedRootFSTarReader_FailsClosedAtCap(t *testing.T) {
	t.Parallel()

	// We cannot easily synthesize MaxRootFSTarStreamBytes+2 bytes of input
	// (that is ~74 MiB). Instead, validate the wrapper logic with a small
	// override of the cap by constructing the reader directly with a reduced
	// maxRead. This proves the boundary semantics: reads up to maxRead
	// succeed; the byte that crosses maxRead returns the cap error.
	l := &limitedRootFSTarReader{
		r:       bytes.NewReader([]byte("abcdefghij")), // 10 bytes
		read:    0,
		maxRead: 5,
	}
	buf := make([]byte, 4)
	// First read: 4 bytes (read=4, under cap).
	n, err := l.Read(buf)
	if err != nil {
		t.Fatalf("first Read error: %v", err)
	}
	if n != 4 {
		t.Fatalf("first Read n=%d want 4", n)
	}
	// Second read: requests 4, only 6 remain in source, cap is 5 -> reads 1
	// more byte (read=5), then next byte would push read to 6 > 5 -> error.
	n, err = l.Read(buf)
	if err == nil {
		t.Fatalf("expected cap error on second Read, got nil (n=%d)", n)
	}
	if !strings.Contains(err.Error(), "MaxRootFSTarStreamBytes") {
		t.Errorf("error should mention MaxRootFSTarStreamBytes, got: %v", err)
	}
	// The read that crosses the cap may return the partial byte it managed
	// to read before tripping the guard; n can be 0 or 1 depending on slice
	// sizing. We only require that an error is returned and that no further
	// reads succeed.
	if _, err := l.Read(buf); err == nil {
		t.Errorf("Read after cap must keep failing, got nil")
	}
}

// TestLoadRootFS_TarNegativeSizeRejected proves a tar header with a negative
// Size is rejected rather than passed to io.CopyN (which would misbehave on
// negative N). This is a defensive check; tar headers should never carry a
// negative size, but an attacker could craft one.
func TestLoadRootFS_TarNegativeSizeRejected(t *testing.T) {
	t.Parallel()

	// Build the tar by hand because tar.Writer would not let us set a negative
	// size directly through WriteHeader in a clean way; instead we craft a
	// minimal tar header bytes with a negative encoded size. Simpler: call
	// drainTarBody directly with size < 0.
	tr := tar.NewReader(bytes.NewReader(nil))
	total := int64(0)
	err := drainTarBody("neg.tar", "neg", tr, -1, &total)
	if err == nil {
		t.Fatal("expected error for negative size, got nil")
	}
	if !strings.Contains(err.Error(), "negative size") {
		t.Errorf("error should mention negative size, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Zip EOCD preflight: reject Zip64, too many entries, huge central directory.
// ---------------------------------------------------------------------------

// craftEOCD builds a minimal archive whose tail is a 22-byte EOCD record
// (no comment) with the given total entry count, central-directory size, and
// central-directory offset. All multi-disk fields are zero (single-disk
// archive).
//
// The archive body preceding the EOCD is just `preLen` zero bytes (default 0);
// preflight only reads the EOCD tail and does not parse the central directory,
// so we do NOT materialize cdSize bytes of fake central-directory entries.
// The cdSize and cdOffset values are written into the EOCD record as-is; this
// lets tests craft pathological declared sizes (e.g. the 0xffffffff Zip64
// sentinel or a >cap size) without allocating gigabytes.
func craftEOCD(totalEntries uint16, cdSize uint32, cdOffset uint32) []byte {
	return craftEOCDWithPrefix(totalEntries, cdSize, cdOffset, 0)
}

// craftEOCDWithPrefix is like craftEOCD but prepends preLen zero bytes before
// the EOCD. This is used to place a Zip64 EOCD locator (or other bytes) in
// front of the EOCD.
func craftEOCDWithPrefix(totalEntries uint16, cdSize uint32, cdOffset uint32, preLen int) []byte {
	buf := make([]byte, preLen, preLen+22)
	eocd := make([]byte, 22)
	// signature 0x06054b50 little-endian
	eocd[0] = 0x50
	eocd[1] = 0x4b
	eocd[2] = 0x05
	eocd[3] = 0x06
	// disk number = 0, CD start disk = 0 (already zero)
	// entries on this disk = totalEntries
	eocd[8] = byte(totalEntries)
	eocd[9] = byte(totalEntries >> 8)
	// total entries = totalEntries
	eocd[10] = byte(totalEntries)
	eocd[11] = byte(totalEntries >> 8)
	// central directory size
	eocd[12] = byte(cdSize)
	eocd[13] = byte(cdSize >> 8)
	eocd[14] = byte(cdSize >> 16)
	eocd[15] = byte(cdSize >> 24)
	// central directory offset
	eocd[16] = byte(cdOffset)
	eocd[17] = byte(cdOffset >> 8)
	eocd[18] = byte(cdOffset >> 16)
	eocd[19] = byte(cdOffset >> 24)
	// comment length = 0 (already zero)
	buf = append(buf, eocd...)
	return buf
}

// TestPreflightZip_TooManyEntries proves preflightZipDirectory rejects an
// archive whose EOCD advertises more than MaxRootFSEntries entries, before
// zip.NewReader is ever called. This bounds the work zip.NewReader can do.
func TestPreflightZip_TooManyEntries(t *testing.T) {
	t.Parallel()

	total := uint16(MaxRootFSEntries + 1)
	// cdSize/offset are tiny and consistent; preflight should fail on the
	// entry-count check.
	arch := craftEOCD(total, 0, 0)
	err := preflightZipDirectory(bytes.NewReader(arch), int64(len(arch)))
	if err == nil {
		t.Fatal("expected error for too many entries, got nil")
	}
	if !strings.Contains(err.Error(), "MaxRootFSEntries") {
		t.Errorf("error should mention MaxRootFSEntries, got: %v", err)
	}
}

// TestPreflightZip_CentralDirectoryTooLarge proves preflight rejects an archive
// whose central-directory size exceeds MaxRootFSZipCentralDirectoryBytes,
// before zip.NewReader is called. This bounds the memory zip.NewReader would
// allocate parsing the central directory.
func TestPreflightZip_CentralDirectoryTooLarge(t *testing.T) {
	t.Parallel()

	// Advertise a central directory larger than the cap. The actual archive
	// bytes do not contain that much data; preflight reads only the EOCD and
	// checks the declared size against the cap, so it fails before touching
	// the (non-existent) central directory bytes.
	tooBig := uint32(MaxRootFSZipCentralDirectoryBytes + 1)
	arch := craftEOCD(0, tooBig, 0)
	err := preflightZipDirectory(bytes.NewReader(arch), int64(len(arch)))
	if err == nil {
		t.Fatal("expected error for oversized central directory, got nil")
	}
	if !strings.Contains(err.Error(), "MaxRootFSZipCentralDirectoryBytes") {
		t.Errorf("error should mention MaxRootFSZipCentralDirectoryBytes, got: %v", err)
	}
}

// TestPreflightZip_Zip64SentinelsRejected proves preflight rejects archives
// whose EOCD entry-count, central-directory-size, or central-directory-offset
// fields carry the Zip64 sentinel values (0xffff / 0xffffffff). Such archives
// require a Zip64 EOCD record to determine the real values, and the loader
// does not support Zip64, so it fails closed.
func TestPreflightZip_Zip64SentinelsRejected(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		fn   func() []byte
	}{
		{
			"entries sentinel",
			func() []byte { return craftEOCD(0xffff, 0, 0) },
		},
		{
			"cd size sentinel",
			func() []byte { return craftEOCD(0, 0xffffffff, 0) },
		},
		{
			"cd offset sentinel",
			func() []byte { return craftEOCD(0, 0, 0xffffffff) },
		},
	}
	for _, tc := range cases {
		arch := tc.fn()
		err := preflightZipDirectory(bytes.NewReader(arch), int64(len(arch)))
		if err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), "zip64") {
			t.Errorf("%s: error should mention zip64, got: %v", tc.name, err)
		}
	}
}

// TestPreflightZip_Zip64LocatorRejected proves preflight rejects archives that
// carry a Zip64 EOCD locator record immediately before the EOCD. The locator
// signature is 0x07064b50.
func TestPreflightZip_Zip64LocatorRejected(t *testing.T) {
	t.Parallel()

	// Build: [Zip64 EOCD locator (20 bytes)] [EOCD (22 bytes)]
	locator := make([]byte, 20)
	locator[0] = 0x50
	locator[1] = 0x4b
	locator[2] = 0x06
	locator[3] = 0x07 // zip64EOCDLocatorSignature little-endian
	eocd := craftEOCD(0, 0, 0)
	// craftEOCD prepends a cdSize-byte central directory (0 here), so eocd is
	// just the 22-byte EOCD record.
	arch := append(locator, eocd...)
	err := preflightZipDirectory(bytes.NewReader(arch), int64(len(arch)))
	if err == nil {
		t.Fatal("expected error for Zip64 locator, got nil")
	}
	if !strings.Contains(err.Error(), "zip64") {
		t.Errorf("error should mention zip64, got: %v", err)
	}
}

// TestPreflightZip_DiskSpanningRejected proves preflight rejects multi-disk
// archives (disk number or CD start disk non-zero), which archive/zip does not
// support.
func TestPreflightZip_DiskSpanningRejected(t *testing.T) {
	t.Parallel()

	// Build an EOCD with disk number = 1.
	eocd := craftEOCD(0, 0, 0)
	eocd[4] = 1 // disk number = 1
	err := preflightZipDirectory(bytes.NewReader(eocd), int64(len(eocd)))
	if err == nil {
		t.Fatal("expected error for disk spanning, got nil")
	}
	if !strings.Contains(err.Error(), "disk spanning") {
		t.Errorf("error should mention disk spanning, got: %v", err)
	}
}

// TestPreflightZip_CDOutOfBounds proves preflight rejects archives whose
// central directory (offset + size) extends past the end of the file.
func TestPreflightZip_CDOutOfBounds(t *testing.T) {
	t.Parallel()

	// cdOffset+cdSize > file size. Build a 22-byte EOCD with a cdOffset that
	// points past the archive.
	eocd := craftEOCD(0, 10, 100) // offset 100, size 10 -> 110 > 22
	err := preflightZipDirectory(bytes.NewReader(eocd), int64(len(eocd)))
	if err == nil {
		t.Fatal("expected error for CD out of bounds, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds file size") {
		t.Errorf("error should mention file size, got: %v", err)
	}
}

// TestPreflightZip_TooSmall proves preflight rejects archives smaller than the
// minimum EOCD size.
func TestPreflightZip_TooSmall(t *testing.T) {
	t.Parallel()

	arch := []byte{0x50, 0x4b, 0x05, 0x06}
	err := preflightZipDirectory(bytes.NewReader(arch), int64(len(arch)))
	if err == nil {
		t.Fatal("expected error for too-small archive, got nil")
	}
	if !strings.Contains(err.Error(), "too small") {
		t.Errorf("error should mention too small, got: %v", err)
	}
}

// TestPreflightZip_NoEOCD proves preflight rejects an archive whose tail does
// not contain an EOCD signature.
func TestPreflightZip_NoEOCD(t *testing.T) {
	t.Parallel()

	// 64 bytes of garbage, no EOCD signature.
	arch := bytes.Repeat([]byte{0xAA}, 64)
	err := preflightZipDirectory(bytes.NewReader(arch), int64(len(arch)))
	if err == nil {
		t.Fatal("expected error for missing EOCD, got nil")
	}
	if !strings.Contains(err.Error(), "EOCD") {
		t.Errorf("error should mention EOCD, got: %v", err)
	}
}

// TestPreflightZip_AcceptsValidEOCD proves a structurally-valid EOCD with
// entry count / central-directory size under the caps passes preflight. The
// archive may still be rejected by zip.NewReader for other reasons, but
// preflight itself must accept it.
func TestPreflightZip_AcceptsValidEOCD(t *testing.T) {
	t.Parallel()

	// 5 entries, tiny but structurally valid central directory at offset 0.
	cd := buildCentralDirectoryHeaders(t, 5)
	arch := append(cd, craftEOCD(5, uint32(len(cd)), 0)...)
	if err := preflightZipDirectory(bytes.NewReader(arch), int64(len(arch))); err != nil {
		t.Fatalf("preflight should accept valid EOCD, got: %v", err)
	}
}

func buildCentralDirectoryHeaders(t *testing.T, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	for i := 0; i < n; i++ {
		name := []byte("f" + itoaPad(i, 6))
		hdr := make([]byte, zipCentralDirectoryHeaderSize)
		binary.LittleEndian.PutUint32(hdr[0:4], zipCentralDirectoryHeaderSignature)
		binary.LittleEndian.PutUint16(hdr[28:30], uint16(len(name)))
		buf.Write(hdr)
		buf.Write(name)
	}
	return buf.Bytes()
}

func TestPreflightZip_ScansActualCentralDirectoryEntryCap(t *testing.T) {
	t.Parallel()

	cd := buildCentralDirectoryHeaders(t, MaxRootFSEntries+1)
	eocd := craftEOCD(1, uint32(len(cd)), 0)
	arch := append(cd, eocd...)
	err := preflightZipDirectory(bytes.NewReader(arch), int64(len(arch)))
	if err == nil {
		t.Fatal("expected error for actual central-directory entry overflow, got nil")
	}
	if !strings.Contains(err.Error(), "MaxRootFSEntries") {
		t.Errorf("error should mention MaxRootFSEntries, got: %v", err)
	}
}

func TestPreflightZip_RejectsUnderreportedCentralDirectorySize(t *testing.T) {
	t.Parallel()

	cd := buildCentralDirectoryHeaders(t, 3)
	// EOCD under-reports the central directory as empty even though valid
	// headers sit immediately before it. archive/zip would start at cdOffset
	// and parse those headers before our post-NewReader len(zr.File) cap; the
	// preflight must therefore reject unless cdOffset+cdSize lands exactly at
	// the real EOCD.
	eocd := craftEOCD(0, 0, 0)
	arch := append(cd, eocd...)
	err := preflightZipDirectory(bytes.NewReader(arch), int64(len(arch)))
	if err == nil {
		t.Fatal("expected error for under-reported central directory size, got nil")
	}
	if !strings.Contains(err.Error(), "does not end at EOCD") {
		t.Errorf("error should mention EOCD boundary, got: %v", err)
	}
}

func TestPreflightZip_RejectsCentralDirectoryEntryCrossingDeclaredSize(t *testing.T) {
	t.Parallel()

	hdr := make([]byte, zipCentralDirectoryHeaderSize)
	binary.LittleEndian.PutUint32(hdr[0:4], zipCentralDirectoryHeaderSignature)
	binary.LittleEndian.PutUint16(hdr[28:30], 10) // entryLen > cdSize below
	eocd := craftEOCD(1, uint32(len(hdr)), 0)
	arch := append(hdr, eocd...)
	err := preflightZipDirectory(bytes.NewReader(arch), int64(len(arch)))
	if err == nil {
		t.Fatal("expected error for central-directory entry crossing cdSize, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds remaining") {
		t.Errorf("error should mention remaining central-directory bytes, got: %v", err)
	}
}

func TestPreflightZip_AcceptsValidCentralDirectoryScan(t *testing.T) {
	t.Parallel()

	cd := buildCentralDirectoryHeaders(t, 3)
	eocd := craftEOCD(3, uint32(len(cd)), 0)
	arch := append(cd, eocd...)
	if err := preflightZipDirectory(bytes.NewReader(arch), int64(len(arch))); err != nil {
		t.Fatalf("preflight should accept valid central directory, got: %v", err)
	}
}

// craftEOCDWithComment builds a 22-byte EOCD record followed by a comment of
// the given bytes, with the EOCD comment-length field set to len(comment).
// The other EOCD fields are set from the arguments. This is used to craft
// archives whose EOCD comment carries a forged PK\x05\x06 signature.
func craftEOCDWithComment(totalEntries uint16, cdSize uint32, cdOffset uint32, comment []byte) []byte {
	out := make([]byte, 0, 22+len(comment))
	eocd := make([]byte, 22)
	eocd[0] = 0x50
	eocd[1] = 0x4b
	eocd[2] = 0x05
	eocd[3] = 0x06
	eocd[8] = byte(totalEntries)
	eocd[9] = byte(totalEntries >> 8)
	eocd[10] = byte(totalEntries)
	eocd[11] = byte(totalEntries >> 8)
	eocd[12] = byte(cdSize)
	eocd[13] = byte(cdSize >> 8)
	eocd[14] = byte(cdSize >> 16)
	eocd[15] = byte(cdSize >> 24)
	eocd[16] = byte(cdOffset)
	eocd[17] = byte(cdOffset >> 8)
	eocd[18] = byte(cdOffset >> 16)
	eocd[19] = byte(cdOffset >> 24)
	cl := uint16(len(comment))
	eocd[20] = byte(cl)
	eocd[21] = byte(cl >> 8)
	out = append(out, eocd...)
	out = append(out, comment...)
	return out
}

// TestPreflightZip_ForgedEOCDInCommentRejected proves preflightZipDirectory
// does NOT honor a forged PK\x05\x06 signature embedded inside the real
// EOCD's comment. The real (earlier) EOCD here advertises a central directory
// larger than MaxRootFSZipCentralDirectoryBytes, which preflight must reject.
// The real EOCD's comment contains a forged EOCD signature whose own
// comment-length field (read at forged-offset 20) does NOT land at EOF, so a
// stdlib-compatible validity check rejects the forged candidate.
//
// Before the fix preflight scanned backwards and accepted the FIRST
// PK\x05\x06 signature it found without validating the comment length, so it
// picked the forged signature inside the comment. The forged EOCD's fields
// (taken from the comment bytes) advertised a tiny safe central directory and
// preflight passed - while archive/zip (which DOES validate comment length)
// skipped the forged signature and parsed the real earlier EOCD, letting an
// attacker smuggle an oversized central directory past preflight.
//
// The forged EOCD in the comment is crafted with totalEntries=0, cdSize=0,
// cdOffset=0 (safe values that would pass the caps) and a commentLen of 5,
// which makes forgedIdx+22+commentLen = 22+22+5 = 49 != len(tail)=44, so the
// stdlib-compatible == EOF check rejects it. preflight then scans earlier and
// finds the real EOCD whose cdSize exceeds the cap, and rejects.
func TestPreflightZip_ForgedEOCDInCommentRejected(t *testing.T) {
	t.Parallel()

	// Build a forged 22-byte EOCD record living inside the real EOCD's
	// comment. Its fields are "safe" (0 entries, 0-size CD) but its
	// commentLen field is set to 5, which does not align with EOF.
	forged := make([]byte, 22)
	forged[0] = 0x50 // PK\x05\x06 little-endian
	forged[1] = 0x4b
	forged[2] = 0x05
	forged[3] = 0x06
	// totalEntries = 0, cdSize = 0, cdOffset = 0 (already zero)
	// commentLen = 5 (forged[20], forged[21]); 5 != len(tail)-forgedIdx-22.
	forged[20] = 5
	forged[21] = 0

	// Real EOCD advertises an oversized central directory. Its comment is
	// the forged EOCD record. preflight must reject on the real EOCD's
	// cdSize, not accept the forged one.
	tooBig := uint32(MaxRootFSZipCentralDirectoryBytes + 1)
	arch := craftEOCDWithComment(0, tooBig, 0, forged)

	err := preflightZipDirectory(bytes.NewReader(arch), int64(len(arch)))
	if err == nil {
		t.Fatal("expected error for forged EOCD in comment, got nil (preflight accepted the forged signature)")
	}
	if !strings.Contains(err.Error(), "MaxRootFSZipCentralDirectoryBytes") {
		t.Errorf("error should mention MaxRootFSZipCentralDirectoryBytes (proving the real EOCD was selected), got: %v", err)
	}
}

// TestPreflightZip_ForgedEOCDInCommentWithTrailingJunkRejected is a stronger
// variant: the forged signature inside the comment is followed by enough
// trailing bytes that the forged comment-length field points somewhere INSIDE
// the file (not past EOF), yet still does not land exactly at EOF. preflight
// must skip the forged candidate and find the real EOCD. Here the real EOCD
// advertises too many entries.
//
// Layout: [real EOCD (22B)] [forged EOCD (22B)] [junk (4B)] = 48 bytes.
// forgedIdx=22. forged commentLen=0 -> 22+22+0=44 != 48, so the == EOF check
// fails (the forged candidate's comment does not reach EOF). preflight skips
// it, scans earlier, finds the real EOCD whose totalEntries exceeds the cap,
// and rejects. The 4 trailing junk bytes prove the check is not fooled by a
// forged commentLen that points to a valid in-file position.
func TestPreflightZip_ForgedEOCDInCommentWithTrailingJunkRejected(t *testing.T) {
	t.Parallel()

	// Forged 22-byte EOCD with commentLen=0, safe fields (0 entries, 0 CD).
	forged := make([]byte, 22)
	forged[0] = 0x50
	forged[1] = 0x4b
	forged[2] = 0x05
	forged[3] = 0x06
	// totalEntries=0, cdSize=0, cdOffset=0, commentLen=0 (all zero).

	// Trailing junk after the forged EOCD inside the real EOCD's comment.
	junk := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	comment := append(forged, junk...)

	// Real EOCD advertises too many entries.
	tooMany := uint16(MaxRootFSEntries + 1)
	arch := craftEOCDWithComment(tooMany, 0, 0, comment)

	err := preflightZipDirectory(bytes.NewReader(arch), int64(len(arch)))
	if err == nil {
		t.Fatal("expected error for forged EOCD with trailing junk, got nil (preflight accepted the forged signature)")
	}
	if !strings.Contains(err.Error(), "MaxRootFSEntries") {
		t.Errorf("error should mention MaxRootFSEntries (proving the real EOCD was selected), got: %v", err)
	}
}

// TestPreflightZip_ValidEOCDWithCommentAccepted proves the comment-length
// validation does not regress ordinary archives that carry a legitimate EOCD
// comment. The EOCD has a non-empty comment whose length lands exactly at EOF;
// preflight must accept it.
func TestPreflightZip_ValidEOCDWithCommentAccepted(t *testing.T) {
	t.Parallel()

	comment := []byte("this is a legitimate archive comment")
	cd := buildCentralDirectoryHeaders(t, 3)
	arch := append(cd, craftEOCDWithComment(3, uint32(len(cd)), 0, comment)...)
	if err := preflightZipDirectory(bytes.NewReader(arch), int64(len(arch))); err != nil {
		t.Fatalf("preflight should accept valid EOCD with comment, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Directory streaming cap: a directory with more than MaxRootFSEntries files
// must be rejected (fail closed) without reading the entire directory into
// memory.
// ---------------------------------------------------------------------------

// TestLoadRootFS_DirectoryRejectsTooManyEntries proves the streaming directory
// loader fails closed when the entry count exceeds MaxRootFSEntries. The
// fixture creates MaxRootFSEntries+1 small files in a single directory; the
// loader streams them in batches and rejects as soon as the cap is exceeded.
//
// This test is intentionally NOT parallel: it creates many filesystem entries
// (which is I/O-heavy on Windows) and we want to avoid concurrent contention.
func TestLoadRootFS_DirectoryRejectsTooManyEntries(t *testing.T) {
	root := t.TempDir()
	// Create MaxRootFSEntries+1 small files in the root directory.
	for i := 0; i <= MaxRootFSEntries; i++ {
		name := "f" + itoaPad(i, 6)
		full := filepath.Join(root, name)
		if err := os.WriteFile(full, []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	cfg := &fsconf.FakeshellConfig{RootFS: root}
	_, err := LoadRootFS(cfg)
	if err == nil {
		t.Fatal("expected error for too many directory entries, got nil")
	}
	if !strings.Contains(err.Error(), "MaxRootFSEntries") {
		t.Errorf("error should mention MaxRootFSEntries, got: %v", err)
	}
}

// TestLoadRootFS_DirectoryStreamingNested verifies the streaming walk still
// materializes nested directory trees correctly (the stack-based traversal
// visits subdirectories after their parent's batch loop completes).
func TestLoadRootFS_DirectoryStreamingNested(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	// Build a small nested tree:
	//   a/b/c/file1
	//   a/b/file2
	//   a/file3
	//   file4
	trees := []string{
		"a/b/c",
	}
	for _, p := range trees {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(full, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", p, err)
		}
	}
	files := []string{
		"a/b/c/file1",
		"a/b/file2",
		"a/file3",
		"file4",
	}
	for _, p := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.WriteFile(full, []byte("content-not-copied"), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	cfg := &fsconf.FakeshellConfig{RootFS: root}
	f, err := LoadRootFS(cfg)
	if err != nil {
		t.Fatalf("LoadRootFS(dir) error = %v", err)
	}

	for _, p := range []string{"/a", "/a/b", "/a/b/c"} {
		ok, err := afero.IsDir(f, p)
		if err != nil {
			t.Fatalf("IsDir(%s) error = %v", p, err)
		}
		if !ok {
			t.Errorf("expected directory %s", p)
		}
	}
	for _, p := range []string{"/a/b/c/file1", "/a/b/file2", "/a/file3", "/file4"} {
		info, err := f.Stat(p)
		if err != nil {
			t.Fatalf("Stat(%s) error = %v", p, err)
		}
		if info.IsDir() {
			t.Errorf("%s is a directory, want regular file", p)
			continue
		}
		if info.Size() != 0 {
			t.Errorf("%s size = %d, want 0 (placeholder must not copy content)", p, info.Size())
		}
	}
}

// TestLoadRootFS_DirectoryStreamingBatchBoundary verifies the streaming walk
// handles a directory whose entry count is an exact multiple of the batch
// size (exercises the EOF-vs-empty-batch loop termination logic).
func TestLoadRootFS_DirectoryStreamingBatchBoundary(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	// Create exactly rootFSDirReadBatchSize files so the first ReadDir returns
	// a full batch and the second returns EOF/empty.
	for i := 0; i < rootFSDirReadBatchSize; i++ {
		name := "f" + itoaPad(i, 6)
		full := filepath.Join(root, name)
		if err := os.WriteFile(full, []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	cfg := &fsconf.FakeshellConfig{RootFS: root}
	f, err := LoadRootFS(cfg)
	if err != nil {
		t.Fatalf("LoadRootFS(dir) error = %v", err)
	}
	// Verify the last file in the batch was materialized.
	last := "/f" + itoaPad(rootFSDirReadBatchSize-1, 6)
	if ok, err := afero.Exists(f, last); err != nil || !ok {
		t.Errorf("expected file %s, ok=%v err=%v", last, ok, err)
	}
}
