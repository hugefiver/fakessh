//go:build !no_fakeshell && !plan9

package fakeshell

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/afero"
)

func TestPreflightZipDirectoryMatchesArchiveZipEOCDSelection(t *testing.T) {
	t.Parallel()

	cd := buildCentralDirectoryHeaders(t, 2)
	laterEOCD := craftEOCD(2, uint32(len(cd)), 0)
	laterEOCD[4] = 1 // archive/zip accepts this, but rootfs rejects disk spanning.
	comment := append(laterEOCD, 0xaa)
	archive := append(cd, craftEOCDWithComment(0, 0, uint32(len(cd)), comment)...)

	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatalf("zip.NewReader rejected regression fixture: %v", err)
	}
	if len(zr.File) != 2 {
		t.Fatalf("zip.NewReader selected %d entries, want later EOCD with 2 entries", len(zr.File))
	}

	err = preflightZipDirectory(bytes.NewReader(archive), int64(len(archive)))
	if err == nil || !strings.Contains(err.Error(), "ambiguous EOCD") {
		t.Fatalf("preflight error = %v, want rejection of trailing data after the EOCD selected by archive/zip", err)
	}
}

type rootfsMkdirHookFS struct {
	afero.Fs
	hookPath string
	hook     func() error
	hookErr  error
	run      bool
}

func (fs *rootfsMkdirHookFS) MkdirAll(name string, perm os.FileMode) error {
	if err := fs.Fs.MkdirAll(name, perm); err != nil {
		return err
	}
	if !fs.run && name == fs.hookPath {
		fs.run = true
		fs.hookErr = fs.hook()
	}
	return nil
}

func TestLoadRootFSFromDirDoesNotResolveChangedAncestorOutsideRoot(t *testing.T) {
	t.Parallel()

	temp := t.TempDir()
	root := filepath.Join(temp, "root")
	ancestor := filepath.Join(root, "ancestor")
	external := filepath.Join(temp, "external")
	const entryName = "external-name"
	if err := os.MkdirAll(ancestor, 0o755); err != nil {
		t.Fatalf("mkdir root fixture: %v", err)
	}
	if err := os.MkdirAll(external, 0o755); err != nil {
		t.Fatalf("mkdir external fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ancestor, entryName), nil, 0o644); err != nil {
		t.Fatalf("write in-root fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(external, entryName), nil, 0o644); err != nil {
		t.Fatalf("write external fixture: %v", err)
	}

	expected, err := lstatRootFS(root)
	if err != nil {
		t.Fatalf("lstat root: %v", err)
	}
	out := &rootfsMkdirHookFS{
		Fs:       afero.NewMemMapFs(),
		hookPath: "/ancestor",
		hook: func() error {
			if err := os.Rename(ancestor, filepath.Join(root, "original-ancestor")); err != nil {
				return err
			}
			return os.Symlink(external, ancestor)
		},
	}
	err = loadRootFSFromDir(out, root, expected)
	if out.hookErr != nil {
		t.Skipf("filesystem cannot replace an open directory with a symlink: %v", out.hookErr)
	}
	if !out.run {
		t.Fatal("directory replacement hook did not run")
	}
	if err == nil {
		t.Fatal("loadRootFSFromDir accepted a child resolved through an outside-root ancestor")
	}
	if exists, existsErr := afero.Exists(out, "/ancestor/"+entryName); existsErr != nil || exists {
		t.Fatalf("outside-root name was materialized: exists=%v err=%v", exists, existsErr)
	}
}
