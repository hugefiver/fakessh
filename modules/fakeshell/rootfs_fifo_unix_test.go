//go:build !no_fakeshell && !plan9 && unix

package fakeshell

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/afero"
)

const rootfsFIFOChildEnv = "FAKESSH_ROOTFS_FIFO_CHILD"
const rootfsFIFOFixtureEnv = "FAKESSH_ROOTFS_FIFO_FIXTURE"

func TestOpenRootFSCheckedFIFOReplacementDoesNotBlock(t *testing.T) {
	testRootFSFIFOReplacement(t, false)
}

func TestLoadRootFSFromDirFIFOReplacementDoesNotBlock(t *testing.T) {
	testRootFSFIFOReplacement(t, true)
}

func testRootFSFIFOReplacement(t *testing.T, directory bool) {
	t.Helper()
	if os.Getenv(rootfsFIFOChildEnv) == "1" {
		rootfsRunFIFOOpenChild(t, directory)
		return
	}

	fixtureDir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+t.Name()+"$")
	cmd.Env = append(os.Environ(), rootfsFIFOChildEnv+"=1", rootfsFIFOFixtureEnv+"="+fixtureDir)
	output, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("rootfs open blocked on a FIFO replacement; child output: %s", output)
	}
	if err != nil {
		t.Fatalf("FIFO regression child failed: %v\n%s", err, output)
	}
}

func rootfsRunFIFOOpenChild(t *testing.T, directory bool) {
	t.Helper()
	dir := os.Getenv(rootfsFIFOFixtureEnv)
	if dir == "" {
		t.Fatal("missing FIFO fixture directory")
	}
	target := filepath.Join(dir, "target")
	if directory {
		if err := os.Mkdir(target, 0o755); err != nil {
			t.Fatalf("create original directory: %v", err)
		}
	} else if err := os.WriteFile(target, nil, 0o644); err != nil {
		t.Fatalf("create original regular file: %v", err)
	}
	expected, err := lstatRootFS(target)
	if err != nil {
		t.Fatalf("lstat original regular file: %v", err)
	}
	if err := os.Rename(target, filepath.Join(dir, "original")); err != nil {
		t.Fatalf("rename original regular file: %v", err)
	}
	if err := syscall.Mkfifo(target, 0o600); err != nil {
		t.Fatalf("mkfifo replacement: %v", err)
	}

	if directory {
		err = loadRootFSFromDir(afero.NewMemMapFs(), target, expected)
	} else {
		var f *os.File
		f, err = openRootFSChecked(target, expected)
		if f != nil {
			_ = f.Close()
		}
	}
	if err == nil {
		t.Fatal("rootfs accepted a FIFO replacement")
	}
}
