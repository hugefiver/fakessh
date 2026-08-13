//go:build !no_fakeshell && !plan9 && windows
// +build !no_fakeshell,!plan9,windows

package fakeshell

import (
	"fmt"
	"os"
	"syscall"
)

// lstatRootFS opens the path itself (rather than a reparse-point target) and
// returns FileInfo obtained while that handle is live. Stat on os.NewFile uses
// the handle's volume/file IDs, so os.SameFile later compares a stable object
// identity instead of lazily resolving the original Lstat path after a rename.
func lstatRootFS(path string) (os.FileInfo, error) {
	pathp, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("lstat %q: %w", path, err)
	}
	h, err := syscall.CreateFile(
		pathp,
		0,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_OPEN_REPARSE_POINT|syscall.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("lstat %q: %w", path, err)
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		if closeErr := syscall.CloseHandle(h); closeErr != nil {
			return nil, fmt.Errorf("lstat %q: wrap handle: close: %w", path, closeErr)
		}
		return nil, fmt.Errorf("lstat %q: wrap handle", path)
	}
	info, statErr := f.Stat()
	closeErr := f.Close()
	if statErr != nil {
		if closeErr != nil {
			return nil, fmt.Errorf("lstat %q: stat: %w (close: %v)", path, statErr, closeErr)
		}
		return nil, fmt.Errorf("lstat %q: stat: %w", path, statErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("lstat %q: close: %w", path, closeErr)
	}
	return info, nil
}
