//go:build !no_fakeshell && !plan9 && !windows
// +build !no_fakeshell,!plan9,!windows

package fakeshell

import "os"

// lstatRootFS delegates to os.Lstat on non-Windows platforms, where returned
// FileInfo values carry stable inode identity for os.SameFile.
func lstatRootFS(path string) (os.FileInfo, error) {
	return os.Lstat(path)
}
