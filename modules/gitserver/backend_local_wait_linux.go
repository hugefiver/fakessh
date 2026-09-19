//go:build !no_gitserver && linux

package gitserver

import "golang.org/x/sys/unix"

// Like os.Process.blockUntilWaitable, but deliberately separate from Wait:
// WNOWAIT leaves the zombie (and its PID) reserved until our final Cmd.Wait.
func waitLocalProcessExit(pid int) error {
	var info unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if err != unix.EINTR {
			return err
		}
	}
}
