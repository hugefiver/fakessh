//go:build !no_gitserver && (freebsd || openbsd || darwin)

package gitserver

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// NOTE_EXIT observes exit without consuming wait status. Unlike waitid, kqueue
// is available on all three BSD targets. An already-exiting child may produce
// ESRCH at registration (notably OpenBSD and Darwin); it is safe to treat that
// as exit only because this is our own, exclusively owned, unreaped child.
// See filt_procattach in each OS's sys/kern/kern_event.c (bsd/kern on Darwin):
// OpenBSD rejects PS_EXITING, FreeBSD activates NOTE_EXIT for zombies, and
// Darwin's proc_find/proc_refdrain orders attachment before exit notification
// or returns ESRCH. None of these operations reap the child.
func waitLocalProcessExit(pid int) error {
	syscall.ForkLock.RLock()
	kq, err := unix.Kqueue()
	if err == nil {
		unix.CloseOnExec(kq)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return err
	}
	defer unix.Close(kq)

	var change unix.Kevent_t
	unix.SetKevent(&change, pid, unix.EVFILT_PROC, unix.EV_ADD|unix.EV_ONESHOT)
	change.Fflags = unix.NOTE_EXIT
	for {
		_, err = unix.Kevent(kq, []unix.Kevent_t{change}, nil, nil)
		if err != unix.EINTR {
			break
		}
	}
	if err == unix.ESRCH {
		return nil
	}
	if err != nil {
		return err
	}
	var events [1]unix.Kevent_t
	for {
		n, err := unix.Kevent(kq, nil, events[:], nil)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		if events[0].Flags&unix.EV_ERROR != 0 {
			return unix.Errno(events[0].Data)
		}
		if events[0].Fflags&unix.NOTE_EXIT != 0 {
			return nil
		}
	}
}
