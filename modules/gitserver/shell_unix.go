//go:build linux || freebsd || openbsd || darwin
// +build linux freebsd openbsd darwin

package gitserver

import (
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

func CurrentUser() (*user.User, error) {
	return user.Current()
}

func LookupUser(username string) (*user.User, error) {
	return user.Lookup(username)
}

func GetUid(username string, current bool) (uid uint32, gid uint32, err error) {
	var user *user.User
	if current {
		user, err = CurrentUser()
	} else {
		user, err = LookupUser(username)
	}
	if err != nil {
		return
	}

	u, err := strconv.ParseUint(user.Uid, 10, 32)
	if err != nil {
		return
	}
	g, err := strconv.ParseUint(user.Gid, 10, 32)
	if err != nil {
		return
	}

	uid = uint32(u)
	gid = uint32(g)
	return
}

func ExecWithUid(uid, gid uint32, name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uid,
			Gid: gid,
		},
	}
	return cmd
}
