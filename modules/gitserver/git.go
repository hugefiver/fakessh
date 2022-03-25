package gitserver

import (
	"context"
)

func ServeGitShell(config *Config, ctx context.Context) error {
	return nil
}

// func foo() {
// 	cmd := exec.Command("ls")
// 	// cmd.SysProcAttr = &syscall.SysProcAttr{
// 	// 	HideWindow:                 false,
// 	// 	CmdLine:                    "",
// 	// 	CreationFlags:              0,
// 	// 	Token:                      0,
// 	// 	ProcessAttributes:          &syscall.SecurityAttributes{},
// 	// 	ThreadAttributes:           &syscall.SecurityAttributes{},
// 	// 	NoInheritHandles:           false,
// 	// 	AdditionalInheritedHandles: []syscall.Handle{},
// 	// 	ParentProcess:              0,
// 	// }

// 	// linux
// 	//
// 	// cmd.SysProcAttr = &syscall.SysProcAttr{
// 	// 	Chroot: "",
// 	// 	Credential: &syscall.Credential{
// 	// 		Uid:         0,
// 	// 		Gid:         0,
// 	// 		Groups:      []uint32{},
// 	// 		NoSetGroups: false,
// 	// 	},
// 	// 	Ptrace:                     false,
// 	// 	Setsid:                     false,
// 	// 	Setpgid:                    false,
// 	// 	Setctty:                    false,
// 	// 	Noctty:                     false,
// 	// 	Ctty:                       0,
// 	// 	Foreground:                 false,
// 	// 	Pgid:                       0,
// 	// 	Pdeathsig:                  0,
// 	// 	Cloneflags:                 0,
// 	// 	Unshareflags:               0,
// 	// 	UidMappings:                []syscall.SysProcIDMap{},
// 	// 	GidMappings:                []syscall.SysProcIDMap{},
// 	// 	GidMappingsEnableSetgroups: false,
// 	// 	AmbientCaps:                []uintptr{},
// 	// }

// 	// freebsd
// 	//
// 	cmd.SysProcAttr = &syscall.SysProcAttr{
// 		Chroot:     "",
// 		Credential: &syscall.Credential{},
// 		Ptrace:     false,
// 		Setsid:     false,
// 		Setpgid:    false,
// 		Setctty:    false,
// 		Noctty:     false,
// 		Ctty:       0,
// 		Foreground: false,
// 		Pgid:       0,
// 	}

// 	os.Executable()

// }
