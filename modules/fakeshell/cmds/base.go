package cmds

import (
	"bytes"
	"fmt"
	"path"
	"strings"

	"github.com/spf13/afero"
)

type FuncCmd func(runner *CommandRunner, args ...string) error

func (f FuncCmd) Run(runner *CommandRunner, args ...string) error {
	return f(runner, args...)
}

var (
	CmdLs    = FuncCmd(ls)
	CmdPwd   = FuncCmd(pwd)
	CmdCd    = FuncCmd(cd)
	CmdUname = FuncCmd(uname)
	CmdEnv   = FuncCmd(env)
)

func ls(r *CommandRunner, args ...string) error {
	var dir string
	if len(args) == 0 {
		dir = r.GetEnv("PWD")
	} else {
		dir = args[len(args)-1]
		if !strings.HasPrefix(dir, "/") {
			path.Join(r.GetEnv("PWD"), dir)
		}
	}

	exsists, err := afero.Exists(r.RootFS, dir)
	if err != nil {
		return err
	}
	if !exsists {
		r.Stderr.Write([]byte("ls: cannot access '" + dir + "': No such file or directory\n"))
		return nil
	}

	return nil
}

func pwd(r *CommandRunner, args ...string) error {
	_, err := r.Stdout.Write([]byte(r.GetEnv("PWD")))
	return err
}

func cd(r *CommandRunner, args ...string) error {
	return nil
}

func uname(r *CommandRunner, args ...string) error {
	c := r.C
	_, err := fmt.Fprintf(r.Stdout, "%s %s %s © FakeShell 2024", c.OS, c.HostName, c.Kernel)
	return err
}

func env(r *CommandRunner, args ...string) error {
	buf := bytes.NewBuffer(nil)

	envs := r.GetEnvs()
	for i, e := range envs {
		_, err := fmt.Fprintf(buf, "%s=%s", e.Key, e.Value)
		if err != nil {
			return err
		}
		if i < len(envs)-1 {
			buf.WriteByte('\n')
		}
	}
	_, _ = fmt.Fprint(r.Stdout, buf.String())
	return nil
}
