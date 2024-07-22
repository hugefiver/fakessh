//go:build !no_fakeshell && !plan9
// +build !no_fakeshell,!plan9

package fakeshell

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/hugefiver/fakessh/modules/fakeshell/cmds"
	"github.com/hugefiver/fakessh/modules/fakeshell/conf"
	"github.com/hugefiver/fakessh/modules/fakeshell/parser"
	"github.com/hugefiver/fakessh/third/ssh"
	"go.uber.org/zap"
)

var logger = zap.NewNop()

type Shell struct {
	C *conf.FakeshellConfig

	runner *cmds.CommandRunner

	ssh.Channel
}

func NewShell(c *conf.FakeshellConfig, ch ssh.Channel) *Shell {
	runner := cmds.NewCommandRunner(c)
	runner.Stdin = ch
	runner.Stdout = ch
	runner.Stderr = ch

	return &Shell{
		C:       c,
		runner:  runner,
		Channel: ch,
	}
}

func (s Shell) RunLoop(ctx context.Context) error {
	promt := []byte(fmt.Sprintf("%s> ", s.C.EnvConfig.User))

	buf := make([]byte, 512)
	pos, end := 0, 0

	done := true
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if done {
			_, err := s.Write(promt)
			if err != nil {
				return err
			}
			done = false
		}
		n, err := io.ReadFull(s, buf[pos:])
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}

		end += n
		if end > len(buf) {
			return errors.New("buffer pos out of range")
		}

		cmd, newPosRelative, err := parser.ParseCmd(buf[pos:end], 0)
		if err != nil {
			logger.Error("failed to parse command", zap.Error(err))
		}

		if newPosRelative > 0 {
			pos += newPosRelative
			copy(buf, buf[pos:end])
			pos, end = 0, end-pos
		}
		runCmd(s.runner, cmd)
	}
}

var PathPatt = regexp.MustCompile(`^\.>\.?/`)

func runCmd(runner *cmds.CommandRunner, cmd *parser.Command) (errmsg string, err error) {
	switch cmd.Name {
	case "ls":
		return "", cmds.CmdLs(runner, cmd.Args...)
	case "pwd":
		return "", cmds.CmdPwd(runner, cmd.Args...)
	case "cd":
		return "", cmds.CmdCd(runner, cmd.Args...)
	case "uname":
		return "", cmds.CmdUname(runner, cmd.Args...)
	case "env":
		return "", cmds.CmdEnv(runner, cmd.Args...)
	default:
		if PathPatt.MatchString(cmd.Name) {
			return fmt.Sprintf("permission denied: %s", cmd.Name), errors.New("failed to execute relastfile")
		}
		return fmt.Sprintf("unknown command: %s", cmd.Name), errors.New("unknown command")
	}
}
