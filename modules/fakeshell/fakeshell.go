//go:build !no_fakeshell && !plan9
// +build !no_fakeshell,!plan9

package fakeshell

import (
	"bytes"
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
	promt := fmt.Appendf(nil, "%s> ", s.C.EnvConfig.User)

	buf := make([]byte, 512)
	pos, end := 0, 0

	done := true
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		for pos < end && (buf[pos] == '\n' || buf[pos] == ';') {
			pos++
		}
		if pos > 0 {
			copy(buf, buf[pos:end])
			pos, end = 0, end-pos
		}
		bufferedCommand := bytes.ContainsAny(buf[pos:end], "\n;")

		if done && !bufferedCommand {
			_, err := s.Write(promt)
			if err != nil {
				return err
			}
			done = false
		}

		var err error
		if !bufferedCommand {
			if end >= len(buf) {
				return errors.New("buffer pos out of range")
			}
			var n int
			n, err = s.Read(buf[end:])
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			if n == 0 && errors.Is(err, io.EOF) {
				return nil
			}

			end += n
			if end > len(buf) {
				return errors.New("buffer pos out of range")
			}
			if !bytes.ContainsAny(buf[pos:end], "\n;") && !errors.Is(err, io.EOF) {
				continue
			}
		}

		cmd, newPosRelative, err := parser.ParseCmd(buf[pos:end], 0)
		if err != nil {
			logger.Error("failed to parse command", zap.Error(err))
			pos, end = discardBufferedCommand(buf, pos, end)
			done = true
			continue
		}

		if newPosRelative > 0 {
			pos += newPosRelative
			if pos < end && (buf[pos] == '\n' || buf[pos] == ';') {
				pos++
			}
			copy(buf, buf[pos:end])
			pos, end = 0, end-pos
		}
		if cmd == nil || cmd.Name == "" {
			done = true
			continue
		}
		if msg, err := runCmd(s.runner, cmd); err != nil && msg != "" {
			_, _ = s.Write([]byte(msg + "\n"))
		}
		done = true
	}
}

func discardBufferedCommand(buf []byte, pos, end int) (int, int) {
	if pos >= end {
		return 0, 0
	}
	if rel := bytes.IndexAny(buf[pos:end], "\n;"); rel >= 0 {
		pos += rel + 1
	} else {
		pos = end
	}
	copy(buf, buf[pos:end])
	return 0, end - pos
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
