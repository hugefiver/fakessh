//go:build !no_fakeshell && !plan9
// +build !no_fakeshell,!plan9

package fakeshell

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

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

	// loadErr stores any error returned by LoadRootFS during NewShell. If
	// non-nil, RunLoop returns it immediately before printing a prompt or
	// accepting any command, so a failed rootfs load never produces a shell
	// backed by an empty or partial filesystem.
	loadErr error

	// logInitErr stores any error returned by NewSessionLogger during
	// NewShell. If non-nil, RunLoop records a session_end event (best-effort)
	// and returns it before processing commands, so a failed logger init never
	// gives the attacker an un-logged session.
	logInitErr error

	// logger is the per-session bounded event logger. It is nil only when
	// loadErr or logInitErr is non-nil (RunLoop nil-checks before emitting).
	logger cmds.EventLogger

	ssh.Channel
}

func NewShell(c *conf.FakeshellConfig, ch ssh.Channel) *Shell {
	runner := cmds.NewCommandRunner(c)
	runner.Stdin = ch
	runner.Stdout = ch
	runner.Stderr = ch

	s := &Shell{
		C:       c,
		runner:  runner,
		Channel: ch,
	}

	// Load the fake rootfs now. If this fails we record the error and refuse
	// to run commands; RunLoop checks loadErr before printing the first
	// prompt. There is no empty-fs fallback: a missing/invalid rootfs must
	// abort the shell rather than silently give the attacker an empty FS.
	fs, err := LoadRootFS(c)
	if err != nil {
		s.loadErr = err
		return s
	}
	runner.SetRootFS(fs)

	// Create the per-session bounded logger now. If logging is enabled and
	// initialization fails (e.g. cannot create the session dir), record the
	// error and abort before any command runs, mirroring the rootfs posture:
	// an enabled-but-broken logger must never silently give an un-logged
	// session. A disabled logger returns a no-op with nil error.
	lgr, lerr := NewSessionLogger(c.LogConfig)
	if lerr != nil {
		s.logInitErr = lerr
		return s
	}
	s.logger = lgr
	runner.Logger = lgr

	return s
}

func (s Shell) RunLoop(ctx context.Context) error {
	// Abort before any prompt or command if the rootfs failed to load. There
	// is intentionally no empty-fs fallback: a failed load must close the
	// session so an attacker cannot obtain a shell with a missing/partial FS.
	if s.loadErr != nil {
		s.logSessionEnd("rootfs_load_error")
		return s.loadErr
	}

	// Abort before any prompt or command if the logger failed to initialize.
	// An enabled-but-broken logger must never silently give an un-logged
	// session; we do not have a usable logger here, so session_end is skipped
	// (there is nothing to write to).
	if s.logInitErr != nil {
		return s.logInitErr
	}

	s.logSessionStart()
	defer s.logSessionEnd("session_end")

	promt := fmt.Appendf(nil, "%s> ", s.C.EnvConfig.User)
	buf := make([]byte, 0, MaxInputLineBytes+1)
	done := true
	eof := false
	commandsThisCycle := 0

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if commandsThisCycle < MaxCommandsPerReadCycle {
			processed, err := s.processBufferedInput(&buf, eof, &done, &commandsThisCycle)
			if err != nil {
				if errors.Is(err, cmds.ErrExit) {
					return nil
				}
				return err
			}
			if processed {
				continue
			}
		}

		if commandsThisCycle >= MaxCommandsPerReadCycle {
			commandsThisCycle = 0
			continue
		}

		if eof {
			return nil
		}

		_, hasBufferedCommand := findCommandSeparator(buf)
		if done && !hasBufferedCommand {
			_, err := s.Write(promt)
			if err != nil {
				return err
			}
			done = false
		}

		atEOF, tooLong, err := s.readInput(&buf)
		commandsThisCycle = 0
		if err != nil {
			return err
		}
		if atEOF {
			eof = true
		}
		if tooLong {
			logger.Warn("terminating overlong fakeshell input", zap.Int("buffered_bytes", len(buf)), zap.Int("max_input_line_bytes", MaxInputLineBytes))
			return errInputLineTooLong
		}
	}
}

func (s Shell) processBufferedInput(buf *[]byte, eof bool, done *bool, commandsThisCycle *int) (bool, error) {
	if len(*buf) == 0 {
		return false, nil
	}
	sep, ok := findCommandSeparator(*buf)
	if !ok && !eof {
		return false, nil
	}

	segmentEnd := len(*buf)
	consumeEnd := len(*buf)
	if ok {
		segmentEnd = sep + 1
		consumeEnd = sep + 1
	}
	segment := (*buf)[:segmentEnd]

	cmd, _, err := parser.ParseCmd(segment, 0)
	if err != nil {
		logger.Error("failed to parse command", zap.Error(err))
		return false, fmt.Errorf("invalid input: %s", parseInputErrorReason(err))
	}

	if err := validateParsedCommand(cmd); err != nil {
		logger.Warn("rejected invalid fakeshell input", zap.String("reason", err.Error()))
		return false, fmt.Errorf("invalid input: %w", err)
	}

	*buf = append((*buf)[:0], (*buf)[consumeEnd:]...)
	*commandsThisCycle = *commandsThisCycle + 1
	if cmd == nil || cmd.Name == "" {
		*done = true
		return true, nil
	}

	msg, runErr := runCmd(s.runner, cmd)
	s.logCommand(cmd, msg, runErr)
	if runErr != nil {
		if errors.Is(runErr, cmds.ErrExit) {
			// exit built-in: clean shutdown, return nil to caller.
			return false, cmds.ErrExit
		}
		if msg != "" {
			_, _ = s.Write([]byte(msg + "\n"))
		}
	}
	*done = true
	return true, nil
}

func (s Shell) readInput(buf *[]byte) (atEOF bool, tooLong bool, err error) {
	remaining := MaxInputLineBytes + 1 - len(*buf)
	if remaining <= 0 {
		return false, true, nil
	}

	chunk := make([]byte, remaining)
	n, readErr := s.Read(chunk)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return false, false, readErr
	}
	if n > 0 {
		*buf = append(*buf, chunk[:n]...)
	}
	atEOF = errors.Is(readErr, io.EOF)
	if len(*buf) > MaxInputLineBytes {
		if sep, ok := findCommandSeparator(*buf); !ok || sep > MaxInputLineBytes {
			return atEOF, true, nil
		}
	}
	return atEOF, false, nil
}

func parseInputErrorReason(err error) string {
	if err == nil {
		return "parse error"
	}
	if err.Error() == "unclosed quote" {
		return "unterminated quote"
	}
	return "parse error"
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
	case "whoami":
		return "", cmds.CmdWhoami(runner, cmd.Args...)
	case "hostname":
		return "", cmds.CmdHostname(runner, cmd.Args...)
	case "echo":
		return "", cmds.CmdEcho(runner, cmd.Args...)
	case "touch":
		return "", cmds.CmdTouch(runner, cmd.Args...)
	case "exit":
		return "", cmds.CmdExit(runner, cmd.Args...)
	case "uname":
		return "", cmds.CmdUname(runner, cmd.Args...)
	case "env":
		return "", cmds.CmdEnv(runner, cmd.Args...)
	case "id":
		return "", cmds.CmdId(runner, cmd.Args...)
	case "groups":
		return "", cmds.CmdGroups(runner, cmd.Args...)
	case "who":
		return "", cmds.CmdWho(runner, cmd.Args...)
	case "w":
		return "", cmds.CmdW(runner, cmd.Args...)
	case "last":
		return "", cmds.CmdLast(runner, cmd.Args...)
	case "uptime":
		return "", cmds.CmdUptime(runner, cmd.Args...)
	case "date":
		return "", cmds.CmdDate(runner, cmd.Args...)
	case "df":
		return "", cmds.CmdDf(runner, cmd.Args...)
	case "free":
		return "", cmds.CmdFree(runner, cmd.Args...)
	case "ps":
		return "", cmds.CmdPs(runner, cmd.Args...)
	case "netstat":
		return "", cmds.CmdNetstat(runner, cmd.Args...)
	case "ss":
		return "", cmds.CmdSs(runner, cmd.Args...)
	case "ip":
		return "", cmds.CmdIp(runner, cmd.Args...)
	case "ifconfig":
		return "", cmds.CmdIfconfig(runner, cmd.Args...)
	case "which":
		return "", cmds.CmdWhich(runner, cmd.Args...)
	case "stat":
		return "", cmds.CmdStat(runner, cmd.Args...)
	case "wc":
		return "", cmds.CmdWc(runner, cmd.Args...)
	case "head":
		return "", cmds.CmdHead(runner, cmd.Args...)
	case "tail":
		return "", cmds.CmdTail(runner, cmd.Args...)
	case "cat":
		return "", cmds.CmdCat(runner, cmd.Args...)
	case "history":
		return "", cmds.CmdHistory(runner, cmd.Args...)
	case "clear":
		return "", cmds.CmdClear(runner, cmd.Args...)
	default:
		if PathPatt.MatchString(cmd.Name) {
			return fmt.Sprintf("permission denied: %s", cmd.Name), errors.New("failed to execute relastfile")
		}
		return fmt.Sprintf("unknown command: %s", cmd.Name), errors.New("unknown command")
	}
}

// ---------------------------------------------------------------------------
// Session event logging helpers
// ---------------------------------------------------------------------------

// logSessionStart emits a session_start event. It is a no-op when no logger is
// attached (e.g. disabled logging). Logger errors are swallowed so logging
// never affects shell behavior.
func (s Shell) logSessionStart() {
	if s.logger == nil {
		return
	}
	s.logger.Log(cmds.Event{
		Time:    time.Now().UTC(),
		Type:    "session_start",
		CWD:     s.cwd(),
		Command: "",
		Args:    nil,
		Error:   "",
	})
}

// logSessionEnd emits a session_end event with the given reason. It is a
// no-op when no logger is attached. It also closes the logger so the file is
// flushed; Close is idempotent. Best-effort: errors are swallowed.
func (s Shell) logSessionEnd(reason string) {
	if s.logger == nil {
		return
	}
	s.logger.Log(cmds.Event{
		Time:    time.Now().UTC(),
		Type:    "session_end",
		CWD:     s.cwd(),
		Command: "",
		Args:    nil,
		Error:   reason,
	})
	// Close the logger to flush any buffered (gzip) writer. Ignoring the
	// error: a close failure must not change the shell's return value.
	_ = s.logger.Close()
}

// logCommand emits a single command event for a parsed command, including the
// CWD, command name, args, any error message/error, and a deep copy of the
// per-session dynamic metadata (nil if the store is empty). It is a no-op
// when no logger is attached.
//
// The command field uses the parsed command NAME (not the raw channel bytes)
// and the args are the parsed arg list, so the log never contains the raw
// attacker input buffer. All fields are bounded by the logger.
func (s Shell) logCommand(cmd *parser.Command, errmsg string, runErr error) {
	if s.logger == nil || cmd == nil {
		return
	}

	errStr := errmsg
	if runErr != nil && !errors.Is(runErr, cmds.ErrExit) {
		// Include the error value too for non-exit errors so the log captures
		// the underlying reason (e.g. "unknown command"). ErrExit is a clean
		// shutdown and is not an error to record.
		if errStr == "" {
			errStr = runErr.Error()
		} else {
			errStr = errStr + ": " + runErr.Error()
		}
	}

	var meta []cmds.DynamicEntry
	if s.runner != nil && s.runner.Dynamic != nil {
		// Entries() returns deep copies; the logger re-bounds the preview
		// defensively. This is the same-session dynamic store only, never
		// cross-session.
		meta = s.runner.Dynamic.Entries()
	}

	s.logger.Log(cmds.Event{
		Time:     time.Now().UTC(),
		Type:     "command",
		CWD:      s.cwd(),
		Command:  cmd.Name,
		Args:     append([]string(nil), cmd.Args...),
		Error:    errStr,
		Metadata: meta,
	})
}

// cwd returns the runner's current working directory (PWD env), or "/" if
// unset. It reads without holding the runner mu because PWD is a string read
// and the worst case is a torn read of an env var that is only mutated by the
// single-threaded RunLoop.
func (s Shell) cwd() string {
	if s.runner == nil {
		return "/"
	}
	cwd := s.runner.GetEnv("PWD")
	if cwd == "" {
		return "/"
	}
	return cwd
}
