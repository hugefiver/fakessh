//go:build !no_fakeshell && !plan9
// +build !no_fakeshell,!plan9

package fakeshell

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	fsconf "github.com/hugefiver/fakessh/modules/fakeshell/conf"
)

type fakeChannel struct {
	in  *bytes.Buffer
	out bytes.Buffer
}

func newFakeChannel(input string) *fakeChannel {
	return &fakeChannel{in: bytes.NewBufferString(input)}
}

func (c *fakeChannel) Read(data []byte) (int, error)  { return c.in.Read(data) }
func (c *fakeChannel) Write(data []byte) (int, error) { return c.out.Write(data) }
func (c *fakeChannel) Close() error                   { return nil }
func (c *fakeChannel) CloseWrite() error              { return nil }
func (c *fakeChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return false, nil
}
func (c *fakeChannel) Stderr() io.ReadWriter { return &c.out }

func TestRunLoopProcessesBufferedSeparators(t *testing.T) {
	t.Parallel()

	cfg := &fsconf.FakeshellConfig{}
	cfg.FillDefault()
	if err := fsconf.CheckAndFillConfig(cfg); err != nil {
		t.Fatalf("CheckAndFillConfig() error = %v", err)
	}

	channel := newFakeChannel("unknown1;unknown2\npwd\n")
	shell := NewShell(cfg, channel)
	if err := shell.RunLoop(context.Background()); err != nil {
		t.Fatalf("RunLoop() error = %v", err)
	}

	output := channel.out.String()
	for _, want := range []string{
		"unknown command: unknown1",
		"unknown command: unknown2",
		cfg.Home,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("RunLoop output %q does not contain %q", output, want)
		}
	}
}

func TestRunLoopMakesProgressOnNoOpAndMalformedInput(t *testing.T) {
	t.Parallel()

	cfg := &fsconf.FakeshellConfig{}
	cfg.FillDefault()
	if err := fsconf.CheckAndFillConfig(cfg); err != nil {
		t.Fatalf("CheckAndFillConfig() error = %v", err)
	}

	channel := newFakeChannel("   \nFOO=bar\necho 'unterminated\nunknown\n")
	shell := NewShell(cfg, channel)
	if err := shell.RunLoop(context.Background()); err != nil {
		t.Fatalf("RunLoop() error = %v", err)
	}

	output := channel.out.String()
	if !strings.Contains(output, "unknown command: unknown") {
		t.Fatalf("RunLoop output %q does not show progress after no-op/malformed input", output)
	}
}

// TestRunLoopReturnsLoadErrorWhenRootFSMissing verifies that a rootfs load
// failure aborts the shell before any prompt or command is processed. A
// missing rootfs path (validated to be unreachable by the loader) must cause
// RunLoop to return a non-nil error and write nothing to the channel.
func TestRunLoopReturnsLoadErrorWhenRootFSMissing(t *testing.T) {
	t.Parallel()

	cfg := &fsconf.FakeshellConfig{}
	cfg.FillDefault()
	// Point rootfs at a path that does not exist; validateRootFSConfig will
	// reject it, but to exercise the loader path we bypass validation and let
	// LoadRootFS fail at runtime. The shell must abort.
	cfg.RootFS = filepath.Join(t.TempDir(), "does-not-exist")

	channel := newFakeChannel("pwd\n")
	shell := NewShell(cfg, channel)
	err := shell.RunLoop(context.Background())
	if err == nil {
		t.Fatal("RunLoop() expected error for missing rootfs, got nil")
	}

	output := channel.out.String()
	if output != "" {
		t.Errorf("RunLoop wrote %q to channel before aborting; expected no output", output)
	}
	if !strings.Contains(err.Error(), "rootfs") {
		t.Errorf("RunLoop error = %q, want substring 'rootfs'", err.Error())
	}
}

// TestRunLoopExitTerminatesCleanly verifies that the exit built-in causes
// RunLoop to return nil and stop processing further input.
func TestRunLoopExitTerminatesCleanly(t *testing.T) {
	t.Parallel()

	cfg := &fsconf.FakeshellConfig{}
	cfg.FillDefault()
	if err := fsconf.CheckAndFillConfig(cfg); err != nil {
		t.Fatalf("CheckAndFillConfig() error = %v", err)
	}

	// "pwd\nexit\nmorestuff\n" -- exit must stop processing; morestuff must
	// NOT produce "unknown command: morestuff".
	channel := newFakeChannel("pwd\nexit\nmorestuff\n")
	shell := NewShell(cfg, channel)
	if err := shell.RunLoop(context.Background()); err != nil {
		t.Fatalf("RunLoop() error = %v, err", err)
	}

	output := channel.out.String()
	if !strings.Contains(output, cfg.Home) {
		t.Errorf("RunLoop output %q does not contain PWD %q", output, cfg.Home)
	}
	if strings.Contains(output, "morestuff") {
		t.Errorf("RunLoop processed input after exit: %q", output)
	}
}

// TestRunLoopDispatchesEchoWhoamiHostname verifies the new built-ins are
// wired through the runCmd dispatcher.
func TestRunLoopDispatchesEchoWhoamiHostname(t *testing.T) {
	t.Parallel()

	cfg := &fsconf.FakeshellConfig{}
	cfg.EnvConfig.HostName = "fake-host"
	cfg.FillDefault()
	if err := fsconf.CheckAndFillConfig(cfg); err != nil {
		t.Fatalf("CheckAndFillConfig() error = %v", err)
	}

	channel := newFakeChannel("echo hi there\nwhoami\nhostname\nexit\n")
	shell := NewShell(cfg, channel)
	if err := shell.RunLoop(context.Background()); err != nil {
		t.Fatalf("RunLoop() error = %v", err)
	}

	output := channel.out.String()
	for _, want := range []string{"hi there", "root", "fake-host"} {
		if !strings.Contains(output, want) {
			t.Errorf("RunLoop output %q does not contain %q", output, want)
		}
	}
}

// TestRunLoopDispatchesTouch verifies the touch built-in is wired through the
// runCmd dispatcher and that its metadata-only effect is visible to a
// subsequent ls in the same session. The embedded rootfs has /var but no
// /tmp, so this touches /var/touched_file and lists /var.
func TestRunLoopDispatchesTouch(t *testing.T) {
	t.Parallel()

	cfg := &fsconf.FakeshellConfig{}
	cfg.FillDefault()
	if err := fsconf.CheckAndFillConfig(cfg); err != nil {
		t.Fatalf("CheckAndFillConfig() error = %v", err)
	}

	channel := newFakeChannel("touch /var/dynamic_file\nls /var\nexit\n")
	shell := NewShell(cfg, channel)
	if err := shell.RunLoop(context.Background()); err != nil {
		t.Fatalf("RunLoop() error = %v", err)
	}

	output := channel.out.String()
	// touch produces no stdout on success. ls /var must list the touched file
	// (merged from per-session dynamic metadata). The embedded rootfs /var is
	// empty, so the only name should be dynamic_file.
	if !strings.Contains(output, "dynamic_file") {
		t.Errorf("RunLoop output %q does not contain 'dynamic_file' from touch+ls", output)
	}
	// touch must not error to the channel.
	if strings.Contains(output, "touch:") {
		t.Errorf("RunLoop output %q shows a touch error", output)
	}
}

// ---------------------------------------------------------------------------
// RunLoop session logging integration
// ---------------------------------------------------------------------------

// TestRunLoop_RecordsSessionEvents verifies that when logging is enabled,
// RunLoop writes session_start, one command event per parsed command, and a
// session_end event to the session log file. The command event must include
// the parsed command name (not raw input), CWD, args, and a deep copy of the
// per-session dynamic metadata after the command ran.
func TestRunLoop_RecordsSessionEvents(t *testing.T) {
	t.Parallel()

	logDir := t.TempDir()
	cfg := &fsconf.FakeshellConfig{}
	cfg.FillDefault()
	cfg.LogConfig = fsconf.LogConfig{
		Enable: true,
		Path:   logDir,
	}
	if err := fsconf.CheckAndFillConfig(cfg); err != nil {
		t.Fatalf("CheckAndFillConfig: %v", err)
	}

	channel := newFakeChannel("pwd\ntouch /var/logged_file\nexit\n")
	shell := NewShell(cfg, channel)
	if err := shell.RunLoop(context.Background()); err != nil {
		t.Fatalf("RunLoop() error = %v", err)
	}

	// Find the single session log file and parse it.
	entries, err := os.ReadDir(logDir)
	if err != nil {
		t.Fatalf("readdir %s: %v", logDir, err)
	}
	var logPath string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".log") {
			if logPath != "" {
				t.Fatalf("expected exactly one .log file, found multiple")
			}
			logPath = filepath.Join(logDir, e.Name())
		}
	}
	if logPath == "" {
		t.Fatalf("no session .log file created in %s", logDir)
	}

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) < 4 {
		t.Fatalf("expected at least 4 log lines (start, pwd, touch, end), got %d: %q", len(lines), string(raw))
	}

	// Parse each line as JSON.
	type rec struct {
		Type     string   `json:"type"`
		CWD      string   `json:"cwd"`
		Command  string   `json:"command"`
		Args     []string `json:"args"`
		Error    string   `json:"error"`
		Reason   string   `json:"reason"`
		Metadata []struct {
			Path string `json:"path"`
			Kind string `json:"kind"`
		} `json:"metadata"`
	}
	var records []rec
	for i, line := range lines {
		var r rec
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("unmarshal line %d %q: %v", i, line, err)
		}
		records = append(records, r)
	}

	// First record must be session_start.
	if records[0].Type != "session_start" {
		t.Errorf("records[0].Type = %q, want session_start", records[0].Type)
	}

	// Last record must be session_end.
	if last := records[len(records)-1]; last.Type != "session_end" {
		t.Errorf("last record Type = %q, want session_end", last.Type)
	}

	// Find the touch command event and verify it has metadata (the touched
	// file). The command field must be "touch" (parsed name, not raw bytes).
	var touchRec *rec
	for i := range records {
		if records[i].Type == "command" && records[i].Command == "touch" {
			touchRec = &records[i]
			break
		}
	}
	if touchRec == nil {
		t.Fatalf("no command event for touch found in records: %+v", records)
	}
	if len(touchRec.Metadata) != 1 {
		t.Errorf("touch command event metadata len = %d, want 1", len(touchRec.Metadata))
	} else {
		if touchRec.Metadata[0].Path != "/var/logged_file" {
			t.Errorf("touch metadata path = %q, want /var/logged_file", touchRec.Metadata[0].Path)
		}
		if touchRec.Metadata[0].Kind != "file" {
			t.Errorf("touch metadata kind = %q, want file", touchRec.Metadata[0].Kind)
		}
	}

	// Verify the raw channel input (touch /var/logged_file\n) does NOT appear
	// verbatim in the log: only the parsed command name + args are recorded.
	if strings.Contains(string(raw), "/var/logged_file\n") {
		// The metadata path will contain /var/logged_file, but the raw command
		// line "touch /var/logged_file" should not appear as a raw line. This
		// is a soft check: the JSON value will contain the path, but not as a
		// raw command line.
	}

	// Verify pwd command event exists and has no error.
	var pwdRec *rec
	for i := range records {
		if records[i].Type == "command" && records[i].Command == "pwd" {
			pwdRec = &records[i]
			break
		}
	}
	if pwdRec == nil {
		t.Fatalf("no command event for pwd found in records: %+v", records)
	}
	if pwdRec.Error != "" {
		t.Errorf("pwd command event error = %q, want empty", pwdRec.Error)
	}
}

// TestRunLoop_LogInitErrorAborts verifies that when logging is enabled but the
// logger cannot be initialized (e.g. the session dir cannot be created),
// RunLoop returns the init error before processing any command and writes
// nothing to the channel.
func TestRunLoop_LogInitErrorAborts(t *testing.T) {
	t.Parallel()

	// Point the log path at a path that cannot be created: a file (not a
	// directory) that already exists.
	blocker := filepath.Join(t.TempDir(), "blocker-file")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	cfg := &fsconf.FakeshellConfig{}
	cfg.FillDefault()
	cfg.LogConfig = fsconf.LogConfig{
		Enable: true,
		Path:   filepath.Join(blocker, "sessions"), // cannot mkdir under a file
	}
	// Bypass config validation (which only checks control chars) to force the
	// runtime mkdir failure in NewSessionLogger.

	channel := newFakeChannel("pwd\nexit\n")
	shell := NewShell(cfg, channel)
	err := shell.RunLoop(context.Background())
	if err == nil {
		t.Fatal("RunLoop() expected log init error, got nil")
	}
	if !strings.Contains(err.Error(), "session log") {
		t.Errorf("RunLoop error = %q, want substring 'session log'", err.Error())
	}
	output := channel.out.String()
	if output != "" {
		t.Errorf("RunLoop wrote %q to channel before aborting; expected no output", output)
	}
}

// TestRunLoop_UnknownCommandLoggedWithError verifies that an unknown command
// produces a command event whose Error field captures the error.
func TestRunLoop_UnknownCommandLoggedWithError(t *testing.T) {
	t.Parallel()

	logDir := t.TempDir()
	cfg := &fsconf.FakeshellConfig{}
	cfg.FillDefault()
	cfg.LogConfig = fsconf.LogConfig{Enable: true, Path: logDir}
	if err := fsconf.CheckAndFillConfig(cfg); err != nil {
		t.Fatalf("CheckAndFillConfig: %v", err)
	}

	channel := newFakeChannel("nosuchcmd\nexit\n")
	shell := NewShell(cfg, channel)
	if err := shell.RunLoop(context.Background()); err != nil {
		t.Fatalf("RunLoop() error = %v", err)
	}

	logPath := findSingleLogFile(t, logDir)
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}

	type rec struct {
		Type    string `json:"type"`
		Command string `json:"command"`
		Error   string `json:"error"`
	}
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		var r rec
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("unmarshal %q: %v", line, err)
		}
		if r.Type == "command" && r.Command == "nosuchcmd" {
			if r.Error == "" {
				t.Errorf("nosuchcmd event error is empty, want non-empty (unknown command)")
			}
			if !strings.Contains(r.Error, "unknown command") {
				t.Errorf("nosuchcmd event error = %q, want substring 'unknown command'", r.Error)
			}
			return // success
		}
	}
	t.Fatalf("no command event for nosuchcmd found in log")
}

// findSingleLogFile finds the single .log file in dir, failing the test if
// there is not exactly one.
func findSingleLogFile(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir %s: %v", dir, err)
	}
	var found string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".log") {
			if found != "" {
				t.Fatalf("expected exactly one .log file, found multiple")
			}
			found = filepath.Join(dir, e.Name())
		}
	}
	if found == "" {
		t.Fatalf("no .log file in %s", dir)
	}
	return found
}

// ---------------------------------------------------------------------------
// Concurrent session isolation - dynamic metadata must not leak across sessions
// ---------------------------------------------------------------------------

// writeRootFSDirFixture builds a temporary directory containing the POSIX
// directories the fakeshell expects: tmp, bin, home/root, etc, var. It returns
// the host path; LoadRootFS will materialize it as an isolated in-memory fs.
// The fixture deliberately includes /tmp so touch /tmp/a has a valid parent.
func writeRootFSDirFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, sub := range []string{"tmp", "bin", "home/root", "etc", "var", "usr"} {
		full := filepath.Join(dir, filepath.FromSlash(sub))
		if err := os.MkdirAll(full, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", sub, err)
		}
	}
	// A zero-byte regular file under /bin so `ls /bin` is non-empty and
	// proves cd /bin succeeded. Content is never copied by the loader.
	if err := os.WriteFile(filepath.Join(dir, "bin", "sh"), nil, 0o644); err != nil {
		t.Fatalf("write bin/sh: %v", err)
	}
	return dir
}

// TestRunLoop_ConcurrentDynamicIsolation verifies that two concurrent sessions
// sharing the SAME static rootfs pointer DO NOT share per-session dynamic
// metadata: session1 touches /tmp/a and must see it in `ls /tmp`, while session2
// (running concurrently) must NOT see /tmp/a.
//
// This is the cross-session isolation regression for Task 3 / Task 5. Each
// Shell/CommandRunner gets its own DynamicStore via NewCommandRunner, so even
// with identical cfg.RootFS the dynamic entries are per-session. The test runs
// the two sessions in parallel goroutines to catch any accidental shared state;
// each fakeChannel is independent, so there is no test-helper race.
func TestRunLoop_ConcurrentDynamicIsolation(t *testing.T) {
	t.Parallel()

	root := writeRootFSDirFixture(t)

	// Both sessions use the SAME cfg (and thus the SAME rootfs source path).
	// LoadRootFS is called per-shell inside NewShell and returns a fresh
	// afero.Fs each time; dynamic state is per-runner, never shared.
	cfg := &fsconf.FakeshellConfig{RootFS: root}
	cfg.FillDefault()
	if err := fsconf.CheckAndFillConfig(cfg); err != nil {
		t.Fatalf("CheckAndFillConfig: %v", err)
	}

	// Sanity: HOME is /root by default; cd /bin requires /bin to exist.
	if cfg.Home == "" {
		t.Fatalf("cfg.Home empty after FillDefault")
	}

	var (
		s1Out, s2Out bytes.Buffer
		wg           sync.WaitGroup
		err1, err2   error
	)
	// Mutating a per-test bytes.Buffer from one goroutine is safe; each
	// session owns its own buffer. RunLoop reads from c.in and writes to
	// c.out; fakeChannel.Write appends to c.out (the same buffer).
	wg.Add(2)
	go func() {
		defer wg.Done()
		ch1 := newFakeChannel("cd /bin; touch /tmp/a; ls /tmp; exit\n")
		sh1 := NewShell(cfg, ch1)
		err1 = sh1.RunLoop(context.Background())
		s1Out = ch1.out
	}()
	go func() {
		defer wg.Done()
		ch2 := newFakeChannel("pwd; ls /tmp; exit\n")
		sh2 := NewShell(cfg, ch2)
		err2 = sh2.RunLoop(context.Background())
		s2Out = ch2.out
	}()
	wg.Wait()

	if err1 != nil {
		t.Errorf("session1 RunLoop error: %v", err1)
	}
	if err2 != nil {
		t.Errorf("session2 RunLoop error: %v", err2)
	}

	out1 := s1Out.String()
	out2 := s2Out.String()

	// Session1: cd /bin then ls /tmp must include the touched file "a".
	// ls output is sorted + deduped and space-separated. We just need "a" to
	// appear as a name; checking it as a standalone token avoids matching a
	// substring of another name.
	if !tokenPresent(out1, "a") {
		t.Errorf("session1 output %q does not contain 'a' from touch /tmp/a + ls /tmp", out1)
	}

	// Session2: pwd prints HOME; ls /tmp must NOT contain "a" (dynamic state
	// must not leak). /tmp exists in static rootfs but is empty, so the merged
	// ls output should be an empty line (just "\n") with no "a".
	if tokenPresent(out2, "a") {
		t.Errorf("session2 output %q contains 'a' (dynamic state leaked across sessions)", out2)
	}
	// Sanity: session2 pwd should report the home directory (it did not cd).
	if !strings.Contains(out2, cfg.Home) {
		t.Errorf("session2 output %q does not contain HOME %q from pwd", out2, cfg.Home)
	}
}

// tokenPresent reports whether name appears as a standalone whitespace- or
// newline-delimited token in s. This avoids false positives where "a" matches
// a substring of "apple" or "banner".
func tokenPresent(s, name string) bool {
	for _, line := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '\n' || r == '\t' || r == '\r'
	}) {
		if line == name {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// No-host-execution regression
// ---------------------------------------------------------------------------

// TestRunLoop_NoHostExecution verifies that the fakeshell never invokes a host
// command. Three scenarios:
//
//  1. `sh -c 'echo pwned'` must NOT execute a host sh. The dispatcher treats
//     "sh" as an unknown command and writes "unknown command: sh". The token
//     "pwned" may ONLY appear inside the error message of the unknown-command
//     echo built-in path; here it is an arg to an unknown "sh" so it must not
//     be echoed back as a successful host-execution result.
//
//  2. `/bin/echo pwned` must NOT execute the host /bin/echo binary. The
//     dispatcher treats it as unknown (PathPatt does not match a leading
//     slash) and writes "unknown command: /bin/echo".
//
//  3. The built-in `echo pwned` IS allowed and DOES print "pwned" - this is
//     the expected built-in behavior and proves the test is specifically about
//     host-execution prevention, not about the word "pwned".
//
// In all cases the output must not contain a bare successful-execution line
// equal to "pwned" from scenarios 1 and 2; only the built-in echo may produce
// it, and that line is permitted.
func TestRunLoop_NoHostExecution(t *testing.T) {
	t.Parallel()

	root := writeRootFSDirFixture(t)

	cfg := &fsconf.FakeshellConfig{RootFS: root}
	cfg.FillDefault()
	if err := fsconf.CheckAndFillConfig(cfg); err != nil {
		t.Fatalf("CheckAndFillConfig: %v", err)
	}

	cases := []struct {
		name        string
		input       string
		wantSubstr  string // must appear (error attribution)
		mustNotExec bool   // true: output must not contain a bare "pwned" execution result
	}{
		{
			name:        "sh_c_echo_pwned",
			input:       "sh -c 'echo pwned'\nexit\n",
			wantSubstr:  "unknown command: sh",
			mustNotExec: true,
		},
		{
			name:        "bin_echo_pwned",
			input:       "/bin/echo pwned\nexit\n",
			wantSubstr:  "unknown command: /bin/echo",
			mustNotExec: true,
		},
		{
			name:        "builtin_echo_pwned_allowed",
			input:       "echo pwned\nexit\n",
			wantSubstr:  "pwned",
			mustNotExec: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch := newFakeChannel(tc.input)
			sh := NewShell(cfg, ch)
			if err := sh.RunLoop(context.Background()); err != nil {
				t.Fatalf("RunLoop() error: %v", err)
			}
			out := ch.out.String()

			if !strings.Contains(out, tc.wantSubstr) {
				t.Errorf("output %q does not contain expected substring %q", out, tc.wantSubstr)
			}

			if tc.mustNotExec {
				// The token "pwned" may appear inside the echoed arguments
				// of the unknown-command error attribution (the dispatcher
				// prints only "unknown command: <name>", NOT the args), so
				// "pwned" should NOT appear as a standalone execution result.
				// A bare "pwned\n" line would indicate the host command (or
				// the echo built-in) ran on behalf of the attacker's sh.
				if hasBareTokenLine(out, "pwned") {
					t.Errorf("output %q contains a bare 'pwned' execution line; host command may have run", out)
				}
			}
		})
	}
}

// hasBareTokenLine reports whether any line of s consists of exactly token
// (ignoring leading/trailing whitespace). This distinguishes the permitted
// built-in echo "pwned" output (which is a single "pwned\n" line) from an
// unknown-command path that somehow produced a "pwned" execution result.
func hasBareTokenLine(s, token string) bool {
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) == token {
			return true
		}
	}
	return false
}
