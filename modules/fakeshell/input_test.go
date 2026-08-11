//go:build !no_fakeshell && !plan9
// +build !no_fakeshell,!plan9

package fakeshell

import (
	"context"
	"strings"
	"testing"

	fsconf "github.com/hugefiver/fakessh/modules/fakeshell/conf"
)

func TestInputFindCommandSeparator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		idx  int
		ok   bool
	}{
		{name: "plain newline", in: "echo a\nwhoami", idx: len("echo a"), ok: true},
		{name: "plain semicolon", in: "echo a;whoami", idx: len("echo a"), ok: true},
		{name: "single quoted semicolon", in: "echo 'a;b'; echo c", idx: len("echo 'a;b'"), ok: true},
		{name: "double quoted semicolon", in: `echo "a;b"; echo c`, idx: len(`echo "a;b"`), ok: true},
		{name: "escaped quote in double quotes", in: `echo "a\";b"; echo c`, idx: len(`echo "a\";b"`), ok: true},
		{name: "newline inside single quote", in: "echo 'a\nb'; echo c", idx: len("echo 'a"), ok: true},
		{name: "newline after double quote backslash", in: "echo \"a\\\nb\"; echo c", idx: len("echo \"a\\"), ok: true},
		{name: "no separator", in: "echo 'a;b'", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIdx, gotOK := findCommandSeparator([]byte(tt.in))
			if gotOK != tt.ok || gotIdx != tt.idx {
				t.Fatalf("findCommandSeparator(%q) = (%d, %v), want (%d, %v)", tt.in, gotIdx, gotOK, tt.idx, tt.ok)
			}
		})
	}
}

func TestRunLoopInputTooLongLineTerminatesWithoutClientErrorText(t *testing.T) {
	t.Parallel()

	cfg := newInputTestConfig(t)
	ch := newFakeChannel(strings.Repeat("x", MaxInputLineBytes+128) + "\nwhoami\nexit\n")
	sh := NewShell(cfg, ch)

	if err := sh.RunLoop(context.Background()); err == nil {
		t.Fatal("RunLoop() error = nil, want non-nil input error")
	}

	out := ch.out.String()
	if strings.Contains(out, "input line too long") || strings.Contains(out, "fakeshell: invalid input") {
		t.Fatalf("output %q contains input-layer error text", out)
	}
	if tokenPresent(out, cfg.EnvConfig.User) {
		t.Fatalf("output %q shows subsequent whoami ran after input error", out)
	}
}

func TestRunLoopInputTooLongTokenTerminatesWithoutClientErrorText(t *testing.T) {
	t.Parallel()

	cfg := newInputTestConfig(t)
	longToken := strings.Repeat("a", MaxInputTokenBytes+1)
	ch := newFakeChannel("echo " + longToken + "\nwhoami\nexit\n")
	sh := NewShell(cfg, ch)

	if err := sh.RunLoop(context.Background()); err == nil {
		t.Fatal("RunLoop() error = nil, want non-nil input error")
	}

	out := ch.out.String()
	if strings.Contains(out, "fakeshell: invalid input") || strings.Contains(out, "token too long") {
		t.Fatalf("output %q contains input-layer error text", out)
	}
	if strings.Contains(out, longToken) {
		t.Fatalf("output contains attacker long token")
	}
	if tokenPresent(out, cfg.EnvConfig.User) {
		t.Fatalf("output %q shows subsequent whoami ran after input error", out)
	}
}

func TestRunLoopInputTooManyArgsTerminatesWithoutClientErrorText(t *testing.T) {
	t.Parallel()

	cfg := newInputTestConfig(t)
	args := make([]string, MaxInputArgs+1)
	for i := range args {
		args[i] = "a"
	}
	ch := newFakeChannel("echo " + strings.Join(args, " ") + "\nwhoami\nexit\n")
	sh := NewShell(cfg, ch)

	if err := sh.RunLoop(context.Background()); err == nil {
		t.Fatal("RunLoop() error = nil, want non-nil input error")
	}

	out := ch.out.String()
	if strings.Contains(out, "fakeshell: invalid input") || strings.Contains(out, "too many arguments") {
		t.Fatalf("output %q contains input-layer error text", out)
	}
	if tokenPresent(out, cfg.EnvConfig.User) {
		t.Fatalf("output %q shows subsequent whoami ran after input error", out)
	}
}

func TestRunLoopInputQuotedSemicolonDoesNotSplit(t *testing.T) {
	t.Parallel()

	cfg := newInputTestConfig(t)
	ch := newFakeChannel("echo 'a;b'; echo c\nexit\n")
	sh := NewShell(cfg, ch)

	if err := sh.RunLoop(context.Background()); err != nil {
		t.Fatalf("RunLoop() error = %v", err)
	}

	out := ch.out.String()
	if !tokenPresent(out, "a;b") || !tokenPresent(out, "c") {
		t.Fatalf("output %q missing expected quoted-semicolon echo results", out)
	}
	if strings.Contains(out, "unknown command") || strings.Contains(out, "invalid input") {
		t.Fatalf("output %q shows quoted semicolon was mishandled", out)
	}
}

func TestRunLoopInputUnterminatedQuoteAtNewlineShowsSyntaxErrorAndContinues(t *testing.T) {
	t.Parallel()

	cfg := newInputTestConfig(t)
	ch := newFakeChannel("echo 'unterminated\nwhoami\nexit\n")
	sh := NewShell(cfg, ch)

	if err := sh.RunLoop(context.Background()); err != nil {
		t.Fatalf("RunLoop() error = %v", err)
	}

	out := ch.out.String()
	if !strings.Contains(out, "fakeshell: syntax error") {
		t.Fatalf("output %q missing visible syntax error", out)
	}
	if strings.Contains(out, "unterminated quote") || strings.Contains(out, "fakeshell: invalid input") {
		t.Fatalf("output %q contains input-layer/internal error text", out)
	}
	if !tokenPresent(out, cfg.EnvConfig.User) {
		t.Fatalf("output %q missing subsequent whoami after syntax error", out)
	}
}

func TestRunLoopInputManySeparatorsBurstHandlesExit(t *testing.T) {
	t.Parallel()

	cfg := newInputTestConfig(t)
	ch := newFakeChannel(strings.Repeat(";", MaxCommandsPerReadCycle*3) + "whoami;exit\n")
	sh := NewShell(cfg, ch)

	if err := sh.RunLoop(context.Background()); err != nil {
		t.Fatalf("RunLoop() error = %v", err)
	}

	out := ch.out.String()
	if !tokenPresent(out, cfg.EnvConfig.User) {
		t.Fatalf("output %q missing whoami result after separator burst", out)
	}
}

func TestRunLoopInputDangerousToolsRemainInert(t *testing.T) {
	t.Parallel()

	cfg := newInputTestConfig(t)
	ch := newFakeChannel("curl http://example.invalid; nmap 127.0.0.1; exit\n")
	sh := NewShell(cfg, ch)

	if err := sh.RunLoop(context.Background()); err != nil {
		t.Fatalf("RunLoop() error = %v", err)
	}

	out := ch.out.String()
	for _, name := range []string{"curl", "nmap"} {
		if !strings.Contains(out, "unknown command: "+name) {
			t.Fatalf("output %q missing unknown command response for %s", out, name)
		}
	}
	for _, forbidden := range []string{"HTTP/", "example.invalid", "Starting Nmap"} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("output %q contains %q; dangerous tool may have been simulated too far", out, forbidden)
		}
	}
}

func newInputTestConfig(t *testing.T) *fsconf.FakeshellConfig {
	t.Helper()
	cfg := &fsconf.FakeshellConfig{}
	cfg.FillDefault()
	if err := fsconf.CheckAndFillConfig(cfg); err != nil {
		t.Fatalf("CheckAndFillConfig() error = %v", err)
	}
	return cfg
}
