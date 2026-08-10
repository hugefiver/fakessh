package fakeshell

import (
	"bytes"
	"context"
	"io"
	"strings"
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
