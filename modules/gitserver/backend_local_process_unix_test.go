//go:build !no_gitserver && (linux || freebsd || openbsd || darwin)
// +build !no_gitserver
// +build linux freebsd openbsd darwin

package gitserver

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hugefiver/fakessh/third/ssh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type blockingLocalChannel struct {
	closed   chan struct{}
	readDone chan struct{}
	once     sync.Once
	readOnce sync.Once
	writeMu  sync.Mutex
	output   bytes.Buffer
	stderr   bytes.Buffer
}

func newBlockingLocalChannel() *blockingLocalChannel {
	return &blockingLocalChannel{closed: make(chan struct{}), readDone: make(chan struct{})}
}

func (c *blockingLocalChannel) Read([]byte) (int, error) {
	<-c.closed
	c.readOnce.Do(func() { close(c.readDone) })
	return 0, io.EOF
}
func (c *blockingLocalChannel) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.output.Write(p)
}
func (c *blockingLocalChannel) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}
func (c *blockingLocalChannel) CloseWrite() error { return nil }
func (c *blockingLocalChannel) SendRequest(string, bool, []byte) (bool, error) {
	return false, nil
}
func (c *blockingLocalChannel) Stderr() io.ReadWriter { return localStderrWriter{channel: c} }

func (c *blockingLocalChannel) outputString() string {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.output.String()
}

func (c *blockingLocalChannel) stderrString() string {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.stderr.String()
}

type blockingOutputLocalChannel struct {
	*blockingLocalChannel
	writeStarted  chan struct{}
	writeRelease  chan struct{}
	writeReturned chan struct{}
	startOnce     sync.Once
	releaseOnce   sync.Once
	returnOnce    sync.Once
}

func newBlockingOutputLocalChannel() *blockingOutputLocalChannel {
	return &blockingOutputLocalChannel{
		blockingLocalChannel: newBlockingLocalChannel(),
		writeStarted:         make(chan struct{}),
		writeRelease:         make(chan struct{}),
		writeReturned:        make(chan struct{}),
	}
}

func (c *blockingOutputLocalChannel) Write([]byte) (int, error) {
	c.startOnce.Do(func() { close(c.writeStarted) })
	<-c.writeRelease
	c.returnOnce.Do(func() { close(c.writeReturned) })
	return 0, io.ErrClosedPipe
}

func (c *blockingOutputLocalChannel) Close() error {
	err := c.blockingLocalChannel.Close()
	c.releaseOnce.Do(func() { close(c.writeRelease) })
	return err
}

type localStderrWriter struct{ channel *blockingLocalChannel }

func (localStderrWriter) Read([]byte) (int, error) { return 0, io.EOF }
func (w localStderrWriter) Write(p []byte) (int, error) {
	w.channel.writeMu.Lock()
	defer w.channel.writeMu.Unlock()
	return w.channel.stderr.Write(p)
}

func closeLocalChannelAndWait(t *testing.T, channel *blockingLocalChannel) {
	t.Helper()
	require.NoError(t, channel.Close())
	select {
	case <-channel.readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("stdin copy goroutine did not leave the SSH channel read")
	}
}

func writeLocalTestShell(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "git-shell-test")
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755))
	return path
}

func newLocalProcessTestServer(t *testing.T, shell string) (*Server, Request) {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "project.git"), 0o755))
	current, err := user.Current()
	require.NoError(t, err)
	srv := newTestServer(t, &Config{
		Enable:      true,
		Backend:     BackendLocal,
		GitShell:    shell,
		GitUserHome: current.HomeDir,
		User:        current.Username,
		CurrentUser: true,
		RepoRoot:    root,
		Repositories: []RepositoryConfig{{
			Path:     "project.git",
			ReadKeys: []string{"SHA256:key"},
		}},
	})
	return srv, Request{Command: "git-upload-pack", Operation: OperationRead, RepoPath: "project.git"}
}

func TestServeLocalReturnsWhenProcessExitsBeforeSSHInputEOF(t *testing.T) {
	srv, req := newLocalProcessTestServer(t, writeLocalTestShell(t, "exit 0\n"))
	channel := newBlockingLocalChannel()
	done := make(chan error, 1)
	go func() { done <- srv.serveLocal(context.Background(), req, "", channel) }()

	select {
	case err := <-done:
		require.NoError(t, err)
		closeLocalChannelAndWait(t, channel)
	case <-time.After(750 * time.Millisecond):
		closeLocalChannelAndWait(t, channel)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("serveLocal goroutine did not clean up after releasing blocked SSH input")
		}
		t.Fatal("serveLocal waited for SSH input EOF after the process exited")
	}
}

func TestServeLocalNormalCompletionDrainsOutput(t *testing.T) {
	srv, req := newLocalProcessTestServer(t, writeLocalTestShell(t, "printf legitimate-output\nprintf legitimate-error >&2\nexit 0\n"))
	channel := newBlockingLocalChannel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.serveLocal(ctx, req, "", channel) }()

	select {
	case err := <-done:
		require.NoError(t, err)
		assert.Equal(t, "legitimate-output", channel.outputString(), "normal completion must drain all child output before returning")
		assert.Equal(t, "legitimate-error", channel.stderrString(), "normal completion must drain all child stderr before returning")
		closeLocalChannelAndWait(t, channel)
	case <-time.After(2 * time.Second):
		cancel()
		closeLocalChannelAndWait(t, channel)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		t.Fatal("serveLocal did not finish after draining normal output")
	}
}

func TestServeLocalCancellationReleasesSlotBeforeBlockedOutputCopy(t *testing.T) {
	srv, req := newLocalProcessTestServer(t, writeLocalTestShell(t, "printf blocked-output\nsleep 30\n"))
	srv.localSlots = make(chan struct{}, 1)
	channel := newBlockingOutputLocalChannel()
	t.Cleanup(func() { _ = channel.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.serveLocal(ctx, req, "", channel) }()

	select {
	case <-channel.writeStarted:
	case <-time.After(2 * time.Second):
		cancel()
		_ = channel.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		t.Fatal("child output did not reach the blocking SSH writer")
	}
	cancel()

	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(750 * time.Millisecond):
		_ = channel.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		t.Fatal("cancellation waited for a blocked SSH output writer")
	}

	assert.True(t, srv.tryAcquireLocalSlot(), "local process slot must be released before transport output unblocks")
	srv.releaseLocalSlot()
	require.NoError(t, channel.Close())
	select {
	case <-channel.writeReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("output copy did not leave the SSH writer after transport close")
	}
	select {
	case <-channel.readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("stdin copy did not leave the SSH reader after transport close")
	}
}

func TestCopyLocalOutputExitsOnlyAfterBlockedTransportReleases(t *testing.T) {
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	channel := newBlockingOutputLocalChannel()
	t.Cleanup(func() {
		_ = reader.Close()
		_ = writer.Close()
		_ = channel.Close()
	})
	done := copyLocalOutput(channel, reader)
	_, err = writer.Write([]byte("blocked-output"))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	select {
	case <-channel.writeStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("pipe output did not reach the blocking transport")
	}
	require.NoError(t, reader.Close(), "backend cancellation may close the pipe reader")
	select {
	case <-done:
		t.Fatal("closing the pipe reader cannot interrupt an in-progress SSH Write")
	case <-time.After(100 * time.Millisecond):
	}

	require.NoError(t, channel.Close(), "transport owner releases the blocked SSH Write")
	select {
	case err := <-done:
		assert.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("output copy did not exit after transport close")
	}
}

func TestServeLocalCancellationKillsProcessGroupDescendants(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "descendant.pid")
	parentExitedFile := filepath.Join(t.TempDir(), "parent-exited")
	survivedFile := filepath.Join(t.TempDir(), "descendant-survived")
	script := "(sleep 1; printf survived > \"" + survivedFile + "\") &\nchild=$!\nprintf '%s' \"$child\" > \"" + pidFile + "\"\nprintf exited > \"" + parentExitedFile + "\"\nexit 0\n"
	srv, req := newLocalProcessTestServer(t, writeLocalTestShell(t, script))
	channel := newBlockingLocalChannel()
	t.Cleanup(func() { _ = channel.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.serveLocal(ctx, req, "", channel) }()

	var childPID int
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(pidFile)
		_, parentErr := os.Stat(parentExitedFile)
		if err == nil && parentErr == nil {
			childPID, err = strconv.Atoi(strings.TrimSpace(string(data)))
			require.NoError(t, err)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if childPID == 0 {
		cancel()
		_ = channel.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		t.Fatal("child process did not publish its pid")
	}
	// serveLocal owns cancellation and reaping. Do not signal a saved numeric
	// descendant PID from Cleanup: by then that PID could belong to a new child.
	time.Sleep(50 * time.Millisecond)

	cancel()
	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		closeLocalChannelAndWait(t, channel)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		t.Fatal("serveLocal did not return after cancellation")
	}
	closeLocalChannelAndWait(t, channel)

	time.Sleep(1200 * time.Millisecond)
	_, err := os.Stat(survivedFile)
	assert.True(t, os.IsNotExist(err), "descendant process %d survived cancellation and wrote %q", childPID, survivedFile)
}

var _ ssh.Channel = (*blockingLocalChannel)(nil)
