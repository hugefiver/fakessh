//go:build !no_gitserver && (linux || freebsd || openbsd || darwin)

package gitserver

import (
	"context"
	"io"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalExitObservationDoesNotReap(t *testing.T) {
	cmd := execAsCurrentUser("/bin/sh", "-c", "exit 23")
	require.NoError(t, cmd.Start())
	reaped := false
	t.Cleanup(func() {
		if !reaped {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})

	require.NoError(t, waitLocalProcessExit(cmd.Process.Pid))
	// Repeat after exit to cover late kqueue registration as well as WNOWAIT.
	require.NoError(t, waitLocalProcessExit(cmd.Process.Pid))
	err := cmd.Wait()
	reaped = true
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr, "observation must leave wait status for Cmd.Wait")
	assert.Equal(t, 23, exitErr.ExitCode())
}

type recordingLocalCommand struct {
	localCommandProcess
	mu     sync.Mutex
	events []string
}

func (p *recordingLocalCommand) record(event string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, event)
}
func (p *recordingLocalCommand) waitExited() error {
	err := p.localCommandProcess.waitExited()
	p.record("observed")
	return err
}
func (p *recordingLocalCommand) terminateGroup() {
	p.record("signal")
	p.localCommandProcess.terminateGroup()
}
func (p *recordingLocalCommand) reap() error {
	p.record("reap")
	return p.localCommandProcess.reap()
}

func TestLocalExitedLeaderWithInheritedPipeSignalsBeforeReap(t *testing.T) {
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	defer reader.Close()
	defer writer.Close()
	// The shell exits, while sleep still owns the output writer. No sleeps or
	// pid-file heuristics in the test determine whether the leader has exited.
	cmd := execAsCurrentUser("/bin/sh", "-c", "sleep 30 & exit 23")
	cmd.Stdout = writer
	cmd.Stderr = writer
	require.NoError(t, cmd.Start())
	require.NoError(t, writer.Close())
	p := &recordingLocalCommand{localCommandProcess: localCommandProcess{cmd}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stdin := &lifecycleTestInput{closed: make(chan struct{})}
	output := copyLocalOutput(io.Discard, reader)
	stderr := make(chan error, 1)
	stderr <- nil
	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		done <- waitLocalProcess(ctx, p, stdin, output, stderr)
		close(finished)
	}()
	t.Cleanup(func() {
		cancel()
		awaitLifecycleEvent(t, finished)
	})
	awaitLifecycleEvent(t, stdin.closed) // real OS exit observation, not reap
	select {
	case err := <-done:
		t.Fatalf("returned with inherited pipe still open: %v", err)
	default:
	}
	require.NoError(t, waitLocalProcessExit(cmd.Process.Pid), "leader must still be waitable")
	cancel()
	require.ErrorIs(t, awaitLifecycleResult(t, done), context.Canceled)
	assert.Equal(t, []string{"observed", "signal", "reap"}, p.events)
	require.NotNil(t, cmd.ProcessState)
	assert.Equal(t, 23, cmd.ProcessState.ExitCode(), "final Wait must reap the original leader's status")

	// The lifecycle may return without waiting for copies, but killing the
	// group must close the descendant's writer. There is no network block here.
	select {
	case err := <-output:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("descendant retained inherited pipe after group cancellation")
	}
}
