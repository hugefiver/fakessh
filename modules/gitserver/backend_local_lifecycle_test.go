//go:build !no_gitserver

package gitserver

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type lifecycleTestProcess struct {
	exit     chan error
	started  chan struct{}
	onSignal func()
	reapErr  error
	mu       sync.Mutex
	events   []string
}

func (p *lifecycleTestProcess) record(event string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, event)
}
func (p *lifecycleTestProcess) snapshot() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.events...)
}
func (p *lifecycleTestProcess) waitExited() error {
	close(p.started)
	err := <-p.exit
	p.record("observed")
	return err
}
func (p *lifecycleTestProcess) terminateGroup() {
	p.record("signal")
	if p.onSignal != nil {
		p.onSignal()
	}
}
func (p *lifecycleTestProcess) reap() error {
	p.record("reap")
	return p.reapErr
}

type lifecycleTestInput struct {
	closed chan struct{}
	once   sync.Once
}

func (in *lifecycleTestInput) Close() error {
	in.once.Do(func() { close(in.closed) })
	return nil
}

func awaitLifecycleEvent(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("local process lifecycle did not reach expected event")
	}
}

func awaitLifecycleResult(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("local process lifecycle did not complete")
		return nil
	}
}

func newLifecycleTestProcess() (*lifecycleTestProcess, *lifecycleTestInput) {
	return &lifecycleTestProcess{exit: make(chan error, 1), started: make(chan struct{})},
		&lifecycleTestInput{closed: make(chan struct{})}
}

func TestLocalProcessSignalsBeforeReapWhileRunning(t *testing.T) {
	p, stdin := newLifecycleTestProcess()
	p.onSignal = func() { p.exit <- nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- waitLocalProcess(ctx, p, stdin, make(chan error), make(chan error)) }()
	awaitLifecycleEvent(t, p.started)
	cancel()
	require.ErrorIs(t, awaitLifecycleResult(t, done), context.Canceled)
	assert.Equal(t, []string{"signal", "observed", "reap"}, p.snapshot())
	awaitLifecycleEvent(t, stdin.closed)
}

func TestLocalProcessSignalsBeforeReapAfterLeaderExit(t *testing.T) {
	p, stdin := newLifecycleTestProcess()
	p.exit <- nil
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	// Neither inherited output pipes nor a blocked SSH writer may force an
	// early reap, or delay cancellation's final signal and slot release.
	go func() { done <- waitLocalProcess(ctx, p, stdin, make(chan error), make(chan error)) }()
	awaitLifecycleEvent(t, stdin.closed)
	assert.Equal(t, []string{"observed"}, p.snapshot(), "PID must remain reserved during output drain")
	cancel()
	require.ErrorIs(t, awaitLifecycleResult(t, done), context.Canceled)
	assert.Equal(t, []string{"observed", "signal", "reap"}, p.snapshot())
}

func TestLocalProcessObservationFailureSignalsBeforeReap(t *testing.T) {
	p, stdin := newLifecycleTestProcess()
	failure := errors.New("exit observer unavailable")
	p.exit <- failure
	err := waitLocalProcess(context.Background(), p, stdin, make(chan error), make(chan error))
	require.ErrorIs(t, err, failure)
	assert.Equal(t, []string{"observed", "signal", "reap"}, p.snapshot())
}

func TestLocalProcessNormalExitDrainsBeforeReap(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "exit-error"}[failed], func(t *testing.T) {
			p, stdin := newLifecycleTestProcess()
			if failed {
				p.reapErr = errors.New("exit status 23")
			}
			p.exit <- nil
			stdout, stderr := make(chan error, 1), make(chan error, 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- waitLocalProcess(ctx, p, stdin, stdout, stderr) }()
			awaitLifecycleEvent(t, stdin.closed)
			assert.Equal(t, []string{"observed"}, p.snapshot())
			stdout <- nil
			stderr <- nil
			assert.Equal(t, p.reapErr, awaitLifecycleResult(t, done))
			assert.Equal(t, []string{"observed", "reap"}, p.snapshot(), "normal completion must not signal")
		})
	}
}

func TestLocalOutputCompletedWinsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stdout, stderr := make(chan error, 1), make(chan error, 1)
	stdout <- nil
	stderr <- nil
	outErr, errErr, pending := waitLocalOutput(ctx, stdout, stderr)
	assert.NoError(t, outErr)
	assert.NoError(t, errErr)
	assert.False(t, pending)
}
