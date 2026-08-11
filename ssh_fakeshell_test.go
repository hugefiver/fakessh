//go:build !no_fakeshell && !plan9
// +build !no_fakeshell,!plan9

package main

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	fakeconf "github.com/hugefiver/fakessh/modules/fakeshell/conf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type blockingFakeShellChannel struct {
	closed chan struct{}
	once   sync.Once
}

func newBlockingFakeShellChannel() *blockingFakeShellChannel {
	return &blockingFakeShellChannel{closed: make(chan struct{})}
}

func (c *blockingFakeShellChannel) Read(data []byte) (int, error) {
	<-c.closed
	return 0, io.EOF
}

func (c *blockingFakeShellChannel) Write(data []byte) (int, error) { return len(data), nil }

func (c *blockingFakeShellChannel) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *blockingFakeShellChannel) CloseWrite() error { return nil }

func (c *blockingFakeShellChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return false, nil
}

func (c *blockingFakeShellChannel) Stderr() io.ReadWriter { return discardReadWriter{} }

type discardReadWriter struct{}

func (discardReadWriter) Read(p []byte) (int, error)  { return 0, io.EOF }
func (discardReadWriter) Write(p []byte) (int, error) { return len(p), nil }

func TestServeFakeShellClosesIdleChannelOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	channel := newBlockingFakeShellChannel()
	done := make(chan struct{})

	go func() {
		defer close(done)
		serveFakeShell(ctx, &SSHConnectionContext{FakeShellConfig: &fakeconf.FakeshellConfig{}}, channel, nil)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serveFakeShell did not return after context cancellation")
	}

	select {
	case <-channel.closed:
	default:
		t.Fatal("serveFakeShell did not close the channel on context cancellation")
	}
	require.Error(t, ctx.Err())
	assert.ErrorIs(t, ctx.Err(), context.DeadlineExceeded)
}
