//go:build !no_fakeshell && !no_gitserver && !plan9
// +build !no_fakeshell,!no_gitserver,!plan9

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hugefiver/fakessh/modules/fakeshell"
	"github.com/hugefiver/fakessh/modules/gitserver"
	"github.com/hugefiver/fakessh/third/ssh"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func init() {
	if log == nil {
		log = zap.NewNop().Sugar()
	}
}

type deadlineRecordingConn struct {
	net.Conn
	mu        sync.Mutex
	deadlines []time.Time
}

type blockingWriteConn struct {
	net.Conn
	mu      sync.Mutex
	armed   bool
	allowed int
	blocked chan struct{}
	closed  chan struct{}
	block   sync.Once
	close   sync.Once
}

type closeOrderRecorder struct {
	mu     sync.Mutex
	events []string
}

func (r *closeOrderRecorder) add(event string) {
	r.mu.Lock()
	r.events = append(r.events, event)
	r.mu.Unlock()
}

func (r *closeOrderRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

type closeOrderChannel struct {
	recorder        *closeOrderRecorder
	transportClosed <-chan struct{}
}

func (c *closeOrderChannel) Read([]byte) (int, error)    { return 0, net.ErrClosed }
func (c *closeOrderChannel) Write(p []byte) (int, error) { return len(p), nil }
func (c *closeOrderChannel) Close() error {
	c.recorder.add("channel")
	if c.transportClosed != nil {
		<-c.transportClosed
	}
	return nil
}
func (c *closeOrderChannel) CloseWrite() error { return nil }
func (c *closeOrderChannel) SendRequest(string, bool, []byte) (bool, error) {
	return false, nil
}
func (c *closeOrderChannel) Stderr() io.ReadWriter { return c }

type closeOrderConn struct {
	recorder *closeOrderRecorder
	closed   chan struct{}
	once     sync.Once
}

func newCloseOrderConn(recorder *closeOrderRecorder) *closeOrderConn {
	return &closeOrderConn{recorder: recorder, closed: make(chan struct{})}
}

func (c *closeOrderConn) Read([]byte) (int, error)    { return 0, net.ErrClosed }
func (c *closeOrderConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *closeOrderConn) Close() error {
	c.once.Do(func() {
		c.recorder.add("transport")
		close(c.closed)
	})
	return nil
}
func (c *closeOrderConn) LocalAddr() net.Addr              { return nil }
func (c *closeOrderConn) RemoteAddr() net.Addr             { return nil }
func (c *closeOrderConn) SetDeadline(time.Time) error      { return nil }
func (c *closeOrderConn) SetReadDeadline(time.Time) error  { return nil }
func (c *closeOrderConn) SetWriteDeadline(time.Time) error { return nil }

func newBlockingWriteConn(conn net.Conn) *blockingWriteConn {
	return &blockingWriteConn{
		Conn:    conn,
		blocked: make(chan struct{}),
		closed:  make(chan struct{}),
	}
}

func (c *blockingWriteConn) arm() {
	c.armAfterWrites(0)
}

func (c *blockingWriteConn) armAfterWrites(allowed int) {
	c.mu.Lock()
	c.armed = true
	c.allowed = allowed
	c.mu.Unlock()
}

func (c *blockingWriteConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if !c.armed {
		c.mu.Unlock()
		return c.Conn.Write(p)
	}
	if c.allowed > 0 {
		c.allowed--
		c.mu.Unlock()
		return c.Conn.Write(p)
	}
	c.mu.Unlock()
	c.block.Do(func() { close(c.blocked) })
	<-c.closed
	return 0, net.ErrClosed
}

func (c *blockingWriteConn) Close() error {
	c.close.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func (c *deadlineRecordingConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, deadline)
	c.mu.Unlock()
	return c.Conn.SetDeadline(deadline)
}

func (c *deadlineRecordingConn) lastDeadline() (time.Time, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.deadlines) == 0 {
		return time.Time{}, 0
	}
	return c.deadlines[len(c.deadlines)-1], len(c.deadlines)
}

func (c *deadlineRecordingConn) waitForDeadlineCalls(want int, timeout time.Duration) (time.Time, int) {
	deadline := time.Now().Add(timeout)
	for {
		last, calls := c.lastDeadline()
		if calls >= want || time.Now().After(deadline) {
			return last, calls
		}
		time.Sleep(time.Millisecond)
	}
}

func testSSHServerConfig(t *testing.T, permissions *ssh.Permissions) *ssh.ServerConfig {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	signer, err := ssh.NewSignerFromSigner(privateKey)
	if err != nil {
		t.Fatalf("NewSignerFromSigner() error = %v", err)
	}
	config := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			return permissions, nil
		},
	}
	config.AddHostKey(signer)
	return config
}

func startHandledSSHConnection(t *testing.T, timeout time.Duration, permissions *ssh.Permissions, gitServer *gitserver.Server, parentContext context.Context, beforeGlobalReply func(), wrap ...func(net.Conn) net.Conn) (*ssh.Client, *deadlineRecordingConn, <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	clientResult := make(chan struct {
		client *ssh.Client
		err    error
	}, 1)
	go func() {
		client, err := ssh.Dial("tcp", listener.Addr().String(), &ssh.ClientConfig{
			User:            "test",
			Auth:            []ssh.AuthMethod{ssh.Password("test")},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         2 * time.Second,
		})
		clientResult <- struct {
			client *ssh.Client
			err    error
		}{client, err}
	}()

	var serverNetConn net.Conn
	select {
	case serverNetConn = <-accepted:
	case err := <-acceptErr:
		t.Fatalf("Accept() error = %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("Accept() timed out")
	}
	if len(wrap) > 0 {
		serverNetConn = wrap[0](serverNetConn)
	}
	recordingConn := &deadlineRecordingConn{Conn: serverNetConn}
	t.Cleanup(func() { _ = recordingConn.Close() })

	connections := &atomic.Int64{}
	connections.Store(1)
	successful := &atomic.Int64{}
	handled := make(chan struct{})
	serverConfig := testSSHServerConfig(t, permissions)
	go func() {
		defer close(handled)
		handleConn(&SSHConnectionContext{
			Conn:              recordingConn,
			connectionContext: parentContext,
			postAuthTimeout:   timeout,
			beforeGlobalReply: beforeGlobalReply,
			Connections:       connections,
			SuccConnections:   successful,
			FakeShellConfig:   &fakeshell.Config{},
			GitServer:         gitServer,
		}, serverConfig)
	}()

	var result struct {
		client *ssh.Client
		err    error
	}
	select {
	case result = <-clientResult:
	case <-time.After(2 * time.Second):
		t.Fatal("SSH client handshake timed out")
	}
	if result.err != nil {
		t.Fatalf("ssh.Dial() error = %v", result.err)
	}
	t.Cleanup(func() { _ = result.client.Close() })
	return result.client, recordingConn, handled
}

func TestTransportClosingChannelClosesChannelBeforeTransport(t *testing.T) {
	recorder := &closeOrderRecorder{}
	transport := newCloseOrderConn(recorder)
	channel := &closeOrderChannel{recorder: recorder}
	closing := &transportClosingChannel{Channel: channel, transport: transport}

	if err := closing.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case <-transport.closed:
		t.Fatal("transport closed before the peer had a grace period to acknowledge channel close")
	case <-time.After(sshChannelCloseGrace / 4):
	}
	select {
	case <-transport.closed:
	case <-time.After(2 * sshChannelCloseGrace):
		t.Fatal("transport remained open after the channel-close grace period")
	}
	events := recorder.snapshot()
	if len(events) != 2 || events[0] != "channel" || events[1] != "transport" {
		t.Fatalf("close order = %v, want [channel transport]", events)
	}
}

func TestTransportClosingChannelBoundsBlockedChannelClose(t *testing.T) {
	recorder := &closeOrderRecorder{}
	transport := newCloseOrderConn(recorder)
	channel := &closeOrderChannel{
		recorder:        recorder,
		transportClosed: transport.closed,
	}
	closing := &transportClosingChannel{Channel: channel, transport: transport}

	done := make(chan error, 1)
	go func() { done <- closing.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-time.After(2 * sshChannelCloseGrace):
		t.Fatal("Close() stayed blocked behind the SSH channel close")
	}

	events := recorder.snapshot()
	if len(events) != 2 || events[0] != "channel" || events[1] != "transport" {
		t.Fatalf("close order = %v, want [channel transport]", events)
	}
}

func TestHandleConnQuotesChannelAndGlobalRequestTypes(t *testing.T) {
	previousLog := log
	core, observed := observer.New(zap.DebugLevel)
	log = zap.New(core).Sugar()

	client, _, handled := startHandledSSHConnection(t, time.Second, nil, nil, nil, nil)
	defer func() {
		_ = client.Close()
		select {
		case <-handled:
		case <-time.After(time.Second):
		}
		log = previousLog
	}()

	if _, _, err := client.OpenChannel("line\nchannel", nil); err == nil {
		t.Fatal("unknown channel type unexpectedly succeeded")
	}
	ok, _, err := client.SendRequest("line\nglobal", true, nil)
	if err != nil {
		t.Fatalf("SendRequest() error = %v", err)
	}
	if ok {
		t.Fatal("unknown global request unexpectedly succeeded")
	}
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	ok, _, err = client.SendRequest("line\npost-session", true, nil)
	if err != nil {
		t.Fatalf("post-session SendRequest() error = %v", err)
	}
	if ok {
		t.Fatal("unknown post-session global request unexpectedly succeeded")
	}

	var channelLog string
	var requestLogs []string
	for _, entry := range observed.All() {
		switch {
		case strings.Contains(entry.Message, "ClientNewChannel") && strings.Contains(entry.Message, "line"):
			channelLog = entry.Message
		case strings.Contains(entry.Message, "ClientRequest"):
			requestLogs = append(requestLogs, entry.Message)
		}
	}
	if channelLog == "" || len(requestLogs) != 2 {
		t.Fatalf("missing protocol logs: channel=%q requests=%q", channelLog, requestLogs)
	}
	for name, message := range map[string]string{
		"channel":              channelLog,
		"pre-session request":  requestLogs[0],
		"post-session request": requestLogs[1],
	} {
		if strings.Contains(message, "\n") {
			t.Fatalf("%s log contains a literal newline: %q", name, message)
		}
	}
	if !strings.Contains(channelLog, `"line\nchannel"`) {
		t.Fatalf("channel type was not quoted: %q", channelLog)
	}
	if !strings.Contains(requestLogs[0], `"line\nglobal"`) {
		t.Fatalf("pre-session global request type was not quoted: %q", requestLogs[0])
	}
	if !strings.Contains(requestLogs[1], `"line\npost-session"`) {
		t.Fatalf("post-session global request type was not quoted: %q", requestLogs[1])
	}
}

func TestHandleConnKeepsHardDeadlineWhileWaitingForSession(t *testing.T) {
	client, conn, handled := startHandledSSHConnection(t, 150*time.Millisecond, nil, nil, nil, nil)
	ok, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
	if err != nil {
		t.Fatalf("SendRequest() error = %v", err)
	}
	if !ok {
		t.Fatal("server rejected ordinary keepalive request")
	}
	deadline, calls := conn.waitForDeadlineCalls(2, 500*time.Millisecond)
	if calls < 2 {
		t.Fatalf("SetDeadline() calls = %d, want at least handshake and post-auth deadlines", calls)
	}
	if deadline.IsZero() {
		t.Fatal("post-auth pre-session TCP deadline was cleared")
	}

	wait := make(chan error, 1)
	go func() { wait <- client.Wait() }()
	select {
	case <-wait:
	case <-time.After(2 * time.Second):
		t.Fatal("client transport did not close at pre-session hard deadline")
	}
	select {
	case <-handled:
	case <-time.After(time.Second):
		t.Fatal("handleConn did not return after pre-session deadline")
	}
}

func TestHandleConnHardTimeoutClosesRealNonGitSSHChannel(t *testing.T) {
	client, conn, handled := startHandledSSHConnection(t, 150*time.Millisecond, nil, nil, nil, nil)
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	deadline, calls := conn.waitForDeadlineCalls(3, 500*time.Millisecond)
	if calls < 3 {
		t.Fatalf("SetDeadline() calls = %d, want handshake, pre-session, and non-Git session deadlines", calls)
	}
	if deadline.IsZero() {
		t.Fatal("non-Git session cleared its TCP hard deadline")
	}

	wait := make(chan error, 1)
	go func() { wait <- client.Wait() }()
	select {
	case <-wait:
	case <-time.After(2 * time.Second):
		t.Fatal("real SSH transport stayed blocked after non-Git timeout")
	}
	select {
	case <-handled:
	case <-time.After(time.Second):
		t.Fatal("handleConn stayed blocked in the real SSH channel read")
	}
}

func TestHandleConnClearsDeadlineForGitSession(t *testing.T) {
	timeout := 150 * time.Millisecond
	client, conn, handled := startHandledSSHConnection(t, timeout, gitPerm("SHA256:test"), &gitserver.Server{}, nil, nil)
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	deadline, calls := conn.waitForDeadlineCalls(3, 500*time.Millisecond)
	if calls < 3 {
		t.Fatalf("SetDeadline() calls = %d, want handshake, pre-session, and Git transition deadlines", calls)
	}
	if !deadline.IsZero() {
		t.Fatalf("Git session retained TCP deadline %v", deadline)
	}

	wait := make(chan error, 1)
	go func() { wait <- client.Wait() }()
	select {
	case err := <-wait:
		t.Fatalf("Git transport ended at the non-Git timeout: %v", err)
	case <-time.After(2 * timeout):
	}

	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	select {
	case <-wait:
	case <-time.After(time.Second):
		t.Fatal("Git client transport did not close during cleanup")
	}
	select {
	case <-handled:
	case <-time.After(time.Second):
		t.Fatal("Git handleConn did not return during cleanup")
	}
}

func TestGitSessionCancellationClosesTransportWhileGlobalReplyIsBlocked(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var blockingConn *blockingWriteConn
	client, conn, handled := startHandledSSHConnection(
		t,
		150*time.Millisecond,
		gitPerm("SHA256:test"),
		&gitserver.Server{},
		ctx,
		nil,
		func(conn net.Conn) net.Conn {
			blockingConn = newBlockingWriteConn(conn)
			return blockingConn
		},
	)
	_, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	deadline, calls := conn.waitForDeadlineCalls(3, 500*time.Millisecond)
	if calls < 3 || !deadline.IsZero() {
		t.Fatalf("Git session did not enter the unbounded route: calls=%d deadline=%v", calls, deadline)
	}

	blockingConn.arm()
	requestDone := make(chan error, 1)
	go func() {
		_, _, err := client.SendRequest("blocked-global-reply", true, nil)
		requestDone <- err
	}()
	select {
	case <-blockingConn.blocked:
	case <-time.After(time.Second):
		t.Fatal("server did not block while writing the global request reply")
	}

	cancel()

	select {
	case <-handled:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Git session was cancelled but connection owner did not close the blocked transport")
	}
	select {
	case <-blockingConn.closed:
	default:
		t.Fatal("handleConn returned without closing the underlying transport")
	}
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("blocked global request did not unblock after transport close")
	}
}

func TestGitBackendCompletionBlockedExitStatusClosesOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fingerprint := "SHA256:test"
	tmp := t.TempDir()
	server, err := gitserver.NewServer(&gitserver.Config{
		Enable:         true,
		SSHUser:        "git",
		AuthorizedKeys: filepath.Join(tmp, "unused-authorized-keys"),
		WatchKeys:      true,
		Backend:        gitserver.BackendSSH,
		Repositories: []gitserver.RepositoryConfig{
			{Path: "repo.git", BackendPath: "repo.git", ReadKeys: []string{fingerprint}},
		},
		SSHBackend: gitserver.SSHBackendConfig{
			Address:    "127.0.0.1:1",
			User:       "git",
			KeyFile:    filepath.Join(tmp, "missing-backend-key"),
			KnownHosts: filepath.Join(tmp, "missing-known-hosts"),
		},
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	var blockingConn *blockingWriteConn
	globalReplyStarted := make(chan struct{})
	var globalReplyOnce sync.Once
	client, conn, handled := startHandledSSHConnection(
		t,
		150*time.Millisecond,
		gitPerm(fingerprint),
		server,
		ctx,
		func() { globalReplyOnce.Do(func() { close(globalReplyStarted) }) },
		func(conn net.Conn) net.Conn {
			blockingConn = newBlockingWriteConn(conn)
			return blockingConn
		},
	)
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	deadline, calls := conn.waitForDeadlineCalls(3, 500*time.Millisecond)
	if calls < 3 || !deadline.IsZero() {
		t.Fatalf("Git session did not enter the unbounded route: calls=%d deadline=%v", calls, deadline)
	}

	// Let the exec-success response through, then block the backend's
	// exit-status write after the configured backend fails immediately.
	blockingConn.armAfterWrites(1)
	startDone := make(chan error, 1)
	go func() { startDone <- session.Start("git-upload-pack 'repo.git'") }()
	select {
	case err := <-startDone:
		if err != nil {
			t.Fatalf("Start() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Git exec request was not accepted")
	}
	select {
	case <-blockingConn.blocked:
	case <-time.After(time.Second):
		t.Fatal("backend completed without reaching the blocked exit-status write")
	}
	globalDone := make(chan error, 1)
	go func() {
		_, _, err := client.SendRequest("blocked-behind-exit-status", true, nil)
		globalDone <- err
	}()
	select {
	case <-globalReplyStarted:
	case <-time.After(time.Second):
		t.Fatal("connection owner did not enter the blocked global reply")
	}

	cancel()
	select {
	case <-handled:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("cancel did not make the connection owner close the exit-status-blocked transport")
	}
	select {
	case <-blockingConn.closed:
	default:
		t.Fatal("underlying transport remained open after cancellation")
	}
	select {
	case <-globalDone:
	case <-time.After(time.Second):
		t.Fatal("global request remained blocked after owner transport close")
	}
}
