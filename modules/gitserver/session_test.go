//go:build !no_gitserver
// +build !no_gitserver

package gitserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hugefiver/fakessh/third/ssh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Test harness ------------------------------------------------------------
//
// The session tests drive a real vendored SSH client against a real vendored
// SSH server constructed with NoClientAuth + NoClientAuthCallback so we can
// inject a fixed *ssh.Permissions (the git permission) without standing up
// the full public-key auth path. The server side accepts the first session
// channel and hands it to srv.HandleSession. The client side opens a session
// and sends env/exec/pty/shell/subsystem requests via the ssh.Session API.
//

// sshPipeConns returns a connected pair of net.Conns backed by a real TCP
// listener on 127.0.0.1. net.Pipe() is synchronous and deadlocks the SSH
// version-exchange (both ends write their banner simultaneously with no
// reader); a real loopback TCP socket buffers the writes so the handshakes
// proceed in parallel. This mirrors how third/ssh's own netPipe helper works.
func sshPipeConns(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	type acceptResult struct {
		c   net.Conn
		err error
	}
	ch := make(chan acceptResult, 1)
	go func() {
		c, err := ln.Accept()
		ch <- acceptResult{c, err}
	}()

	c1, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	ar := <-ch
	require.NoError(t, ar.err)
	return ar.c, c1
}

// The backend runner is replaced with a test-controlled hook so the tests
// can assert on the authorized Request / GIT_PROTOCOL value and can block
// the backend to exercise the drain / cancel paths.

// sessionFixture wires up a net.Pipe-based SSH server+client pair with a
// gitserver.Server whose backend runner is replaced by a test hook. It
// returns the connected client, the server-side goroutine's HandleSession
// error channel, the captured backend call, and a cleanup func.
//
// The server-side permissions are the git permission for "SHA256:testkey".
// The backend hook records the (Request, gitProtocol) it was called with and
// signals backendCalled / backendRelease so tests can block/advance the
// backend.
type sessionFixture struct {
	t *testing.T

	srv *Server

	client *ssh.Client

	// serverErr receives the return value of HandleSession.
	serverErr chan error

	// backendCalled is closed when the backend hook is first entered.
	backendCalled chan struct{}
	// backendRelease blocks the backend hook until closed; the hook returns
	// backendErr after release. Tests that want the backend to finish
	// immediately should close backendRelease right after the exec is sent.
	backendRelease chan struct{}
	// backendErr is the error the backend hook returns (default nil).
	backendErr error

	// captured records the authorized Request and GIT_PROTOCOL value passed
	// to the backend hook. It is populated before backendRelease is waited
	// on, so a test can read it after backendCalled is closed.
	capturedMu sync.Mutex
	captured   *Request
	protocol   string
	called     int
}

// newSessionFixture builds the fixture with the given repository config and
// permissions. The permissions are returned to the client via
// NoClientAuthCallback. The fixture starts the server and client goroutines
// and returns once the client has a live *ssh.Client. Cleanup is registered
// with t.Cleanup.
func newSessionFixture(t *testing.T, repos []RepositoryConfig, perms *ssh.Permissions) *sessionFixture {
	t.Helper()

	// Build the gitserver.Server with the given repos. We bypass
	// authorized_keys by pointing at an empty file (newTestServer does
	// this) because these tests do not exercise public-key auth.
	srv := newTestServer(t, &Config{
		Enable:       true,
		Repositories: repos,
	})

	f := &sessionFixture{
		t:              t,
		srv:            srv,
		serverErr:      make(chan error, 1),
		backendCalled:  make(chan struct{}),
		backendRelease: make(chan struct{}),
	}

	// Install the test backend runner. It records the call, signals
	// backendCalled, then blocks on backendRelease. The returned error is
	// f.backendErr (nil by default).
	srv.runBackend = func(ctx context.Context, s *Server, req Request, gitProtocol string, channel ssh.Channel) error {
		f.capturedMu.Lock()
		f.called++
		f.captured = &req
		f.protocol = gitProtocol
		f.capturedMu.Unlock()
		close(f.backendCalled)
		select {
		case <-f.backendRelease:
		case <-ctx.Done():
			return ctx.Err()
		}
		return f.backendErr
	}

	c1, c2 := sshPipeConns(t)

	// Generate a host signer for the server.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostSigner, err := ssh.NewSignerFromSigner(priv)
	require.NoError(t, err)

	serverConf := &ssh.ServerConfig{
		NoClientAuth: true,
		NoClientAuthCallback: func(conn ssh.ConnMetadata) (*ssh.Permissions, error) {
			return perms, nil
		},
	}
	serverConf.AddHostKey(hostSigner)

	// Server goroutine: handshake, accept first session channel, drive
	// HandleSession.
	go func() {
		conn, chans, reqs, err := ssh.NewServerConn(c1, serverConf)
		if err != nil {
			f.serverErr <- err
			c1.Close()
			return
		}
		// Discard global requests so they don't block the mux.
		go ssh.DiscardRequests(reqs)

		for newCh := range chans {
			if newCh.ChannelType() != "session" {
				newCh.Reject(ssh.UnknownChannelType, "unknown channel type")
				continue
			}
			channel, inReqs, err := newCh.Accept()
			if err != nil {
				continue
			}
			f.serverErr <- srv.HandleSession(context.Background(), conn.Permissions, channel, inReqs)
			_ = conn.Close()
			return
		}
		_ = conn.Close()
		f.serverErr <- errors.New("server: no session channel received")
	}()

	// Client goroutine: handshake, wrap in *Client.
	clientConf := &ssh.ClientConfig{
		User:            "git",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	conn, chans, reqs, err := ssh.NewClientConn(c2, "", clientConf)
	if err != nil {
		c1.Close()
		c2.Close()
		t.Fatalf("client handshake: %v", err)
	}
	f.client = ssh.NewClient(conn, chans, reqs)

	t.Cleanup(func() {
		if f.client != nil {
			f.client.Close()
		}
		// c1 is closed by the server goroutine on exit; c2 is closed by
		// f.client.Close(). Closing again is safe (idempotent).
		c1.Close()
	})

	return f
}

// capturedRequest returns a copy of the Request passed to the backend hook,
// or nil if the backend was not called. Safe to call after backendCalled is
// closed.
func (f *sessionFixture) capturedRequest() *Request {
	f.capturedMu.Lock()
	defer f.capturedMu.Unlock()
	return f.captured
}

// backendCallCount returns the number of times the backend hook was invoked.
func (f *sessionFixture) backendCallCount() int {
	f.capturedMu.Lock()
	defer f.capturedMu.Unlock()
	return f.called
}

// gitPerms returns a git permission for the given fingerprint, suitable for
// passing to NoClientAuthCallback via the fixture.
func gitPerms(fp string) *ssh.Permissions {
	return permissionsForFingerprint(fp)
}

// --- Happy path --------------------------------------------------------------

// TestHandleSessionHappyPath verifies the successful end-to-end Git session:
// the client sends GIT_PROTOCOL=version=2 env, then exec git-upload-pack
// 'project.git'. The backend hook is called with the parsed/authorized
// Request (Command, Operation, RepoPath, BackendPath) and the protocol value.
// The client's Run returns nil (exit-status 0).
func TestHandleSessionHappyPath(t *testing.T) {
	t.Parallel()

	repos := []RepositoryConfig{{
		Path:        "project.git",
		BackendPath: "project.git",
		ReadKeys:    []string{"SHA256:testkey"},
	}}
	f := newSessionFixture(t, repos, gitPerms("SHA256:testkey"))

	sess, err := f.client.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	require.NoError(t, sess.Setenv("GIT_PROTOCOL", "version=2"))

	// Release the backend as soon as it is called so Run can finish.
	go func() {
		<-f.backendCalled
		close(f.backendRelease)
	}()

	require.NoError(t, sess.Run("git-upload-pack 'project.git'"))

	// Assert the backend received the authorized request.
	req := f.capturedRequest()
	require.NotNil(t, req, "backend must be called")
	assert.Equal(t, "git-upload-pack", req.Command)
	assert.Equal(t, OperationRead, req.Operation)
	assert.Equal(t, "project.git", req.RepoPath)
	assert.Equal(t, "project.git", req.BackendPath)

	f.capturedMu.Lock()
	assert.Equal(t, "version=2", f.protocol, "GIT_PROTOCOL must be propagated")
	f.capturedMu.Unlock()

	select {
	case err := <-f.serverErr:
		assert.NoError(t, err, "HandleSession should return nil on success")
	case <-time.After(2 * time.Second):
		t.Fatal("HandleSession did not return in time")
	}
}

// TestHandleSessionIdleBeforeExecTimesOut verifies an authenticated git client
// cannot open a session channel and then sit idle forever before sending exec.
// This protects the success-connection slots while still leaving long-running
// transfers unbounded after exec has been accepted.
func TestHandleSessionIdleBeforeExecTimesOut(t *testing.T) {
	repos := []RepositoryConfig{{
		Path:     "project.git",
		ReadKeys: []string{"SHA256:testkey"},
	}}
	f := newSessionFixture(t, repos, gitPerms("SHA256:testkey"))
	f.srv.preExecTimeout = 50 * time.Millisecond

	sess, err := f.client.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	select {
	case err := <-f.serverErr:
		require.ErrorIs(t, err, errPreExecTimeout)
		assert.Equal(t, 0, f.backendCallCount(), "backend must not run without an exec request")
	case <-time.After(2 * time.Second):
		t.Fatal("HandleSession did not time out while waiting for pre-exec request")
	}
}

// --- Unsupported first requests ---------------------------------------------

// TestHandleSessionRejectsPtyReq verifies that a pty-req as the first session
// request is rejected and the session tears down with a server error. The
// client should observe the pty-req failure.
func TestHandleSessionRejectsPtyReq(t *testing.T) {
	t.Parallel()

	repos := []RepositoryConfig{{Path: "project.git", ReadKeys: []string{"SHA256:testkey"}}}
	f := newSessionFixture(t, repos, gitPerms("SHA256:testkey"))

	sess, err := f.client.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	err = sess.RequestPty("xterm", 80, 40, ssh.TerminalModes{})
	assert.Error(t, err, "pty-req must be rejected")

	// Backend must never be called.
	close(f.backendRelease) // in case the server somehow reaches backend
	assert.Equal(t, 0, f.backendCallCount(), "backend must not be called for pty-req")

	select {
	case serverErr := <-f.serverErr:
		require.Error(t, serverErr, "HandleSession must return error on unsupported first request")
		assert.ErrorIs(t, serverErr, errUnsupportedRequest)
	case <-time.After(2 * time.Second):
		t.Fatal("HandleSession did not return after pty-req")
	}
}

// TestHandleSessionRejectsShell verifies that a bare shell request as the
// first session request is rejected.
func TestHandleSessionRejectsShell(t *testing.T) {
	t.Parallel()

	repos := []RepositoryConfig{{Path: "project.git", ReadKeys: []string{"SHA256:testkey"}}}
	f := newSessionFixture(t, repos, gitPerms("SHA256:testkey"))

	sess, err := f.client.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	err = sess.Shell()
	assert.Error(t, err, "shell must be rejected")

	close(f.backendRelease)
	assert.Equal(t, 0, f.backendCallCount(), "backend must not be called for shell")

	select {
	case serverErr := <-f.serverErr:
		require.Error(t, serverErr)
		assert.ErrorIs(t, serverErr, errUnsupportedRequest)
	case <-time.After(2 * time.Second):
		t.Fatal("HandleSession did not return after shell")
	}
}

// TestHandleSessionRejectsSubsystem verifies that a subsystem request as the
// first session request is rejected.
func TestHandleSessionRejectsSubsystem(t *testing.T) {
	t.Parallel()

	repos := []RepositoryConfig{{Path: "project.git", ReadKeys: []string{"SHA256:testkey"}}}
	f := newSessionFixture(t, repos, gitPerms("SHA256:testkey"))

	sess, err := f.client.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	err = sess.RequestSubsystem("sftp")
	assert.Error(t, err, "subsystem must be rejected")

	close(f.backendRelease)
	assert.Equal(t, 0, f.backendCallCount(), "backend must not be called for subsystem")

	select {
	case serverErr := <-f.serverErr:
		require.Error(t, serverErr)
		assert.ErrorIs(t, serverErr, errUnsupportedRequest)
	case <-time.After(2 * time.Second):
		t.Fatal("HandleSession did not return after subsystem")
	}
}

// TestHandleSessionRejectsUnsupportedEnv verifies that an env request setting
// anything other than GIT_PROTOCOL=version=2 is rejected and the session
// tears down.
func TestHandleSessionRejectsUnsupportedEnv(t *testing.T) {
	t.Parallel()

	repos := []RepositoryConfig{{Path: "project.git", ReadKeys: []string{"SHA256:testkey"}}}
	f := newSessionFixture(t, repos, gitPerms("SHA256:testkey"))

	sess, err := f.client.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	err = sess.Setenv("LD_PRELOAD", "/evil/lib.so")
	assert.Error(t, err, "LD_PRELOAD env must be rejected")

	close(f.backendRelease)
	assert.Equal(t, 0, f.backendCallCount(), "backend must not be called for unsupported env")

	select {
	case serverErr := <-f.serverErr:
		require.Error(t, serverErr)
		assert.ErrorIs(t, serverErr, errUnsupportedEnv)
	case <-time.After(2 * time.Second):
		t.Fatal("HandleSession did not return after unsupported env")
	}
}

// TestHandleSessionRejectsWrongGitProtocolValue verifies that an env request
// setting GIT_PROTOCOL to a value other than "version=2" is rejected.
func TestHandleSessionRejectsWrongGitProtocolValue(t *testing.T) {
	t.Parallel()

	repos := []RepositoryConfig{{Path: "project.git", ReadKeys: []string{"SHA256:testkey"}}}
	f := newSessionFixture(t, repos, gitPerms("SHA256:testkey"))

	sess, err := f.client.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	err = sess.Setenv("GIT_PROTOCOL", "evil")
	assert.Error(t, err, "GIT_PROTOCOL=evil must be rejected")

	close(f.backendRelease)
	assert.Equal(t, 0, f.backendCallCount())

	select {
	case serverErr := <-f.serverErr:
		require.Error(t, serverErr)
		assert.ErrorIs(t, serverErr, errUnsupportedEnv)
	case <-time.After(2 * time.Second):
		t.Fatal("HandleSession did not return after bad GIT_PROTOCOL value")
	}
}

// TestHandleSessionRejectsSecondEnv verifies that a second env request (after
// a valid GIT_PROTOCOL env) is rejected.
func TestHandleSessionRejectsSecondEnv(t *testing.T) {
	t.Parallel()

	repos := []RepositoryConfig{{Path: "project.git", ReadKeys: []string{"SHA256:testkey"}}}
	f := newSessionFixture(t, repos, gitPerms("SHA256:testkey"))

	sess, err := f.client.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	require.NoError(t, sess.Setenv("GIT_PROTOCOL", "version=2"))

	// A second env request must be rejected. Use SendRequest so we can
	// observe the false reply directly rather than via Setenv's error
	// (which is the same, but be explicit).
	msg := gitEnvMsg{Name: "GIT_PROTOCOL", Value: "version=2"}
	ok, err := sess.SendRequest("env", true, ssh.Marshal(&msg))
	require.NoError(t, err)
	assert.False(t, ok, "second env request must be replied false")

	close(f.backendRelease)
	assert.Equal(t, 0, f.backendCallCount(), "backend must not be called when second env fails")

	select {
	case serverErr := <-f.serverErr:
		require.Error(t, serverErr)
		assert.ErrorIs(t, serverErr, errSecondEnv)
	case <-time.After(2 * time.Second):
		t.Fatal("HandleSession did not return after second env")
	}
}

// --- Repeated exec ----------------------------------------------------------

// TestHandleSessionRejectsSecondExec verifies that a second exec request,
// sent while the backend is still running the first, is replied false and
// does not start a second backend. The backend is called exactly once.
func TestHandleSessionRejectsSecondExec(t *testing.T) {
	t.Parallel()

	repos := []RepositoryConfig{{Path: "project.git", ReadKeys: []string{"SHA256:testkey"}}}
	f := newSessionFixture(t, repos, gitPerms("SHA256:testkey"))

	sess, err := f.client.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	// Start the command (non-blocking): this sends the first exec and
	// blocks in the backend on backendRelease.
	require.NoError(t, sess.Start("git-upload-pack 'project.git'"))

	// Wait until the backend is actually running so the second exec
	// arrives during the backend phase.
	select {
	case <-f.backendCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("backend was not called in time")
	}

	// Send a second exec via SendRequest (Session.Start would error with
	// "session already started" before sending, so we bypass it). The
	// server should reply false.
	msg := gitExecMsg{Command: "git-receive-pack 'project.git'"}
	ok, err := sess.SendRequest("exec", true, ssh.Marshal(&msg))
	require.NoError(t, err, "SendRequest exec must not return transport error")
	assert.False(t, ok, "second exec must be replied false")

	// Release the first backend so the session can finish.
	close(f.backendRelease)

	// The first command should complete cleanly.
	require.NoError(t, sess.Wait(), "first exec should finish with nil (exit 0)")

	// Exactly one backend call.
	assert.Equal(t, 1, f.backendCallCount(), "backend must be called exactly once")

	// The captured request is the first exec, not the second.
	req := f.capturedRequest()
	require.NotNil(t, req)
	assert.Equal(t, "git-upload-pack", req.Command, "first exec command must be the one dispatched")

	select {
	case serverErr := <-f.serverErr:
		assert.NoError(t, serverErr)
	case <-time.After(2 * time.Second):
		t.Fatal("HandleSession did not return in time")
	}
}

// --- Context cancellation ----------------------------------------------------

// TestHandleSessionContextCancel verifies that cancelling the context passed
// to HandleSession while the backend is running causes HandleSession to
// return promptly (within 1s) with ctx.Err().
func TestHandleSessionContextCancel(t *testing.T) {
	t.Parallel()

	repos := []RepositoryConfig{{Path: "project.git", ReadKeys: []string{"SHA256:testkey"}}}

	// We can't use newSessionFixture directly because it passes
	// context.Background() to HandleSession. Rebuild a minimal fixture
	// with a cancellable context.

	srv := newTestServer(t, &Config{
		Enable:       true,
		Repositories: repos,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverErr := make(chan error, 1)
	backendCalled := make(chan struct{})

	srv.runBackend = func(bctx context.Context, s *Server, req Request, gitProtocol string, channel ssh.Channel) error {
		close(backendCalled)
		<-bctx.Done()
		return bctx.Err()
	}

	perms := gitPerms("SHA256:testkey")

	c1, c2 := sshPipeConns(t)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostSigner, err := ssh.NewSignerFromSigner(priv)
	require.NoError(t, err)

	serverConf := &ssh.ServerConfig{
		NoClientAuth: true,
		NoClientAuthCallback: func(conn ssh.ConnMetadata) (*ssh.Permissions, error) {
			return perms, nil
		},
	}
	serverConf.AddHostKey(hostSigner)

	go func() {
		conn, chans, reqs, err := ssh.NewServerConn(c1, serverConf)
		if err != nil {
			serverErr <- err
			return
		}
		go ssh.DiscardRequests(reqs)
		for newCh := range chans {
			if newCh.ChannelType() != "session" {
				newCh.Reject(ssh.UnknownChannelType, "unknown channel type")
				continue
			}
			channel, inReqs, err := newCh.Accept()
			if err != nil {
				continue
			}
			serverErr <- srv.HandleSession(ctx, conn.Permissions, channel, inReqs)
			_ = conn.Close()
			return
		}
		_ = conn.Close()
		serverErr <- errors.New("no session channel")
	}()

	clientConf := &ssh.ClientConfig{
		User:            "git",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	conn, chans, reqs, err := ssh.NewClientConn(c2, "", clientConf)
	require.NoError(t, err)
	client := ssh.NewClient(conn, chans, reqs)
	defer client.Close()

	sess, err := client.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	// Start the exec so the backend goroutine runs and blocks on ctx.
	require.NoError(t, sess.Start("git-upload-pack 'project.git'"))

	select {
	case <-backendCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("backend not called in time")
	}

	// Cancel the context and assert HandleSession returns within 1s.
	start := time.Now()
	cancel()
	select {
	case err := <-serverErr:
		elapsed := time.Since(start)
		assert.Less(t, elapsed, time.Second, "HandleSession should return within 1s of cancel")
		require.Error(t, err, "HandleSession should return ctx.Err() on cancel")
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("HandleSession did not return after cancel")
	}
}

// --- Malformed / unauthorized exec ------------------------------------------

// TestHandleSessionRejectsMalformedExec verifies that an exec with an
// unparseable command is replied false, the backend is not called, and
// HandleSession returns an error.
func TestHandleSessionRejectsMalformedExec(t *testing.T) {
	t.Parallel()

	repos := []RepositoryConfig{{Path: "project.git", ReadKeys: []string{"SHA256:testkey"}}}
	f := newSessionFixture(t, repos, gitPerms("SHA256:testkey"))

	sess, err := f.client.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	// A foreign command that ParseGitCommand rejects.
	err = sess.Run("rm -rf /")
	require.Error(t, err, "malformed exec must be rejected")

	close(f.backendRelease)
	assert.Equal(t, 0, f.backendCallCount(), "backend must not be called for malformed exec")

	select {
	case serverErr := <-f.serverErr:
		require.Error(t, serverErr)
	case <-time.After(2 * time.Second):
		t.Fatal("HandleSession did not return after malformed exec")
	}
}

// TestHandleSessionRejectsUnauthorizedExec verifies that an exec for a repo
// the key is not authorized for is replied false, the backend is not called,
// and HandleSession returns an error.
func TestHandleSessionRejectsUnauthorizedExec(t *testing.T) {
	t.Parallel()

	// repo is configured but the key has neither read nor write access.
	repos := []RepositoryConfig{{Path: "project.git", ReadKeys: []string{"SHA256:other"}}}
	f := newSessionFixture(t, repos, gitPerms("SHA256:testkey"))

	sess, err := f.client.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	err = sess.Run("git-upload-pack 'project.git'")
	require.Error(t, err, "unauthorized exec must be rejected")

	close(f.backendRelease)
	assert.Equal(t, 0, f.backendCallCount(), "backend must not be called for unauthorized exec")

	select {
	case serverErr := <-f.serverErr:
		require.Error(t, serverErr)
	case <-time.After(2 * time.Second):
		t.Fatal("HandleSession did not return after unauthorized exec")
	}
}

// TestHandleSessionRejectsUnknownRepoExec verifies that an exec for a repo
// not present in the config is rejected.
func TestHandleSessionRejectsUnknownRepoExec(t *testing.T) {
	t.Parallel()

	repos := []RepositoryConfig{{Path: "project.git", ReadKeys: []string{"SHA256:testkey"}}}
	f := newSessionFixture(t, repos, gitPerms("SHA256:testkey"))

	sess, err := f.client.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	err = sess.Run("git-upload-pack 'other.git'")
	require.Error(t, err, "unknown repo exec must be rejected")

	close(f.backendRelease)
	assert.Equal(t, 0, f.backendCallCount(), "backend must not be called for unknown repo exec")

	select {
	case serverErr := <-f.serverErr:
		require.Error(t, serverErr)
	case <-time.After(2 * time.Second):
		t.Fatal("HandleSession did not return after unknown repo exec")
	}
}

// --- Non-git permission fail-closed -----------------------------------------

// TestHandleSessionRejectsNonGitPermission verifies that HandleSession
// fail-closes when called with perms that are not a git permission. This
// should not happen in production (the router checks IsGitPermission first)
// but HandleSession defends itself.
func TestHandleSessionRejectsNonGitPermission(t *testing.T) {
	t.Parallel()

	repos := []RepositoryConfig{{Path: "project.git", ReadKeys: []string{"SHA256:testkey"}}}
	// perms with no gitserver marker
	barePerms := &ssh.Permissions{Extensions: map[string]string{}}
	f := newSessionFixture(t, repos, barePerms)

	// Open a session so the server-side Accept -> HandleSession path runs.
	// HandleSession fail-closes immediately on non-git perms and returns
	// errNotGitPermission before any request is processed.
	sess, err := f.client.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	close(f.backendRelease)

	select {
	case serverErr := <-f.serverErr:
		require.Error(t, serverErr)
		assert.ErrorIs(t, serverErr, errNotGitPermission)
	case <-time.After(2 * time.Second):
		t.Fatal("HandleSession did not return after non-git perms")
	}
	assert.Equal(t, 0, f.backendCallCount(), "backend must not be called for non-git perms")
}

// --- Backend error -> exit-status 1 -----------------------------------------

// TestHandleSessionBackendErrorReturnsExit1 verifies that when the backend
// returns a non-nil error, the client observes a non-zero exit status (Run
// returns *ssh.ExitError) and HandleSession returns the backend error.
func TestHandleSessionBackendErrorReturnsExit1(t *testing.T) {
	t.Parallel()

	repos := []RepositoryConfig{{Path: "project.git", ReadKeys: []string{"SHA256:testkey"}}}
	f := newSessionFixture(t, repos, gitPerms("SHA256:testkey"))
	f.backendErr = errors.New("backend boom")

	sess, err := f.client.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	go func() {
		<-f.backendCalled
		close(f.backendRelease)
	}()

	err = sess.Run("git-upload-pack 'project.git'")
	require.Error(t, err, "Run should return non-nil when backend errors")

	// The client should see a non-zero exit status.
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		assert.NotEqual(t, 0, exitErr.ExitStatus(), "exit status should be non-zero")
	} else {
		// Some error paths return ExitMissingError if the channel closed
		// before exit-status; that still counts as "client saw failure".
		t.Logf("Run returned non-ExitError (acceptable): %T %v", err, err)
	}

	select {
	case serverErr := <-f.serverErr:
		require.Error(t, serverErr, "HandleSession should return backend error")
		assert.Equal(t, "backend boom", serverErr.Error())
	case <-time.After(2 * time.Second):
		t.Fatal("HandleSession did not return in time")
	}
}

// --- Drain / keepalive during backend ---------------------------------------

// TestHandleSessionDrainsRequestsDuringBackend verifies that while the
// backend is running, additional channel requests (window-change, signal)
// are drained and replied false without interrupting the session. The
// backend completes normally and the session finishes with exit 0.
func TestHandleSessionDrainsRequestsDuringBackend(t *testing.T) {
	t.Parallel()

	repos := []RepositoryConfig{{Path: "project.git", ReadKeys: []string{"SHA256:testkey"}}}
	f := newSessionFixture(t, repos, gitPerms("SHA256:testkey"))

	sess, err := f.client.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	require.NoError(t, sess.Start("git-upload-pack 'project.git'"))

	select {
	case <-f.backendCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("backend not called in time")
	}

	// Send a window-change (no reply expected) and a signal (no reply
	// expected). These should be drained harmlessly.
	require.NoError(t, sess.WindowChange(100, 50))
	require.NoError(t, sess.Signal(ssh.SIGINT))

	// Release the backend.
	close(f.backendRelease)

	require.NoError(t, sess.Wait(), "session should finish cleanly after drain")

	select {
	case serverErr := <-f.serverErr:
		assert.NoError(t, serverErr)
	case <-time.After(2 * time.Second):
		t.Fatal("HandleSession did not return in time")
	}
}

// --- EOF on channel without exec --------------------------------------------

// TestHandleSessionRequestStreamClosedBeforeExec verifies that if the client
// closes the session before sending exec, HandleSession returns
// errRequestStreamClosed.
func TestHandleSessionRequestStreamClosedBeforeExec(t *testing.T) {
	t.Parallel()

	repos := []RepositoryConfig{{Path: "project.git", ReadKeys: []string{"SHA256:testkey"}}}
	f := newSessionFixture(t, repos, gitPerms("SHA256:testkey"))

	sess, err := f.client.NewSession()
	require.NoError(t, err)
	// Close immediately without sending exec. The request stream closes.
	require.NoError(t, sess.Close())

	close(f.backendRelease)

	select {
	case serverErr := <-f.serverErr:
		require.Error(t, serverErr)
		// Could be errRequestStreamClosed or a transport error depending
		// on timing; just assert non-nil.
	case <-time.After(2 * time.Second):
		t.Fatal("HandleSession did not return after stream closed")
	}
	assert.Equal(t, 0, f.backendCallCount(), "backend must not be called when stream closes before exec")
}
