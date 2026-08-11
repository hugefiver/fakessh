//go:build !no_gitserver
// +build !no_gitserver

package gitserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hugefiver/fakessh/third/ssh"
	"github.com/hugefiver/fakessh/third/ssh/knownhosts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- buildBackendCommand tests ------------------------------------------------

// TestBuildBackendCommandNormal verifies that buildBackendCommand returns
// "<Command> '<BackendPath>'" using the config-resolved BackendPath.
func TestBuildBackendCommandNormal(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, &Config{
		Enable:  true,
		Backend: BackendSSH,
		SSHBackend: SSHBackendConfig{
			Address:    "127.0.0.1:2222",
			User:       "git",
			KeyFile:    "/dev/null",
			KnownHosts: "/dev/null",
		},
		Repositories: []RepositoryConfig{{
			Path:        "project.git",
			BackendPath: "backend/project.git",
			ReadKeys:    []string{"SHA256:k"},
		}},
	})

	req := Request{
		Command:     "git-upload-pack",
		Operation:   OperationRead,
		RepoPath:    "project.git",
		BackendPath: "backend/project.git",
	}

	cmd, err := srv.buildBackendCommand(req)
	require.NoError(t, err)
	assert.Equal(t, "git-upload-pack 'backend/project.git'", cmd)
}

// TestBuildBackendCommandFallbackToRepoPath verifies that when BackendPath is
// empty, the command uses the normalized RepoPath. This path only happens when
// Authorize was bypassed (e.g. direct test construction).
func TestBuildBackendCommandFallbackToRepoPath(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, &Config{
		Enable:  true,
		Backend: BackendSSH,
		SSHBackend: SSHBackendConfig{
			Address:    "127.0.0.1:2222",
			User:       "git",
			KeyFile:    "/dev/null",
			KnownHosts: "/dev/null",
		},
	})

	req := Request{
		Command:   "git-receive-pack",
		Operation: OperationWrite,
		RepoPath:  "team/widget.git",
		// BackendPath intentionally empty
	}

	cmd, err := srv.buildBackendCommand(req)
	require.NoError(t, err)
	assert.Equal(t, "git-receive-pack 'team/widget.git'", cmd)
}

// TestBuildBackendCommandStripsLeadingSlash verifies that a BackendPath with a
// leading slash is normalized (slash stripped) before being embedded.
func TestBuildBackendCommandStripsLeadingSlash(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, &Config{
		Enable:  true,
		Backend: BackendSSH,
		SSHBackend: SSHBackendConfig{
			Address:    "127.0.0.1:2222",
			User:       "git",
			KeyFile:    "/dev/null",
			KnownHosts: "/dev/null",
		},
	})

	req := Request{
		Command:     "git-upload-pack",
		Operation:   OperationRead,
		RepoPath:    "team/widget.git",
		BackendPath: "/team/widget.git",
	}

	cmd, err := srv.buildBackendCommand(req)
	require.NoError(t, err)
	assert.Equal(t, "git-upload-pack 'team/widget.git'", cmd)
}

// TestBuildBackendCommandRejectsTraversal verifies that buildBackendCommand
// rejects backend paths containing traversal segments even if they arrived
// from a misbehaving Authorize path.
func TestBuildBackendCommandRejectsTraversal(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, &Config{
		Enable:  true,
		Backend: BackendSSH,
		SSHBackend: SSHBackendConfig{
			Address:    "127.0.0.1:2222",
			User:       "git",
			KeyFile:    "/dev/null",
			KnownHosts: "/dev/null",
		},
	})

	for _, bad := range []string{
		"../secret.git",
		"team/../../secret.git",
		"team/../secret.git",
		"team/..",
		"..",
	} {
		req := Request{
			Command:     "git-upload-pack",
			Operation:   OperationRead,
			RepoPath:    "team/widget.git",
			BackendPath: bad,
		}
		_, err := srv.buildBackendCommand(req)
		assert.Error(t, err, "buildBackendCommand must reject traversal path %q", bad)
	}
}

// TestBuildBackendCommandRejectsInvalidCommand verifies that buildBackendCommand
// fails closed when req.Command is not from the whitelisted set. This guards
// against a future caller that bypasses ParseGitCommand.
func TestBuildBackendCommandRejectsInvalidCommand(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, &Config{
		Enable:  true,
		Backend: BackendSSH,
		SSHBackend: SSHBackendConfig{
			Address:    "127.0.0.1:2222",
			User:       "git",
			KeyFile:    "/dev/null",
			KnownHosts: "/dev/null",
		},
	})

	req := Request{
		Command:     "rm -rf /",
		Operation:   OperationRead,
		RepoPath:    "team/widget.git",
		BackendPath: "team/widget.git",
	}

	_, err := srv.buildBackendCommand(req)
	assert.Error(t, err, "buildBackendCommand must reject non-whitelisted command")
}

// TestBuildBackendCommandRejectsBackslash verifies that backslashes in the
// backend path are rejected by NormalizeRepoPath.
func TestBuildBackendCommandRejectsBackslash(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, &Config{
		Enable:  true,
		Backend: BackendSSH,
		SSHBackend: SSHBackendConfig{
			Address:    "127.0.0.1:2222",
			User:       "git",
			KeyFile:    "/dev/null",
			KnownHosts: "/dev/null",
		},
	})

	req := Request{
		Command:     "git-upload-pack",
		Operation:   OperationRead,
		RepoPath:    "team/widget.git",
		BackendPath: `team\widget.git`,
	}

	_, err := srv.buildBackendCommand(req)
	assert.Error(t, err, "buildBackendCommand must reject backslash in BackendPath")
}

// --- serveSSH error tests -----------------------------------------------------

// writePrivateKeyFile writes a PEM-encoded ed25519 private key to a temp file
// and returns the file path and the corresponding ssh.Signer.
func writePrivateKeyFile(t *testing.T) (string, ssh.Signer) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromSigner(priv)
	require.NoError(t, err)

	p := writeKeyFile(t, priv)
	return p, signer
}

// writeKeyFile writes a PEM-encoded ed25519 private key to a temp file and
// returns its path.
func writeKeyFile(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pem.Encode(&buf, block))
	p := filepath.Join(t.TempDir(), "id_ed25519")
	require.NoError(t, os.WriteFile(p, buf.Bytes(), 0600))
	return p
}

// TestServeSSHMissingKeyFileReturnsError verifies that serveSSH returns an
// error when the configured KeyFile does not exist.
func TestServeSSHMissingKeyFileReturnsError(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, &Config{
		Enable:  true,
		Backend: BackendSSH,
		SSHBackend: SSHBackendConfig{
			Address:    "127.0.0.1:2222",
			User:       "git",
			KeyFile:    filepath.Join(t.TempDir(), "does-not-exist"),
			KnownHosts: "/dev/null",
		},
	})

	req := Request{
		Command:     "git-upload-pack",
		Operation:   OperationRead,
		RepoPath:    "project.git",
		BackendPath: "project.git",
	}

	err := srv.serveSSH(context.Background(), req, "", nil)
	assert.Error(t, err, "serveSSH must return an error when KeyFile is missing")
}

// TestServeSSHInvalidKeyReturnsError verifies that serveSSH returns an error
// when the configured KeyFile does not contain a parseable private key.
func TestServeSSHInvalidKeyReturnsError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := filepath.Join(dir, "key")
	require.NoError(t, os.WriteFile(p, []byte("not a private key"), 0600))

	srv := newTestServer(t, &Config{
		Enable:  true,
		Backend: BackendSSH,
		SSHBackend: SSHBackendConfig{
			Address:    "127.0.0.1:2222",
			User:       "git",
			KeyFile:    p,
			KnownHosts: "/dev/null",
		},
	})

	req := Request{
		Command:     "git-upload-pack",
		Operation:   OperationRead,
		RepoPath:    "project.git",
		BackendPath: "project.git",
	}

	err := srv.serveSSH(context.Background(), req, "", nil)
	assert.Error(t, err, "serveSSH must return an error when KeyFile is not a valid key")
}

// TestServeSSHInvalidKnownHostsReturnsError verifies that serveSSH returns
// an error when the configured known_hosts file does not exist.
func TestServeSSHInvalidKnownHostsReturnsError(t *testing.T) {
	t.Parallel()

	keyPath, _ := writePrivateKeyFile(t)

	srv := newTestServer(t, &Config{
		Enable:  true,
		Backend: BackendSSH,
		SSHBackend: SSHBackendConfig{
			Address:    "127.0.0.1:2222",
			User:       "git",
			KeyFile:    keyPath,
			KnownHosts: filepath.Join(t.TempDir(), "no-such-known-hosts"),
		},
	})

	req := Request{
		Command:     "git-upload-pack",
		Operation:   OperationRead,
		RepoPath:    "project.git",
		BackendPath: "project.git",
	}

	err := srv.serveSSH(context.Background(), req, "", nil)
	assert.Error(t, err, "serveSSH must return an error when known_hosts is missing")
}

// --- serveSSH in-process backend server test ---------------------------------

// fakeFrontendChannel is a minimal ssh.Channel implementation that buffers
// stdout and stderr in memory. It is used to drive serveSSH directly without
// standing up a full frontend SSH server. Reads pull from the in buffer; writes
// go to out or err.
//
// When the in buffer is empty, Read returns io.EOF immediately so the client's
// stdin copy goroutine drains the buffer once and then signals EOF to the
// backend via CloseWrite. This mimics a real ssh.Channel whose peer has
// nothing more to send.
type fakeFrontendChannel struct {
	in   *bytes.Buffer
	out  bytes.Buffer
	errw bytes.Buffer
}

func newFakeFrontendChannel(input []byte) *fakeFrontendChannel {
	return &fakeFrontendChannel{in: bytes.NewBuffer(input)}
}

func (c *fakeFrontendChannel) Read(p []byte) (int, error) {
	if c.in.Len() == 0 {
		return 0, io.EOF
	}
	return c.in.Read(p)
}

func (c *fakeFrontendChannel) Write(p []byte) (int, error) { return c.out.Write(p) }
func (c *fakeFrontendChannel) Close() error                { return nil }
func (c *fakeFrontendChannel) CloseWrite() error           { return nil }
func (c *fakeFrontendChannel) SendRequest(string, bool, []byte) (bool, error) {
	return false, nil
}
func (c *fakeFrontendChannel) Stderr() io.ReadWriter { return &c.errw }

// _ is a compile-time anchor so the ssh.Channel interface is satisfied.
var _ ssh.Channel = (*fakeFrontendChannel)(nil)

// backendProbe is the data captured by the in-process SSH backend server
// during a serveSSH test.
type backendProbe struct {
	mu       sync.Mutex
	user     string
	command  string
	env      map[string]string
	stdinBuf bytes.Buffer
	exitCode uint32
}

// startInProcessSSHBackend starts a loopback SSH server that accepts a single
// connection, authenticates the given user with any public key (NoClientAuth
// is false; we use PublicKeyCallback that accepts the specific signer), and
// on the first session channel: captures env requests, runs an exec that
// echoes a fixed string on stdout and stderr, copies stdin to a buffer, and
// sends exit-status 0.
//
// The server returns its listener address so the test can configure the
// gitserver client. The host key is added to the provided known_hosts path.
func startInProcessSSHBackend(t *testing.T, knownHostsPath string) (addr string, probe *backendProbe) {
	t.Helper()

	probe = &backendProbe{env: map[string]string{}}

	// Generate a host key for the backend server.
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostSigner, err := ssh.NewSignerFromSigner(hostPriv)
	require.NoError(t, err)

	serverConf := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			probe.mu.Lock()
			probe.user = conn.User()
			probe.mu.Unlock()
			return &ssh.Permissions{}, nil
		},
	}
	serverConf.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	addr = ln.Addr().String()

	// Write the known_hosts entry for this host key, using the full address
	// (host:port) so the client's HostKeyCallback matches on the actual port.
	khLine := knownhosts.Line([]string{addr}, hostSigner.PublicKey()) + "\n"
	require.NoError(t, os.WriteFile(knownHostsPath, []byte(khLine), 0600))

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				sc, chans, reqs, err := ssh.NewServerConn(c, serverConf)
				if err != nil {
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)

				for newCh := range chans {
					if newCh.ChannelType() != "session" {
						newCh.Reject(ssh.UnknownChannelType, "only session")
						continue
					}
					ch, inReqs, err := newCh.Accept()
					if err != nil {
						return
					}

					go handleBackendSession(ch, inReqs, probe)
				}
			}(conn)
		}
	}()

	return addr, probe
}

// handleBackendSession is the in-process backend's session handler: it
// captures env requests, waits for exec, echoes fixed strings on
// stdout/stderr, copies stdin into the probe buffer, and sends exit-status.
// After sending exit-status it closes the write side of the channel (so the
// client observes EOF on stdout) and waits for the client to finish writing
// stdin before the deferred Close tears down the channel.
func handleBackendSession(ch ssh.Channel, reqs <-chan *ssh.Request, probe *backendProbe) {
	defer ch.Close()

	// Copy stdin into the probe buffer until the client signals EOF
	// (CloseWrite on the client side). This runs in parallel with request
	// processing so we capture all stdin bytes even if the exec finishes
	// quickly.
	stdinDone := make(chan struct{})
	go func() {
		io.Copy(&probe.stdinBuf, ch)
		close(stdinDone)
	}()

	for req := range reqs {
		switch req.Type {
		case "env":
			var msg struct {
				Name  string
				Value string
			}
			if err := ssh.Unmarshal(req.Payload, &msg); err == nil {
				probe.mu.Lock()
				probe.env[msg.Name] = msg.Value
				probe.mu.Unlock()
			}
			req.Reply(true, nil)
		case "exec":
			var msg struct {
				Command string
			}
			if err := ssh.Unmarshal(req.Payload, &msg); err == nil {
				probe.mu.Lock()
				probe.command = msg.Command
				probe.mu.Unlock()
			}
			req.Reply(true, nil)

			// Write the fixed strings on stdout/stderr so the test can
			// assert the wire is connected.
			io.WriteString(ch, "backend-stdout-ok")
			io.WriteString(ch.Stderr(), "backend-stderr-ok")

			// Send exit-status 0.
			probe.mu.Lock()
			code := probe.exitCode
			probe.mu.Unlock()
			payload := make([]byte, 4)
			payload[0] = byte(code >> 24)
			payload[1] = byte(code >> 16)
			payload[2] = byte(code >> 8)
			payload[3] = byte(code)
			ch.SendRequest("exit-status", false, payload)

			// Signal EOF on stdout without tearing down the channel, so the
			// client can finish writing stdin and observe the exit-status.
			_ = ch.CloseWrite()

			// Wait for the client to finish writing stdin before tearing
			// down the channel. This ensures the probe buffer is fully
			// populated when the test inspects it.
			<-stdinDone
			return
		default:
			req.Reply(false, nil)
		}
	}
}

// TestServeSSHUsesFixedBackendConfigAndGitProtocol is the main end-to-end test
// for the SSH backend. It:
//
//   - starts an in-process SSH backend on loopback with a generated host key;
//   - generates a temp private key and a temp known_hosts pinning the backend
//     host key;
//   - configures a gitserver Server with Backend=BackendSSH pointing at the
//     fixed backend address and user;
//   - drives serveSSH directly with a fakeFrontendChannel carrying stdin
//     payload;
//   - asserts the backend sees the fixed user, the whitelisted command
//     "git-upload-pack 'backend/project.git'", the optional
//     GIT_PROTOCOL=version=2 env, and the stdin bytes; and
//   - asserts the frontend channel receives the backend's stdout/stderr.
//
// The test also verifies that the request's RepoPath cannot influence the
// backend address/user/key: only the config-resolved SSHBackend fields are
// used.
func TestServeSSHUsesFixedBackendConfigAndGitProtocol(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	knownHostsPath := filepath.Join(dir, "known_hosts")

	addr, probe := startInProcessSSHBackend(t, knownHostsPath)

	// Generate a client private key for the gitserver->backend connection.
	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	clientKeyPath := writeKeyFile(t, clientPriv)

	// Configure the gitserver to use the fixed backend.
	cfg := &Config{
		Enable:  true,
		Backend: BackendSSH,
		SSHBackend: SSHBackendConfig{
			Address:        addr,
			User:           "fixed-backend-user",
			KeyFile:        clientKeyPath,
			KnownHosts:     knownHostsPath,
			TimeoutSeconds: 5,
		},
		Repositories: []RepositoryConfig{{
			Path:        "project.git",
			BackendPath: "backend/project.git",
			ReadKeys:    []string{"SHA256:testkey"},
		}},
	}
	srv := newTestServer(t, cfg)

	// Sanity: the address in config is what the server will dial, not the
	// request's RepoPath. We assert this after the call by checking probe.
	req := Request{
		Command:     "git-upload-pack",
		Operation:   OperationRead,
		RepoPath:    "project.git",
		BackendPath: "backend/project.git",
	}

	// Drive serveSSH with a fake frontend channel carrying stdin bytes.
	stdinPayload := []byte("pull-payload-from-client\n")
	ch := newFakeFrontendChannel(stdinPayload)

	done := make(chan error, 1)
	go func() {
		done <- srv.serveSSH(context.Background(), req, "version=2", ch)
	}()

	select {
	case err := <-done:
		require.NoError(t, err, "serveSSH should return nil on success")
	case <-time.After(5 * time.Second):
		t.Fatal("serveSSH did not return in time")
	}

	// Assert the backend saw the fixed user and command.
	probe.mu.Lock()
	defer probe.mu.Unlock()
	assert.Equal(t, "fixed-backend-user", probe.user, "backend must see the fixed config user, not a request-controlled user")
	assert.Equal(t, "git-upload-pack 'backend/project.git'", probe.command, "backend must see the whitelisted command + normalized BackendPath")

	// GIT_PROTOCOL must be propagated as version=2.
	assert.Equal(t, "version=2", probe.env["GIT_PROTOCOL"], "GIT_PROTOCOL=version=2 must be propagated to the backend")

	// The backend must have received the stdin bytes.
	assert.Equal(t, stdinPayload, probe.stdinBuf.Bytes(), "backend must receive the frontend's stdin")

	// The frontend channel must have received the backend's stdout/stderr.
	assert.Equal(t, "backend-stdout-ok", ch.out.String(), "frontend must receive backend stdout")
	assert.Equal(t, "backend-stderr-ok", ch.errw.String(), "frontend must receive backend stderr")
}

// TestServeSSHWithoutGitProtocolOmitsEnv verifies that when gitProtocol is
// empty, serveSSH does not send a GIT_PROTOCOL env request to the backend.
func TestServeSSHWithoutGitProtocolOmitsEnv(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	knownHostsPath := filepath.Join(dir, "known_hosts")

	addr, probe := startInProcessSSHBackend(t, knownHostsPath)

	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	clientKeyPath := writeKeyFile(t, clientPriv)

	cfg := &Config{
		Enable:  true,
		Backend: BackendSSH,
		SSHBackend: SSHBackendConfig{
			Address:        addr,
			User:           "git",
			KeyFile:        clientKeyPath,
			KnownHosts:     knownHostsPath,
			TimeoutSeconds: 5,
		},
	}
	srv := newTestServer(t, cfg)

	req := Request{
		Command:     "git-upload-pack",
		Operation:   OperationRead,
		RepoPath:    "project.git",
		BackendPath: "project.git",
	}

	ch := newFakeFrontendChannel(nil)
	done := make(chan error, 1)
	go func() {
		done <- srv.serveSSH(context.Background(), req, "", ch)
	}()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("serveSSH did not return in time")
	}

	probe.mu.Lock()
	defer probe.mu.Unlock()
	_, hasEnv := probe.env["GIT_PROTOCOL"]
	assert.False(t, hasEnv, "GIT_PROTOCOL must not be sent when gitProtocol is empty")
}

// TestServeSSHRejectsUnknownHost verifies that when the backend presents a
// host key that does not match the known_hosts entry, serveSSH fails with a
// host key verification error.
func TestServeSSHRejectsUnknownHost(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Start a backend whose host key we will NOT put in known_hosts.
	knownHostsPath := filepath.Join(dir, "known_hosts")
	addr, _ := startInProcessSSHBackend(t, knownHostsPath)

	// Generate a DIFFERENT host key and put THAT in known_hosts instead.
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	otherSigner, err := ssh.NewSignerFromSigner(otherPriv)
	require.NoError(t, err)
	// Write a known_hosts entry pinning a key that does NOT match the
	// server's actual host key.
	require.NoError(t, os.WriteFile(knownHostsPath, []byte(knownhosts.Line([]string{"127.0.0.1"}, otherSigner.PublicKey())+"\n"), 0600))

	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	clientKeyPath := writeKeyFile(t, clientPriv)

	cfg := &Config{
		Enable:  true,
		Backend: BackendSSH,
		SSHBackend: SSHBackendConfig{
			Address:        addr,
			User:           "git",
			KeyFile:        clientKeyPath,
			KnownHosts:     knownHostsPath,
			TimeoutSeconds: 5,
		},
	}
	srv := newTestServer(t, cfg)

	req := Request{
		Command:     "git-upload-pack",
		Operation:   OperationRead,
		RepoPath:    "project.git",
		BackendPath: "project.git",
	}

	ch := newFakeFrontendChannel(nil)
	done := make(chan error, 1)
	go func() {
		done <- srv.serveSSH(context.Background(), req, "", ch)
	}()

	select {
	case err := <-done:
		require.Error(t, err, "serveSSH must fail when the backend host key does not match known_hosts")
	case <-time.After(5 * time.Second):
		t.Fatal("serveSSH did not return in time")
	}
}

// TestServeSSHContextCancelClosesBackend verifies that ctx cancellation during
// serveSSH causes the function to return ctx.Err() and does not leak the
// backend goroutine.
func TestServeSSHContextCancelClosesBackend(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	knownHostsPath := filepath.Join(dir, "known_hosts")

	// Start a backend that blocks on exec (never sends exit-status).
	addr := startBlockingExecSSHBackend(t, knownHostsPath)

	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	clientKeyPath := writeKeyFile(t, clientPriv)

	cfg := &Config{
		Enable:  true,
		Backend: BackendSSH,
		SSHBackend: SSHBackendConfig{
			Address:        addr,
			User:           "git",
			KeyFile:        clientKeyPath,
			KnownHosts:     knownHostsPath,
			TimeoutSeconds: 5,
		},
	}
	srv := newTestServer(t, cfg)

	req := Request{
		Command:     "git-upload-pack",
		Operation:   OperationRead,
		RepoPath:    "project.git",
		BackendPath: "project.git",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := newFakeFrontendChannel(nil)
	done := make(chan error, 1)
	go func() {
		done <- srv.serveSSH(ctx, req, "", ch)
	}()

	// Give the handshake + exec a moment to land, then cancel.
	time.Sleep(300 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled, "serveSSH must return ctx.Err() on cancellation; got %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("serveSSH did not return after ctx cancel")
	}
}

// TestServeSSHSetenvCancelInterruptsBlockingSetenv verifies that when
// gitProtocol == "version=2" and the backend accepts the session but never
// replies to the env request, serveSSH does not block forever on
// session.Setenv: ctx cancellation closes the backend client and serveSSH
// returns context.Canceled within the test deadline.
//
// The backend server in this test accepts the session channel and then
// drops every request on the floor (no Reply), so session.Setenv blocks
// indefinitely until the client tears down the connection.
func TestServeSSHSetenvCancelInterruptsBlockingSetenv(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	knownHostsPath := filepath.Join(dir, "known_hosts")

	// Start a backend that accepts the session channel but never replies to
	// any request (env, exec, or otherwise), so session.Setenv blocks.
	addr := startNoReplySSHBackend(t, knownHostsPath)

	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	clientKeyPath := writeKeyFile(t, clientPriv)

	cfg := &Config{
		Enable:  true,
		Backend: BackendSSH,
		SSHBackend: SSHBackendConfig{
			Address:        addr,
			User:           "git",
			KeyFile:        clientKeyPath,
			KnownHosts:     knownHostsPath,
			TimeoutSeconds: 5,
		},
	}
	srv := newTestServer(t, cfg)

	req := Request{
		Command:     "git-upload-pack",
		Operation:   OperationRead,
		RepoPath:    "project.git",
		BackendPath: "project.git",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := newFakeFrontendChannel(nil)
	done := make(chan error, 1)
	go func() {
		// gitProtocol == "version=2" forces the Setenv path.
		done <- srv.serveSSH(ctx, req, "version=2", ch)
	}()

	// Give the handshake + session-open + env-send a moment to land, then
	// cancel. Setenv is blocking because the backend never replies.
	time.Sleep(300 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled, "serveSSH must return ctx.Err() when Setenv is blocked; got %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("serveSSH did not return after ctx cancel while Setenv was blocked")
	}
}

// startNoReplySSHBackend starts a loopback SSH server that accepts session
// channels but never replies to any session request. This causes the client's
// session.Setenv (which sends an env request and waits for the reply) to block
// indefinitely until the connection is torn down.
func startNoReplySSHBackend(t *testing.T, knownHostsPath string) (addr string) {
	t.Helper()

	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostSigner, err := ssh.NewSignerFromSigner(hostPriv)
	require.NoError(t, err)

	serverConf := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	serverConf.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	addr = ln.Addr().String()
	require.NoError(t, os.WriteFile(knownHostsPath, []byte(knownhosts.Line([]string{addr}, hostSigner.PublicKey())+"\n"), 0600))

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				sc, chans, reqs, err := ssh.NewServerConn(c, serverConf)
				if err != nil {
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)

				for newCh := range chans {
					if newCh.ChannelType() != "session" {
						newCh.Reject(ssh.UnknownChannelType, "only session")
						continue
					}
					ch, _, err := newCh.Accept()
					if err != nil {
						continue
					}
					// Accept the channel but never reply to any request.
					// This blocks the client's Setenv/Run forever.
					go func(ch ssh.Channel) {
						<-make(chan struct{})
					}(ch)
				}
			}(conn)
		}
	}()

	return addr
}

// startBlockingExecSSHBackend starts a loopback SSH server that accepts the
// exec request but never sends exit-status, so the client-side session.Run
// blocks forever until the conn is torn down.
func startBlockingExecSSHBackend(t *testing.T, knownHostsPath string) (addr string) {
	t.Helper()

	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostSigner, err := ssh.NewSignerFromSigner(hostPriv)
	require.NoError(t, err)

	serverConf := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	serverConf.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	addr = ln.Addr().String()

	// Write the known_hosts entry with the full address (host:port).
	require.NoError(t, os.WriteFile(knownHostsPath, []byte(knownhosts.Line([]string{addr}, hostSigner.PublicKey())+"\n"), 0600))

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				sc, chans, reqs, err := ssh.NewServerConn(c, serverConf)
				if err != nil {
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)

				for newCh := range chans {
					if newCh.ChannelType() != "session" {
						newCh.Reject(ssh.UnknownChannelType, "only session")
						continue
					}
					ch, inReqs, err := newCh.Accept()
					if err != nil {
						continue
					}
					go func(ch ssh.Channel, reqs <-chan *ssh.Request) {
						for req := range reqs {
							req.Reply(req.Type == "exec", nil)
						}
						// Block forever; do not send exit-status.
						<-make(chan struct{})
					}(ch, inReqs)
				}
			}(conn)
		}
	}()

	return addr
}

// TestSSHBackendDefaultRunnerDispatches verifies that defaultBackendRunner
// dispatches to serveSSH when config.Backend == BackendSSH. This is a smoke
// test that the wiring in auth.go is correct: it drives the runner via a real
// in-process backend and a fake channel and asserts no error.
func TestSSHBackendDefaultRunnerDispatches(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	knownHostsPath := filepath.Join(dir, "known_hosts")
	addr, _ := startInProcessSSHBackend(t, knownHostsPath)

	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	clientKeyPath := writeKeyFile(t, clientPriv)

	cfg := &Config{
		Enable:  true,
		Backend: BackendSSH,
		SSHBackend: SSHBackendConfig{
			Address:        addr,
			User:           "git",
			KeyFile:        clientKeyPath,
			KnownHosts:     knownHostsPath,
			TimeoutSeconds: 5,
		},
	}
	srv := newTestServer(t, cfg)

	req := Request{
		Command:     "git-upload-pack",
		Operation:   OperationRead,
		RepoPath:    "project.git",
		BackendPath: "project.git",
	}

	ch := newFakeFrontendChannel(nil)
	err = defaultBackendRunner(context.Background(), srv, req, "", ch)
	require.NoError(t, err, "defaultBackendRunner must dispatch to serveSSH without error")
}
