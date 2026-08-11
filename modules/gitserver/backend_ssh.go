//go:build !no_gitserver
// +build !no_gitserver

package gitserver

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/hugefiver/fakessh/third/ssh"
	"github.com/hugefiver/fakessh/third/ssh/knownhosts"
)

// buildBackendCommand assembles the exec command string sent to the remote
// SSH backend. The command is exactly:
//
//	<Command> '<normalizedBackendPath>'
//
// where <Command> is req.Command (already whitelisted by ParseGitCommand to
// one of git-upload-pack / git-receive-pack / git-upload-archive) and
// <normalizedBackendPath> is NormalizeRepoPath(req.BackendPath) (or
// req.RepoPath when BackendPath is empty, which happens only when Authorize
// was bypassed).
//
// The single-quoted backend path is safe because NormalizeRepoPath rejects
// traversal segments, backslashes, colons, and any segment character outside
// [A-Za-z0-9._@+-]; in particular, single quotes are never present in the
// normalized result.
//
// The client cannot control the backend command: req.Command is always the
// parsed whitelist value, and the backend path is always the config-resolved
// BackendPath from Authorize (never the raw client-supplied RepoPath when
// Authorize has run).
func (s *Server) buildBackendCommand(req Request) (string, error) {
	// Defense-in-depth: verify req.Command is from the whitelist enforced by
	// ParseGitCommand. This makes buildBackendCommand fail-closed even if a
	// future caller bypasses ParseGitCommand.
	if _, ok := gitHyphenCommand[req.Command]; !ok {
		return "", fmt.Errorf("gitserver: invalid backend command %q", req.Command)
	}

	backendPath := req.BackendPath
	if backendPath == "" {
		backendPath = req.RepoPath
	}
	normalized, err := NormalizeRepoPath(backendPath)
	if err != nil {
		return "", fmt.Errorf("gitserver: normalize backend path: %w", err)
	}
	return req.Command + " '" + normalized + "'", nil
}

// serveSSH is the SSH-backend implementation of backendRunner. It dials the
// configured remote SSH backend using the fixed connection parameters from
// config.SSHBackend (Address, User, KeyFile, KnownHosts, TimeoutSeconds),
// opens a session, optionally sets GIT_PROTOCOL=version=2, and runs the
// authorized git command with stdio wired to the frontend ssh.Channel.
//
// Security invariants:
//
//   - The backend address, user, private key, and known_hosts are all read
//     from s.config.SSHBackend. The client request (req) cannot influence
//     any of these; it only controls the command string via the whitelisted
//     req.Command and the config-resolved req.BackendPath.
//   - The backend host key is verified against known_hosts; a mismatch or
//     unknown host causes the handshake to fail.
//   - Context cancellation closes the backend client, which tears down the
//     session and causes session.Run to return. ctx cancellation is honored
//     across every blocking phase: TCP dial, SSH handshake, NewSession,
//     Setenv, and session.Run.
//
// The returned error (including *ssh.ExitError) is mapped by HandleSession to
// exit-status 1 for non-nil, 0 for nil.
func (s *Server) serveSSH(ctx context.Context, req Request, gitProtocol string, channel ssh.Channel) error {
	b := s.config.SSHBackend
	timeout := time.Duration(b.TimeoutSeconds) * time.Second

	// Parse the private key from KeyFile.
	keyBytes, err := os.ReadFile(b.KeyFile)
	if err != nil {
		return fmt.Errorf("gitserver: read ssh backend key file %q: %w", b.KeyFile, err)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return fmt.Errorf("gitserver: parse ssh backend key: %w", err)
	}

	// Build the host key callback from known_hosts.
	hostKeyCallback, err := knownhosts.New(b.KnownHosts)
	if err != nil {
		return fmt.Errorf("gitserver: load known_hosts %q: %w", b.KnownHosts, err)
	}

	// Dial the backend. DialContext respects ctx cancellation for the TCP
	// connect phase.
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", b.Address)
	if err != nil {
		return fmt.Errorf("gitserver: dial ssh backend %q: %w", b.Address, err)
	}

	// Set a deadline so the SSH handshake cannot hang forever.
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	clientConfig := &ssh.ClientConfig{
		User:            b.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         timeout,
	}

	// Run NewClientConn in a goroutine so ctx cancellation can abort the
	// handshake by closing the underlying conn.
	type newConnResult struct {
		c   ssh.Conn
		ch  <-chan ssh.NewChannel
		rq  <-chan *ssh.Request
		err error
	}
	connCh := make(chan newConnResult, 1)
	go func() {
		sc, ch, rq, e := ssh.NewClientConn(conn, b.Address, clientConfig)
		connCh <- newConnResult{sc, ch, rq, e}
	}()

	var client *ssh.Client
	select {
	case res := <-connCh:
		if res.err != nil {
			conn.Close()
			return fmt.Errorf("gitserver: ssh backend handshake: %w", res.err)
		}
		client = ssh.NewClient(res.c, res.ch, res.rq)
	case <-ctx.Done():
		// Close the conn to abort the in-flight handshake, then drain the
		// goroutine to prevent a leak.
		conn.Close()
		res := <-connCh
		if res.c != nil {
			res.c.Close()
		}
		return ctx.Err()
	}
	defer client.Close()

	// Clear the deadline; the session phase relies on ctx for cancellation,
	// not a wall-clock timeout.
	if timeout > 0 {
		_ = conn.SetDeadline(time.Time{})
	}

	// Open a backend session. NewSession opens a channel on the SSH
	// connection and may block if the backend never replies to the channel
	// open. Run it in a goroutine so ctx cancellation can interrupt it by
	// closing the client (which tears down the connection and unblocks the
	// pending channel open).
	type newSessionResult struct {
		s   *ssh.Session
		err error
	}
	sessCh := make(chan newSessionResult, 1)
	go func() {
		ss, e := client.NewSession()
		sessCh <- newSessionResult{ss, e}
	}()

	var session *ssh.Session
	select {
	case res := <-sessCh:
		if res.err != nil {
			return fmt.Errorf("gitserver: open ssh backend session: %w", res.err)
		}
		session = res.s
	case <-ctx.Done():
		// Close the client to abort the in-flight NewSession, then drain
		// the goroutine to prevent a leak.
		_ = client.Close()
		res := <-sessCh
		if res.s != nil {
			res.s.Close()
		}
		return ctx.Err()
	}
	defer session.Close()

	// Propagate GIT_PROTOCOL=version=2 when the frontend negotiated it.
	// Setenv sends a channel request and blocks waiting for the reply; if
	// the backend never replies it would hang forever. Run it in a
	// goroutine so ctx cancellation can interrupt it by closing the client
	// (which closes the channel and unblocks the pending SendRequest).
	if gitProtocol == gitProtocolEnvValue {
		setenvCh := make(chan error, 1)
		go func() {
			setenvCh <- session.Setenv(gitProtocolEnvName, gitProtocolEnvValue)
		}()
		select {
		case err := <-setenvCh:
			if err != nil {
				return fmt.Errorf("gitserver: set GIT_PROTOCOL on backend: %w", err)
			}
		case <-ctx.Done():
			// Close the client to tear down the session and unblock the
			// in-flight Setenv. Drain the goroutine to prevent a leak.
			_ = client.Close()
			<-setenvCh
			return ctx.Err()
		}
	}

	// Build the exec command.
	command, err := s.buildBackendCommand(req)
	if err != nil {
		return err
	}

	// Wire stdio: the backend session reads stdin from the frontend channel,
	// writes stdout to the frontend channel, and writes stderr to the
	// frontend channel's stderr.
	session.Stdin = channel
	session.Stdout = channel
	session.Stderr = channel.Stderr()

	// Run the command. session.Run blocks until the remote process exits. On
	// ctx cancellation we close the client to force Run to return.
	done := make(chan error, 1)
	go func() {
		done <- session.Run(command)
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		// Close the client to tear down the backend session. This causes
		// session.Run to return an error. We wait for it so the goroutine
		// does not leak.
		_ = client.Close()
		<-done
		return ctx.Err()
	}
}
