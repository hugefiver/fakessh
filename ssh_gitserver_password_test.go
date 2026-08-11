//go:build !no_gitserver
// +build !no_gitserver

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/hugefiver/fakessh/conf"
	"github.com/hugefiver/fakessh/third/ssh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestGitServerEndToEndPasswordAuthDeniedForSSHUser is the Task 7 final
// verification that password auth for the git SSH user is denied end-to-end
// at the SSH handshake layer - not just inside authCallback (which is
// covered by TestAuthCallbackBlocksGitSSHUserPassword), but through a real
// vendored SSH client/server handshake over a loopback TCP connection.
//
// Invariants pinned here:
//
//   - With GitServer.Enable=true and SSHUser="git", a client attempting
//     password auth as user "git" must fail the handshake on BOTH sides.
//   - SuccessRatio=100 / Delay=0 / Deviation=0 ensures the only reason the
//     handshake fails is the git-user-password block (not the success_ratio
//     coin flip) and that sleepAuthDelay returns immediately.
//
// This test mutates package globals sc, cl, log, so it does NOT run in
// parallel and it restores the previous values on cleanup.
func TestGitServerEndToEndPasswordAuthDeniedForSSHUser(t *testing.T) {
	// Save and restore globals mutated by authCallback / checkCouldSuccess.
	prevSc := sc
	prevCl := cl
	prevLog := log
	t.Cleanup(func() {
		sc = prevSc
		cl = prevCl
		log = prevLog
	})

	cl = &conf.FlagArgsStruct{}
	log = zap.NewNop().Sugar()

	c := conf.NewDefaultAppConfig()
	c.Server.SuccessRatio = 100
	c.Server.Delay = 0
	c.Server.Deviation = 0
	c.Modules.GitServer.Enable = true
	c.Modules.GitServer.SSHUser = "git"
	sc = c

	// Real loopback TCP pair (net.Pipe deadlocks the SSH version exchange;
	// see modules/gitserver/sshPipeConns for the same rationale).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	type acceptResult struct {
		c   net.Conn
		err error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		conn, err := ln.Accept()
		acceptCh <- acceptResult{conn, err}
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { clientConn.Close() })

	ar := <-acceptCh
	require.NoError(t, ar.err)
	serverConn := ar.c
	t.Cleanup(func() { serverConn.Close() })

	// Generate a host signer for the server.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostSigner, err := ssh.NewSignerFromSigner(priv)
	require.NoError(t, err)

	serverConfig := &ssh.ServerConfig{
		PasswordCallback: authCallback(c),
	}
	serverConfig.AddHostKey(hostSigner)

	// serverErr receives the result of the server-side handshake.
	serverErr := make(chan error, 1)
	go func() {
		_, _, _, err := ssh.NewServerConn(serverConn, serverConfig)
		serverErr <- err
	}()

	// Client uses password auth as the git SSH user. The handshake must
	// fail on the client side because the server rejects password auth for
	// the git user.
	clientConfig := &ssh.ClientConfig{
		User: "git",
		Auth: []ssh.AuthMethod{
			ssh.Password("anything"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		// Bound the handshake so a regression (e.g. the server accepting
		// the git user) surfaces as a timeout rather than hanging.
		Timeout: 5 * time.Second,
	}

	clientCh := make(chan error, 1)
	go func() {
		_, _, _, err := ssh.NewClientConn(clientConn, ln.Addr().String(), clientConfig)
		clientCh <- err
	}()

	// Both sides must report a handshake failure.
	select {
	case err := <-clientCh:
		require.Error(t, err, "client handshake must fail for git user password auth")
	case <-time.After(5 * time.Second):
		t.Fatal("client handshake did not return in time")
	}

	select {
	case err := <-serverErr:
		assert.Error(t, err, "server handshake must fail for git user password auth")
	case <-time.After(5 * time.Second):
		t.Fatal("server handshake did not return in time")
	}
}
