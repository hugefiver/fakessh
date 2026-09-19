//go:build !windows && !plan9 && !no_fakeshell && !no_gitserver
// +build !windows,!plan9,!no_fakeshell,!no_gitserver

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hugefiver/fakessh/modules/fakeshell"
	"github.com/hugefiver/fakessh/modules/gitserver"
	"github.com/hugefiver/fakessh/third/ssh"
	"github.com/hugefiver/fakessh/third/ssh/knownhosts"
)

type openSSHReadResult struct {
	data []byte
	err  error
}

func writeOpenSSHTestPrivateKey(t *testing.T, privateKey ed25519.PrivateKey) (string, ssh.Signer) {
	t.Helper()
	signer, err := ssh.NewSignerFromSigner(privateKey)
	if err != nil {
		t.Fatalf("NewSignerFromSigner() error = %v", err)
	}
	block, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		t.Fatalf("MarshalPrivateKey() error = %v", err)
	}
	var encoded bytes.Buffer
	if err := pem.Encode(&encoded, block); err != nil {
		t.Fatalf("pem.Encode() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, encoded.Bytes(), 0600); err != nil {
		t.Fatalf("WriteFile(private key) error = %v", err)
	}
	return path, signer
}

func startOpenSSHTestBackend(t *testing.T, knownHostsPath string, stdoutPayload, stderrPayload []byte) (string, <-chan []byte, <-chan struct{}, <-chan struct{}, <-chan error) {
	t.Helper()
	_, hostPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(backend host) error = %v", err)
	}
	hostSigner, err := ssh.NewSignerFromSigner(hostPrivateKey)
	if err != nil {
		t.Fatalf("NewSignerFromSigner(backend host) error = %v", err)
	}
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	config.AddHostKey(hostSigner)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(backend) error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	addr := listener.Addr().String()
	line := knownhosts.Line([]string{addr}, hostSigner.PublicKey()) + "\n"
	if err := os.WriteFile(knownHostsPath, []byte(line), 0600); err != nil {
		t.Fatalf("WriteFile(known_hosts) error = %v", err)
	}

	stdinRead := make(chan []byte, 1)
	outputStarted := make(chan struct{})
	outputFinished := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		serverConn, channels, requests, err := ssh.NewServerConn(conn, config)
		if err != nil {
			done <- err
			return
		}
		defer serverConn.Close()
		go ssh.DiscardRequests(requests)

		newChannel, ok := <-channels
		if !ok {
			done <- fmt.Errorf("backend channel stream closed before session")
			return
		}
		if newChannel.ChannelType() != "session" {
			done <- fmt.Errorf("backend channel type = %q, want session", newChannel.ChannelType())
			return
		}
		channel, channelRequests, err := newChannel.Accept()
		if err != nil {
			done <- err
			return
		}

		for req := range channelRequests {
			switch req.Type {
			case "env":
				_ = req.Reply(true, nil)
			case "exec":
				if err := req.Reply(true, nil); err != nil {
					done <- err
					return
				}
				input, err := io.ReadAll(channel)
				if err != nil {
					done <- err
					return
				}
				stdinRead <- input
				close(outputStarted)
				if _, err := io.Copy(channel, bytes.NewReader(stdoutPayload)); err != nil {
					done <- err
					return
				}
				if _, err := io.Copy(channel.Stderr(), bytes.NewReader(stderrPayload)); err != nil {
					done <- err
					return
				}
				close(outputFinished)
				if _, err := channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0}); err != nil {
					done <- err
					return
				}
				if err := channel.CloseWrite(); err != nil {
					done <- err
					return
				}
				if err := channel.Close(); err != nil {
					done <- err
					return
				}

				// Keep the backend transport alive until its peer acknowledges
				// the channel close. Closing serverConn immediately after writing
				// the close packet can truncate buffered extended data or the exit
				// status before the backend SSH client consumes them.
				peerCloseTimer := time.NewTimer(2 * time.Second)
				defer peerCloseTimer.Stop()
				for {
					select {
					case req, ok := <-channelRequests:
						if !ok {
							done <- nil
							return
						}
						_ = req.Reply(false, nil)
					case <-peerCloseTimer.C:
						done <- fmt.Errorf("backend peer did not acknowledge channel close")
						return
					}
				}
			default:
				_ = req.Reply(false, nil)
			}
		}
		done <- fmt.Errorf("backend request stream closed before exec")
	}()

	return addr, stdinRead, outputStarted, outputFinished, done
}

func startOpenSSHTestFrontend(t *testing.T, server *gitserver.Server, config *ssh.ServerConfig) (string, <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(frontend) error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	handled := make(chan struct{})
	go func() {
		defer close(handled)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		connections := &atomic.Int64{}
		connections.Store(1)
		handleConn(&SSHConnectionContext{
			Conn:            conn,
			Connections:     connections,
			SuccConnections: &atomic.Int64{},
			FakeShellConfig: &fakeshell.Config{},
			GitServer:       server,
			postAuthTimeout: 5 * time.Second,
		}, config)
	}()
	return listener.Addr().String(), handled
}

func TestGitBackendSuccessfulOpenSSHCompletionPreservesOutputAndExitStatus(t *testing.T) {
	sshCLI, err := exec.LookPath("ssh")
	if err != nil {
		t.Skipf("OpenSSH client is unavailable: %v", err)
	}

	_, frontendPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(frontend client) error = %v", err)
	}
	frontendKeyPath, frontendSigner := writeOpenSSHTestPrivateKey(t, frontendPrivateKey)
	authorizedKeysPath := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(authorizedKeysPath, ssh.MarshalAuthorizedKey(frontendSigner.PublicKey()), 0600); err != nil {
		t.Fatalf("WriteFile(authorized_keys) error = %v", err)
	}

	_, backendPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(backend client) error = %v", err)
	}
	backendKeyPath, _ := writeOpenSSHTestPrivateKey(t, backendPrivateKey)
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	stdoutPayload := bytes.Repeat([]byte("stdout-pack-data\n"), 256*1024)
	stderrPayload := bytes.Repeat([]byte("stderr-progress\n"), 256*1024)
	backendAddr, backendStdin, outputStarted, outputFinished, backendDone := startOpenSSHTestBackend(t, knownHostsPath, stdoutPayload, stderrPayload)

	fingerprint := ssh.FingerprintSHA256(frontendSigner.PublicKey())
	server, err := gitserver.NewServer(&gitserver.Config{
		Enable:         true,
		SSHUser:        "git",
		AuthorizedKeys: authorizedKeysPath,
		Backend:        gitserver.BackendSSH,
		Repositories: []gitserver.RepositoryConfig{{
			Path:        "repo.git",
			BackendPath: "repo.git",
			ReadKeys:    []string{fingerprint},
		}},
		SSHBackend: gitserver.SSHBackendConfig{
			Address:        backendAddr,
			User:           "git",
			KeyFile:        backendKeyPath,
			KnownHosts:     knownHostsPath,
			TimeoutSeconds: 5,
		},
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	_, frontendHostPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(frontend host) error = %v", err)
	}
	frontendHostSigner, err := ssh.NewSignerFromSigner(frontendHostPrivateKey)
	if err != nil {
		t.Fatalf("NewSignerFromSigner(frontend host) error = %v", err)
	}
	frontendConfig := &ssh.ServerConfig{PublicKeyCallback: server.PublicKeyCallback, AsOpenSSH: true}
	frontendConfig.AddHostKey(frontendHostSigner)
	frontendAddr, handled := startOpenSSHTestFrontend(t, server, frontendConfig)
	_, port, err := net.SplitHostPort(frontendAddr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q) error = %v", frontendAddr, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, sshCLI,
		"-F", "/dev/null",
		"-T",
		"-i", frontendKeyPath,
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=QUIET",
		"-p", port,
		"git@127.0.0.1",
		"git-upload-pack 'repo.git'",
	)
	stdinPayload := "frontend-stdin-until-eof\n"
	cmd.Stdin = strings.NewReader(stdinPayload)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe() error = %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("StderrPipe() error = %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("OpenSSH Start() error = %v", err)
	}
	waited := false
	defer func() {
		if !waited {
			cancel()
			_ = cmd.Wait()
		}
	}()

	select {
	case <-outputStarted:
	case err := <-backendDone:
		t.Fatalf("backend ended before output: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("backend did not receive stdin EOF and start output")
	}
	time.Sleep(200 * time.Millisecond)
	select {
	case <-outputFinished:
		t.Fatal("backend output completed before client pipes were drained; output backpressure was not exercised")
	default:
	}

	stdoutDone := make(chan openSSHReadResult, 1)
	stderrDone := make(chan openSSHReadResult, 1)
	go func() {
		data, err := io.ReadAll(stdout)
		stdoutDone <- openSSHReadResult{data: data, err: err}
	}()
	go func() {
		data, err := io.ReadAll(stderr)
		stderrDone <- openSSHReadResult{data: data, err: err}
	}()
	var stdoutResult, stderrResult openSSHReadResult
	select {
	case stdoutResult = <-stdoutDone:
	case <-ctx.Done():
		t.Fatalf("OpenSSH stdout timed out: %v", ctx.Err())
	}
	select {
	case stderrResult = <-stderrDone:
	case <-ctx.Done():
		t.Fatalf("OpenSSH stderr timed out: %v", ctx.Err())
	}
	// Wait closes StdoutPipe/StderrPipe, so both readers must finish first.
	waitErr := cmd.Wait()
	waited = true
	if waitErr != nil {
		t.Fatalf("OpenSSH Wait() error = %v; stderr tail = %q", waitErr, stderrResult.data[max(0, len(stderrResult.data)-256):])
	}
	if stdoutResult.err != nil {
		t.Fatalf("read OpenSSH stdout error = %v", stdoutResult.err)
	}
	if stderrResult.err != nil {
		t.Fatalf("read OpenSSH stderr error = %v", stderrResult.err)
	}
	if !bytes.Equal(stdoutResult.data, stdoutPayload) {
		t.Fatalf("OpenSSH stdout length = %d, want %d", len(stdoutResult.data), len(stdoutPayload))
	}
	if !bytes.Equal(stderrResult.data, stderrPayload) {
		t.Fatalf("OpenSSH stderr length = %d, want %d", len(stderrResult.data), len(stderrPayload))
	}
	if cmd.ProcessState.ExitCode() != 0 {
		t.Fatalf("OpenSSH exit status = %d, want 0", cmd.ProcessState.ExitCode())
	}
	if got := string(<-backendStdin); got != stdinPayload {
		t.Fatalf("backend stdin = %q, want %q", got, stdinPayload)
	}
	if err := <-backendDone; err != nil {
		t.Fatalf("backend error = %v", err)
	}
	select {
	case <-handled:
	case <-time.After(2 * time.Second):
		t.Fatal("frontend handleConn did not return after successful channel close")
	}
}
