//go:build !no_gitserver
// +build !no_gitserver

package gitserver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/hugefiver/fakessh/third/ssh"
)

// Wire payload structs for the session requests HandleSession cares about.
// They mirror the unexported types in third/ssh (execMsg, setenvRequest) but
// are declared here so this package does not depend on third/ssh internals
// and so tests can construct payloads via ssh.Marshal without reaching into
// the vendored package.
//
// The sshtype tag is optional for ssh.Marshal/ssh.Unmarshal; only field order
// matters. Field names are unexported so nothing outside this package
// accidentally depends on the wire struct shape.
type gitExecMsg struct {
	Command string
}

type gitEnvMsg struct {
	Name  string
	Value string
}

// allowedGitProtocolEnv is the single env request HandleSession honors: the
// client may set GIT_PROTOCOL to "version=2" (the Git wire protocol v2
// advertisement). Any other env name, any other value, or a second env
// request is rejected fail-closed. This mirrors what a hardened git server
// accepts: only GIT_PROTOCOL is propagated, and only the well-known value.
const (
	gitProtocolEnvName  = "GIT_PROTOCOL"
	gitProtocolEnvValue = "version=2"
)

// defaultPreExecTimeout bounds the time between accepting a git session
// channel and accepting its single exec request. Git clients send optional
// GIT_PROTOCOL and exec immediately after opening the session; an authenticated
// client that opens a session and then idles is treated as an availability risk
// and disconnected.
const defaultPreExecTimeout = 10 * time.Second

// Sentinel errors returned by HandleSession. They are wrapped with fmt.Errorf
// at call sites when more context is useful, but the sentinels let tests
// assert on errors.Is without parsing messages.
var (
	// errNotGitPermission is returned when HandleSession is called with perms
	// that were not produced by the gitserver PublicKeyCallback. HandleSession
	// must never have been reached for such perms (the session router checks
	// IsGitPermission first), so this is a fail-closed invariant violation.
	errNotGitPermission = errors.New("gitserver: session handler called with non-git permission")
	// errSecondEnv is returned when a second env request arrives after a
	// valid GIT_PROTOCOL env has already been accepted.
	errSecondEnv = errors.New("gitserver: at most one env request is allowed")
	// errUnsupportedEnv is returned when an env request sets anything other
	// than GIT_PROTOCOL=version=2.
	errUnsupportedEnv = errors.New("gitserver: unsupported env request")
	// errSecondExec is returned when a second exec request arrives after a
	// first exec has already been accepted and dispatched.
	errSecondExec = errors.New("gitserver: at most one exec request is allowed")
	// errUnsupportedRequest is returned when a session request is a type
	// HandleSession never honors (shell, pty-req, subsystem, or any unknown
	// type) and it should cause the session to tear down.
	errUnsupportedRequest = errors.New("gitserver: unsupported session request")
	// errRequestStreamClosed is returned when the client closes the request
	// stream before sending an exec (e.g. client-side error or cancellation).
	errRequestStreamClosed = errors.New("gitserver: request stream closed before exec")
	// errPreExecTimeout is returned when an authenticated git session does not
	// send the required exec request within preExecTimeout.
	errPreExecTimeout = errors.New("gitserver: timed out waiting for exec request")
)

// HandleSession implements the gitserver SSH session protocol for a single
// accepted "session" channel. It is the entry point the connection-level
// router calls once it has accepted a session channel and decided (via
// shouldRouteGitSession) that the authenticated perms belong to a git user.
//
// Protocol enforced (fail-closed):
//
//   - perms must be a gitserver permission (IsGitPermission). Otherwise the
//     session is refused without touching the channel requests.
//   - At most one "env" request is accepted, and only when it sets
//     GIT_PROTOCOL=version=2. Any other env name/value, and any second env
//     request, is replied false and causes HandleSession to return an error.
//   - Exactly one "exec" request is accepted. Its payload is parsed with
//     ssh.Unmarshal into {Command string}; ParseGitCommand then produces a
//     Request and Authorize checks the ACL. Parse/authorize failures are
//     replied false and the session returns an error. On success the exec is
//     replied true and the backend runner is invoked in the same goroutine.
//   - "shell", "pty-req", "subsystem", and any other request type are
//     replied false (when WantReply) and, if they arrive as the first
//     request, cause HandleSession to return an error so the session does
//     not linger.
//   - While the backend runs, subsequent requests (including a second exec)
//     are drained and replied false so the client cannot block the request
//     stream.
//   - On backend completion, an "exit-status" request is sent to the channel
//     (0 on nil error, 1 otherwise) and the channel is closed.
//   - ctx cancellation propagates: if ctx is cancelled while waiting for
//     requests or while the backend runs, HandleSession returns ctx.Err()
//     (after closing the channel).
//
// HandleSession does NOT log pack data and does NOT echo back command
// contents beyond what the protocol already carries. Errors are returned to
// the caller (the connection-level router) for optional logging; they are
// not written to the channel.
func (s *Server) HandleSession(ctx context.Context, perms *ssh.Permissions, channel ssh.Channel, requests <-chan *ssh.Request) error {
	// Fail-closed: never serve a session whose perms were not produced by
	// the gitserver PublicKeyCallback. The router should have checked this,
	// but HandleSession is also a package-level entry point for tests, so it
	// defends itself.
	if !IsGitPermission(perms) {
		_ = channel.Close()
		return errNotGitPermission
	}

	// cleanup closes the channel exactly once and is deferred so every
	// return path tears down the SSH channel. Idempotent.
	var closed bool
	cleanup := func() {
		if closed {
			return
		}
		closed = true
		_ = channel.Close()
	}
	defer cleanup()

	// sendExitStatus sends an exit-status request to the client. status is a
	// uint32 sent big-endian per RFC 4254 6.10. The client's Session.Wait
	// treats 0 as success, non-zero as *ExitError, and a missing exit-status
	// (channel closed first) as *ExitMissingError - so we always send one
	// before closing when a backend actually ran.
	sendExitStatus := func(status uint32) {
		payload := make([]byte, 4)
		binary.BigEndian.PutUint32(payload, status)
		_, _ = channel.SendRequest("exit-status", false, payload)
	}

	// Phase 1: pre-exec request loop. Wait for the client's optional env
	// request (at most one, GIT_PROTOCOL=version=2 only) and the required
	// exec request. shell/pty-req/subsystem/unknown as the first request
	// cause an error return so the session does not linger.
	envAccepted := false
	var gitProtocol string
	var authorizedReq Request
	preExecTimeout := s.preExecTimeout
	if preExecTimeout <= 0 {
		preExecTimeout = defaultPreExecTimeout
	}
	preExecTimer := time.NewTimer(preExecTimeout)
	defer preExecTimer.Stop()

	for {
		select {
		case <-preExecTimer.C:
			return errPreExecTimeout
		case <-ctx.Done():
			return ctx.Err()
		case req, ok := <-requests:
			if !ok {
				return errRequestStreamClosed
			}

			switch req.Type {
			case "env":
				if envAccepted {
					replyFalse(req)
					return errSecondEnv
				}
				var msg gitEnvMsg
				if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
					replyFalse(req)
					return fmt.Errorf("gitserver: malformed env request: %w", err)
				}
				if msg.Name != gitProtocolEnvName || msg.Value != gitProtocolEnvValue {
					replyFalse(req)
					return errUnsupportedEnv
				}
				replyTrue(req)
				envAccepted = true
				gitProtocol = msg.Value

			case "exec":
				var msg gitExecMsg
				if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
					replyFalse(req)
					return fmt.Errorf("gitserver: malformed exec request: %w", err)
				}
				parsed, err := ParseGitCommand(msg.Command)
				if err != nil {
					replyFalse(req)
					return fmt.Errorf("gitserver: parse exec command: %w", err)
				}
				authed, err := s.Authorize(perms, parsed)
				if err != nil {
					replyFalse(req)
					return fmt.Errorf("gitserver: authorize exec: %w", err)
				}
				// Accept the exec: reply true, stash the authorized request,
				// and break out of the pre-exec loop to start the backend.
				replyTrue(req)
				authorizedReq = authed
				if !preExecTimer.Stop() {
					select {
					case <-preExecTimer.C:
					default:
					}
				}
				goto backendPhase

			case "shell", "pty-req", "subsystem":
				replyFalse(req)
				return errUnsupportedRequest

			default:
				replyFalse(req)
				return errUnsupportedRequest
			}
		}
	}

backendPhase:
	// Phase 2: dispatch the backend runner. The backend runs in its own
	// goroutine so HandleSession can concurrently drain the channel's request
	// stream (the vendored mux requires that request channels be serviced, so
	// a blocking backend would deadlock the SSH connection). HandleSession
	// waits for the backend to finish - or returns promptly on ctx
	// cancellation - then sends exit-status and closes the channel.
	//
	// backendDone is buffered so the backend goroutine can finish and exit
	// even if HandleSession returns early on ctx cancellation without
	// reading from backendDone (otherwise the send would block forever and
	// leak the goroutine).
	backendDone := make(chan error, 1)
	go func() {
		backendDone <- s.runBackend(ctx, s, authorizedReq, gitProtocol, channel)
	}()

	// drainLoop processes requests that arrive while the backend runs. Every
	// request is replied false - including a second exec. This matches
	// OpenSSH: once a command is running, additional channel requests are
	// refused but do not kill the session. A second exec is refused the same
	// way (reply false) and does not start a second backend.
	//
	// drainErr is intentionally not recorded: writing it from this goroutine
	// and reading it from the main goroutine would race, and the session's
	// return value must reflect the backend's outcome, not a drained second
	// exec. The TestHandleSessionRejectsSecondExec test pins this contract
	// (backend called once, HandleSession returns nil when backend returns
	// nil).
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		for {
			select {
			case <-ctx.Done():
				return
			case req, ok := <-requests:
				if !ok {
					return
				}
				replyFalse(req)
			}
		}
	}()

	// Wait for the backend to finish or the context to be cancelled. The
	// backend is the authority on when the session ends on the happy path:
	// once it returns we send exit-status, stop draining, close the channel,
	// and return.
	//
	// On ctx cancellation we do NOT wait for the backend. The Task 4
	// lifecycle contract requires HandleSession to return within ~1s of
	// cancel; a backend that ignores ctx must not be able to hang the
	// session. We make a single non-blocking attempt to pick up an already-
	// completed backend result (so a backend that finished concurrently
	// with the cancel is still reported), and otherwise return ctx.Err()
	// immediately. The deferred cleanup closes the channel; the backend
	// goroutine may continue running until it observes ctx cancellation or
	// the closed channel, but HandleSession does not block on it.
	var backendErr error
	select {
	case backendErr = <-backendDone:
		// Backend finished before (or concurrently with) any cancellation.
	case <-ctx.Done():
		// Context cancelled while the backend is still running. Try once,
		// non-blocking, to collect a concurrently-completed result; if the
		// backend has not returned yet, do not wait for it.
		select {
		case backendErr = <-backendDone:
		default:
			// Backend still running. Return ctx.Err() now; defer cleanup
			// closes the channel.
			_ = drainDone
			return ctx.Err()
		}
	}

	// Stop the drain goroutine (it may already have exited via ctx.Done or
	// closed requests). We do not need to wait for it: closing the channel
	// below will cause any further Reply calls to fail harmlessly, and the
	// goroutine exits via its ctx.Done / closed-channel selects.
	_ = drainDone

	// Map the backend error to an exit status. nil -> 0, anything else -> 1
	// in this task. Task 5/6 may refine the mapping (e.g. distinguish
	// authorization-relevant codes), but the contract is that a non-nil
	// error from the backend is reported as a non-zero exit.
	if backendErr == nil {
		sendExitStatus(0)
	} else {
		sendExitStatus(1)
	}

	// cleanup() runs via defer, closing the channel. Return the backend
	// error so the caller (connection-level router) can log it. When ctx
	// was cancelled we prefer ctx.Err() so the caller sees the cause.
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return backendErr
}

// replyTrue / replyFalse are tiny wrappers that swallow the (always-nil in
// practice) Reply error so call sites stay readable. Reply is a no-op when
// WantReply is false, so calling these unconditionally is safe for both
// want-reply and no-reply requests.
func replyTrue(req *ssh.Request)  { _ = req.Reply(true, nil) }
func replyFalse(req *ssh.Request) { _ = req.Reply(false, nil) }
