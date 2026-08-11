//go:build !no_gitserver
// +build !no_gitserver

package gitserver

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/hugefiver/fakessh/third/ssh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Task 7: end-to-end / final verification tests for the Git-over-SSH path.
//
// These tests are distinct from session_test.go's TestHandleSession* cases:
// they drive the full client->server path with a test-controlled backend
// that also exercises frontend observability (stdout/stderr/exit-status on
// the client side) and pins that the authorized Request handed to the
// backend carries a BackendPath that is distinct from the RepoPath (i.e.
// the router actually resolved the repo through the config map rather than
// echoing the path back). They also pin the unauthorized-WRITE path
// (git-receive-pack with a read-only key) never reaches the backend.

// TestGitServerEndToEnd drives a successful end-to-end Git read session:
//
//   - Client sends env GIT_PROTOCOL=version=2, then exec
//     `git-upload-pack 'project.git'`.
//   - Server parses + authorizes the exec, calls runBackend exactly once.
//   - The test backend writes a stdout marker ("PACK-OUT") and a stderr
//     marker ("PACK-ERR") to the channel so the client can observe them,
//     then returns nil.
//   - Client's session.Run returns nil (exit-status 0) and has buffered
//     both markers via separate stdout/stderr captures.
//   - The backend received Request{Command:"git-upload-pack",
//     Operation:OperationRead, RepoPath:"project.git",
//     BackendPath:"backend/project.git"} and gitProtocol=="version=2".
//
// BackendPath is deliberately configured distinct from RepoPath so this test
// would catch a regression where Authorize forgets to populate BackendPath
// from the matched RepositoryConfig.
func TestGitServerEndToEnd(t *testing.T) {
	t.Parallel()

	repos := []RepositoryConfig{{
		Path:        "project.git",
		BackendPath: "backend/project.git",
		ReadKeys:    []string{"SHA256:testkey"},
	}}
	f := newSessionFixture(t, repos, gitPerms("SHA256:testkey"))

	// Replace the fixture's default recording backend with one that also
	// emits observable stdout/stderr markers before signaling. We keep the
	// recording/call-count semantics by reusing the fixture's fields.
	f.srv.runBackend = func(ctx context.Context, s *Server, req Request, gitProtocol string, channel ssh.Channel) error {
		f.capturedMu.Lock()
		f.called++
		f.captured = &req
		f.protocol = gitProtocol
		f.capturedMu.Unlock()
		close(f.backendCalled)
		// Write markers the client can observe. Stdout via channel.Write,
		// stderr via channel.Stderr().
		_, _ = channel.Write([]byte("PACK-OUT"))
		_, _ = channel.Stderr().Write([]byte("PACK-ERR"))
		// Block until released (mirrors the default fixture backend), then
		// return the configured error.
		select {
		case <-f.backendRelease:
		case <-ctx.Done():
			return ctx.Err()
		}
		return f.backendErr
	}

	sess, err := f.client.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	require.NoError(t, sess.Setenv("GIT_PROTOCOL", "version=2"))

	// Capture stdout and stderr separately so we can assert both markers.
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	sess.Stdout = stdout
	sess.Stderr = stderr

	// Release the backend as soon as it is called so Run can finish.
	go func() {
		<-f.backendCalled
		close(f.backendRelease)
	}()

	require.NoError(t, sess.Run("git-upload-pack 'project.git'"),
		"Run should return nil (exit 0) on a successful backend")

	// Frontend observability: client saw the markers written by the backend.
	assert.Equal(t, "PACK-OUT", stdout.String(), "client must observe backend stdout")
	assert.Equal(t, "PACK-ERR", stderr.String(), "client must observe backend stderr")

	// Backend was called exactly once with the fully authorized Request.
	require.Equal(t, 1, f.backendCallCount(), "backend must be called exactly once")
	req := f.capturedRequest()
	require.NotNil(t, req)
	assert.Equal(t, "git-upload-pack", req.Command)
	assert.Equal(t, OperationRead, req.Operation)
	assert.Equal(t, "project.git", req.RepoPath, "RepoPath must be the parsed repo path")
	assert.Equal(t, "backend/project.git", req.BackendPath,
		"BackendPath must be resolved from config, distinct from RepoPath")

	f.capturedMu.Lock()
	assert.Equal(t, "version=2", f.protocol, "GIT_PROTOCOL must be propagated to backend")
	f.capturedMu.Unlock()

	// HandleSession returns nil on the happy path.
	select {
	case serverErr := <-f.serverErr:
		assert.NoError(t, serverErr, "HandleSession should return nil on success")
	case <-time.After(2 * time.Second):
		t.Fatal("HandleSession did not return in time")
	}
}

// TestGitServerEndToEnd_UnauthorizedWriteNoBackend pins that a key which is
// authorized only for read cannot perform a write (git-receive-pack). The
// exec is replied false, session.Run returns an error, and the backend is
// never invoked.
func TestGitServerEndToEnd_UnauthorizedWriteNoBackend(t *testing.T) {
	t.Parallel()

	repos := []RepositoryConfig{{
		Path:        "project.git",
		BackendPath: "backend/project.git",
		// Key has read access only.
		ReadKeys: []string{"SHA256:testkey"},
	}}
	f := newSessionFixture(t, repos, gitPerms("SHA256:testkey"))

	sess, err := f.client.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	require.NoError(t, sess.Setenv("GIT_PROTOCOL", "version=2"))

	// Attempt a write with a read-only key. This must fail before the
	// backend is dispatched.
	err = sess.Run("git-receive-pack 'project.git'")
	require.Error(t, err, "unauthorized write (receive-pack) must be rejected")

	// Backend must never be called. Release in case the server somehow
	// reached it (it must not).
	close(f.backendRelease)
	assert.Equal(t, 0, f.backendCallCount(),
		"backend must not be called for unauthorized write")

	// HandleSession returns an authorization error.
	select {
	case serverErr := <-f.serverErr:
		require.Error(t, serverErr, "HandleSession must error on unauthorized write")
	case <-time.After(2 * time.Second):
		t.Fatal("HandleSession did not return after unauthorized write")
	}
}
