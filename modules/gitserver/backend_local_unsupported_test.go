//go:build !no_gitserver && !(linux || freebsd || openbsd || darwin)
// +build !no_gitserver,!linux,!freebsd,!openbsd,!darwin

package gitserver

import (
	"context"
	"io"
	"testing"

	"github.com/hugefiver/fakessh/third/ssh"
	"github.com/stretchr/testify/assert"
)

// fakeLocalChannel is a minimal ssh.Channel implementation used only by the
// unsupported-platform test to pass a non-nil channel to serveLocal. The
// methods are not exercised because serveLocal must fail-closed before
// touching the channel.
type fakeLocalChannel struct{}

func (fakeLocalChannel) Read([]byte) (int, error)  { return 0, nil }
func (fakeLocalChannel) Write([]byte) (int, error) { return 0, nil }
func (fakeLocalChannel) Close() error              { return nil }
func (fakeLocalChannel) CloseWrite() error         { return nil }
func (fakeLocalChannel) SendRequest(string, bool, []byte) (bool, error) {
	return false, nil
}
func (fakeLocalChannel) Stderr() io.ReadWriter { return nil }

// TestLocalServeOnUnsupportedPlatformReturnsError verifies that on platforms
// where the local git-shell backend is not supported (e.g. Windows),
// serveLocal fail-closes with errLocalBackendUnavailable rather than
// attempting to spawn a privileged child.
func TestLocalServeOnUnsupportedPlatformReturnsError(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, &Config{
		Enable:  true,
		Backend: BackendLocal,
	})

	req := Request{
		Command:   "git-upload-pack",
		Operation: OperationRead,
		RepoPath:  "project.git",
	}

	err := srv.serveLocal(context.Background(), req, "", fakeLocalChannel{})
	assert.ErrorIs(t, err, errLocalBackendUnavailable, "serveLocal must fail-closed with errLocalBackendUnavailable on unsupported platforms")
}

// TestBuildLocalCommandOnUnsupportedPlatformReturnsError verifies the stub
// buildLocalCommand also fails closed on unsupported platforms.
func TestBuildLocalCommandOnUnsupportedPlatformReturnsError(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, &Config{
		Enable:  true,
		Backend: BackendLocal,
	})

	req := Request{
		Command:   "git-upload-pack",
		Operation: OperationRead,
		RepoPath:  "project.git",
	}

	_, err := srv.buildLocalCommand(req, "")
	assert.ErrorIs(t, err, errLocalBackendUnavailable, "buildLocalCommand must fail-closed with errLocalBackendUnavailable on unsupported platforms")
}

// _ is a compile-time anchor so the ssh import is used even if the
// fakeLocalChannel Stderr() signature is refactored. It has no runtime
// effect.
var _ ssh.Channel = fakeLocalChannel{}
