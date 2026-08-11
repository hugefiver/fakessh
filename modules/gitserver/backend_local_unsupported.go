//go:build !no_gitserver && !(linux || freebsd || openbsd || darwin)
// +build !no_gitserver,!linux,!freebsd,!openbsd,!darwin

package gitserver

import (
	"context"
	"errors"
	"os/exec"

	"github.com/hugefiver/fakessh/third/ssh"
)

// errLocalBackendUnavailable is returned by serveLocal on platforms where the
// local git-shell backend is not supported (e.g. Windows). The Unix build
// provides the real implementation. This fail-closed stub keeps the
// backendRunner contract satisfied so the server never silently serves git
// on a platform that cannot drop privileges via setuid.
var errLocalBackendUnavailable = errors.New("gitserver: local git-shell backend unavailable on this platform")

// serveLocal is the fail-closed stub for unsupported platforms. It always
// returns errLocalBackendUnavailable.
func (s *Server) serveLocal(ctx context.Context, req Request, gitProtocol string, channel ssh.Channel) error {
	_ = ctx
	_ = req
	_ = gitProtocol
	_ = channel
	return errLocalBackendUnavailable
}

// buildLocalCommand is the fail-closed stub for unsupported platforms. It
// exists so package tests on unsupported platforms can reference the symbol
// without a compile error; it always returns errLocalBackendUnavailable.
func (s *Server) buildLocalCommand(req Request, gitProtocol string) (*exec.Cmd, error) {
	_ = req
	_ = gitProtocol
	return nil, errLocalBackendUnavailable
}
