//go:build !no_gitserver
// +build !no_gitserver

package main

import (
	"testing"

	"github.com/hugefiver/fakessh/modules/gitserver"
	"github.com/hugefiver/fakessh/third/ssh"
	"github.com/stretchr/testify/assert"
)

// TestShouldRouteGitSession verifies the routing predicate that the
// connection-level handler uses to decide whether an accepted session channel
// belongs to the gitserver backend or to the legacy fakeshell/discard path.
//
// Invariants:
//   - nil server -> false (no gitserver configured; always fakeshell)
//   - non-nil server + non-git perms -> false (password/success_ratio auth
//     never produces a git permission, so it never reaches HandleSession)
//   - non-nil server + git perms -> true (route to HandleSession)
//   - nil perms -> false (defensive; HandleSession also fail-closes)
func TestShouldRouteGitSession(t *testing.T) {
	t.Parallel()

	// A non-nil server is required for routing. We do not need a fully
	// initialized Server here because shouldRouteGitSession only checks
	// for nil + IsGitPermission; it never calls any Server method.
	var srv *gitserver.Server

	// nil server: always false regardless of perms.
	assert.False(t, shouldRouteGitSession(srv, gitPerm("SHA256:x")),
		"nil server must never route to gitserver")
	assert.False(t, shouldRouteGitSession(srv, nil),
		"nil server + nil perms must be false")

	// non-nil server.
	srv = &gitserver.Server{}

	// nil perms: false (IsGitPermission(nil) is false).
	assert.False(t, shouldRouteGitSession(srv, nil),
		"non-nil server + nil perms must be false")

	// non-git perms: false.
	bare := &ssh.Permissions{Extensions: map[string]string{}}
	assert.False(t, shouldRouteGitSession(srv, bare),
		"non-git perms must not route to gitserver")

	// git perms: true.
	assert.True(t, shouldRouteGitSession(srv, gitPerm("SHA256:testkey")),
		"git perms with non-nil server must route to gitserver")
}

// gitPerm builds an *ssh.Permissions carrying the gitserver marker extension
// and the given fingerprint, matching what gitserver.PublicKeyCallback
// produces. It uses the same extension key name ("fakessh.gitserver") so
// gitserver.IsGitPermission recognizes it without cross-package access to
// the unexported constant.
func gitPerm(fp string) *ssh.Permissions {
	return &ssh.Permissions{
		Extensions: map[string]string{
			"fakessh.gitserver":                 "1",
			"fakessh.gitserver.key_fingerprint": fp,
		},
	}
}
