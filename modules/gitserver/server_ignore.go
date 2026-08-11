//go:build no_gitserver
// +build no_gitserver

package gitserver

import (
	"context"
	"errors"

	"github.com/hugefiver/fakessh/third/ssh"
)

// This file provides the minimal set of symbols the main package and conf
// package reference when the gitserver module is compiled out with the
// no_gitserver build tag. None of the real auth/session/repo logic exists in
// this build: every behavior is disabled / false / fail-closed.
//
// Symbols that are ALWAYS compiled (regardless of build tag) live in
// config.go (Config, RepositoryConfig, BackendLocal, BackendSSH,
// CheckAndFillConfig, MergeOptions, FillDefault) and module_ignore.go
// (Embedded=false). This file only adds the runtime symbols the main
// package's ssh.go needs when it references gitserver.Server /
// gitserver.IsGitPermission under no_gitserver.

// Server is the no-op stub used when the gitserver module is compiled out.
// It carries no state because none of its methods do anything useful.
type Server struct{}

// NewServer always returns an error under no_gitserver: the module is not
// embedded, so no server can be constructed. Callers (only
// publicKeyCallbackForConfig under !no_gitserver) are gated on
// gitserver.Embedded and never reach this in the no_gitserver build, but the
// symbol must exist so the main package links.
func NewServer(c *Config) (*Server, error) {
	_ = c
	return nil, errors.New("gitserver: module not embedded (no_gitserver build)")
}

// IsGitPermission is always false under no_gitserver: no public key can ever
// produce a gitserver permission because the public-key callback is never
// installed.
func IsGitPermission(perms *ssh.Permissions) bool {
	_ = perms
	return false
}

// GitKeyFingerprint is always "" under no_gitserver.
func GitKeyFingerprint(perms *ssh.Permissions) string {
	_ = perms
	return ""
}

// PublicKeyCallback is never installed under no_gitserver (the main package's
// publicKeyCallbackForConfig returns nil without calling NewServer), but the
// method must exist on Server so the type is method-compatible with the
// !no_gitserver Server if any code path references it.
func (s *Server) PublicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	_ = conn
	_ = key
	return nil, errors.New("gitserver: module not embedded (no_gitserver build)")
}

// HandleSession is never invoked under no_gitserver (the session router only
// routes to gitserver when IsGitPermission is true, which is always false
// here), but the method must exist so the main package's ssh.go compiles when
// it references ctx.GitServer.HandleSession.
func (s *Server) HandleSession(ctx context.Context, perms *ssh.Permissions, channel ssh.Channel, requests <-chan *ssh.Request) error {
	_ = ctx
	_ = perms
	_ = channel
	_ = requests
	return errors.New("gitserver: module not embedded (no_gitserver build)")
}
