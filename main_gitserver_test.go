//go:build !no_gitserver
// +build !no_gitserver

package main

import (
	"errors"
	"testing"

	"github.com/hugefiver/fakessh/conf"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// TestAuthCallbackBlocksGitSSHUserPassword verifies that password auth for the
// git SSH user is always denied when the gitserver module is enabled, even
// when SuccessRatio would otherwise grant the attempt. This locks the
// invariant that git service is reachable only via PublicKeyCallback and
// never via password / success_ratio.
//
// This test mutates the package globals sc, cl, and log, so it does NOT run
// in parallel and it restores the previous values on cleanup.
func TestAuthCallbackBlocksGitSSHUserPassword(t *testing.T) {
	// Save and restore globals.
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

	cb := authCallback(c)
	_, err := cb(fakeConnMetadata{user: "git"}, []byte("anything"))

	assert.Error(t, err, "password auth for git ssh user must be denied")
	assert.True(t, errors.Is(err, errAuth), "expected errAuth sentinel, got %v", err)

	// Sanity: a non-git user with SuccessRatio=100 is still allowed through
	// the success_ratio path, so the block is specifically scoped to the git
	// ssh user.
	_, err = cb(fakeConnMetadata{user: "someoneelse"}, []byte("anything"))
	assert.NoError(t, err, "non-git user with SuccessRatio=100 should succeed")
}
