//go:build no_gitserver
// +build no_gitserver

package main

import (
	"github.com/hugefiver/fakessh/conf"
	"github.com/hugefiver/fakessh/modules/gitserver"
	"github.com/hugefiver/fakessh/third/ssh"
)

// publicKeyCallbackForConfig is the no_gitserver stub: the gitserver module
// is compiled out, so public-key auth is always disabled and no gitserver
// Server is constructed. The second return value is always nil.
func publicKeyCallbackForConfig(sc *conf.AppConfig) (func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error), *gitserver.Server) {
	_ = sc
	return nil, nil
}
