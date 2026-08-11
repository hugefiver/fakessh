//go:build !no_gitserver
// +build !no_gitserver

package main

import (
	golog "log"

	"github.com/hugefiver/fakessh/conf"
	"github.com/hugefiver/fakessh/modules/gitserver"
	"github.com/hugefiver/fakessh/third/ssh"
)

// publicKeyCallbackForConfig builds the gitserver PublicKeyCallback when the
// gitserver module is embedded (always true under this build tag) and enabled
// in config. It returns nil when gitserver is disabled, leaving public-key
// auth inactive just as before the gitserver feature existed.
//
// It also returns the initialized *gitserver.Server so the caller can thread
// it into Option.GitServer for session routing. When the callback is nil the
// returned Server is also nil.
//
// This helper lives in a build-tagged file so the no_gitserver build never
// has to resolve the gitserver.Server / gitserver.NewServer symbols.
func publicKeyCallbackForConfig(sc *conf.AppConfig) (func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error), *gitserver.Server) {
	if !gitserver.Embedded || !sc.Modules.GitServer.Enable {
		return nil, nil
	}
	gitSrv, err := gitserver.NewServer(&sc.Modules.GitServer)
	if err != nil {
		golog.Fatalf("gitserver init failed: %v", err)
	}
	log.Warnf("[Server] Git server module enabled: ssh_user=%q backend=%q authorized_keys=%q watch_keys=%t",
		sc.Modules.GitServer.SSHUser, sc.Modules.GitServer.Backend,
		sc.Modules.GitServer.AuthorizedKeys, sc.Modules.GitServer.WatchKeys)
	return gitSrv.PublicKeyCallback, gitSrv
}
