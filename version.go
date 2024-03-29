package main

import (
	"fmt"

	"github.com/hugefiver/fakessh/conf"
)

var version = "0.3.x-master"
var commitId = "unknown"
var buildTime = "unknown"
var goversion = "unknown"

func showVersion() {
	fmt.Printf(`FakeSSH - a fake SSH server

version: %s
commit: %s
build time: %s
go version: %s
Default SSH version: %s
`, version, commitId, buildTime, goversion, conf.DefaultSSHVersion)
}
