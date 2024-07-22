//go:build !no_fakeshell && !plan9
// +build !no_fakeshell,!plan9

package fakeshell

import (
	_ "embed"

	"github.com/hugefiver/fakessh/modules/fakeshell/conf"
)

const Embedded = true

type Config = conf.FakeshellConfig

//go:embed assets/rootfs.tar.gz
var embeddedFsGzip []byte
