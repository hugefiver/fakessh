//go:build !no_fakeshell
// +build !no_fakeshell

package fakeshell

import (
	_ "embed"

	"github.com/hugefiver/fakessh/modules/fakeshell/conf"
)

const Embedded = true

type Config = conf.FakeshellConfig

//go:embed assets/rootfs.tar.gz
var embeddedFsGzip []byte
