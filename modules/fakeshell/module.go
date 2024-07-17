//go:build !ignore_fakeshell
// +build !ignore_fakeshell

package fakeshell

import (
	_ "embed"
)

const Embedded = true

type Config = fakeshellConfig

//go:embed assets/rootfs.tar.gz
var embeddedFsGzip []byte

func (c *Config) FillDefault() {
	c.fillDefault()
}
