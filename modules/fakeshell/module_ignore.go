//go:build no_fakeshell || plan9
// +build no_fakeshell plan9

package fakeshell

import "github.com/hugefiver/fakessh/modules"

const Embedded = false

type Config struct {
	Enable bool
}

func (c *Config) FillDefault() {}

func (c *Config) MergeOptions(opt *modules.Opt) bool {
	return false
}
