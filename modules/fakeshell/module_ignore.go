//go:build no_fakeshell || plan9
// +build no_fakeshell plan9

package fakeshell

const Embedded = false

type Config struct {
	Enable bool
}

func (c *Config) FillDefault() {}
