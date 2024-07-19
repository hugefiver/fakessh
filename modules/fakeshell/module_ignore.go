//go:build ignore_fakeshell
// +build ignore_fakeshell

package fakeshell

const Embedded = false

type Config struct {
	Enable bool
}

func (c *Config) FillDefault() {}
