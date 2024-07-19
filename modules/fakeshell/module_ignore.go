//go:build no_fakeshell
// +build no_fakeshell

package fakeshell

const Embedded = false

type Config struct {
	Enable bool
}

func (c *Config) FillDefault() {}
