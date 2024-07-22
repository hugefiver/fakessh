//go:build no_fakeshell || plan9
// +build no_fakeshell plan9

package fakeshell

import (
	"context"

	"github.com/hugefiver/fakessh/third/ssh"
	"go.uber.org/zap"
)

var logger = zap.NewNop()

type Shell struct {
	C *Config

	runner struct{}

	ssh.Channel
}

func NewShell(c *Config, ch ssh.Channel) *Shell {
	// unreachable
	panic("not implemented")
}

func (s Shell) RunLoop(ctx context.Context) error {
	// unreachable
	panic("not implemented")
}
