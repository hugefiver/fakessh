package modules

import (
	"errors"
	"strings"
)

var ErrFailParseOpt = errors.New("fail to parse opt")

type Opt struct {
	Module string
	Key    string
	Value  string
}

func ParseOpt(opt string) (*Opt, error) {
	xs := strings.SplitN(opt, "=", 2)

	if len(xs) != 2 {
		return nil, ErrFailParseOpt
	}

	key, value := xs[0], xs[1]
	var module string
	if idx := strings.Index(key, "."); idx >= 0 {
		module = key[:idx]
		key = key[idx+1:]
	}
	return &Opt{
		strings.TrimSpace(module),
		strings.TrimSpace(key),
		strings.TrimSpace(value)}, nil
}
