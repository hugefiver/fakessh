//go:build !no_fakeshell && !plan9
// +build !no_fakeshell,!plan9

package fakeshell

import (
	"errors"

	"github.com/hugefiver/fakessh/modules/fakeshell/parser"
)

const (
	MaxInputLineBytes       = 4096
	MaxInputTokenBytes      = 1024
	MaxInputArgs            = 64
	MaxCommandsPerReadCycle = 64
)

var (
	errInputLineTooLong           = errors.New("input line too long")
	errInputCommandTokenTooLong   = errors.New("command token too long")
	errInputArgumentTokenTooLong  = errors.New("argument token too long")
	errInputTooManyArguments      = errors.New("too many arguments")
	errInputEnvTokenTooLong       = errors.New("env token too long")
	errInputTooManyEnvAssignments = errors.New("too many env assignments")
)

// findCommandSeparator returns the first command boundary in buf.
//
// Newline is always a hard boundary, even while quote state is open. Semicolon
// is a boundary only outside single and double quotes. Double-quoted backslash
// escaping follows the parser's limited semantics closely enough for boundary
// detection: a backslash shields the following byte from quote/semicolon
// handling, except that a following newline still remains a hard boundary.
func findCommandSeparator(buf []byte) (idx int, ok bool) {
	const noQuote byte = 0
	quote := noQuote

	for i := 0; i < len(buf); i++ {
		c := buf[i]
		if c == '\n' {
			return i, true
		}

		switch quote {
		case noQuote:
			switch c {
			case '\'', '"':
				quote = c
			case ';':
				return i, true
			}
		case '\'':
			if c == '\'' {
				quote = noQuote
			}
		case '"':
			if c == '\\' && i+1 < len(buf) {
				if buf[i+1] == '\n' {
					return i + 1, true
				}
				i++
				continue
			}
			if c == '"' {
				quote = noQuote
			}
		}
	}

	return 0, false
}

func validateParsedCommand(cmd *parser.Command) error {
	if cmd == nil {
		return nil
	}
	if len(cmd.Name) > MaxInputTokenBytes {
		return errInputCommandTokenTooLong
	}
	if len(cmd.Args) > MaxInputArgs {
		return errInputTooManyArguments
	}
	for _, arg := range cmd.Args {
		if len(arg) > MaxInputTokenBytes {
			return errInputArgumentTokenTooLong
		}
	}
	if len(cmd.Opt.Envs) > MaxInputArgs {
		return errInputTooManyEnvAssignments
	}
	for _, env := range cmd.Opt.Envs {
		if len(env.Key) > MaxInputTokenBytes || len(env.Value) > MaxInputTokenBytes || len(env.Key)+1+len(env.Value) > MaxInputTokenBytes {
			return errInputEnvTokenTooLong
		}
	}
	return nil
}
