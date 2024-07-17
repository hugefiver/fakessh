package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseCmd(t *testing.T) {
	t.Parallel()

	type result struct {
		cmd  *Command
		rest string
		err  bool
	}

	tests := []struct {
		name     string
		input    string
		expected result
	}{
		{
			name:  "single command",
			input: "echo hello",
			expected: result{cmd: &Command{
				Name: "echo",
				Args: []string{"hello"},
			}},
		},
		{
			name:  "command with args",
			input: "ls -l -a",
			expected: result{cmd: &Command{
				Name: "ls",
				Args: []string{"-l", "-a"},
			}},
		},
		{
			name:  "command with env vars",
			input: "FOO=bar echo $FOO",
			expected: result{cmd: &Command{
				Name: "echo",
				Args: []string{"$FOO"},
				Opt: CommandOpt{
					Envs: []EnvPair{
						{Key: "FOO", Value: "bar"},
					},
				},
			}},
		},
		{
			name:  "command with quotes",
			input: "echo 'hello world'",
			expected: result{cmd: &Command{
				Name: "echo",
				Args: []string{"hello world"},
			}},
		},
		{
			name:     "unclosed quote",
			input:    "echo 'hello world\"",
			expected: result{cmd: nil, rest: "echo 'hello world\"", err: true},
		},
		{
			name:  "command with quotes and rest after \\n",
			input: "echo 'hello world'\nrest",
			expected: result{cmd: &Command{
				Name: "echo",
				Args: []string{"hello world"},
			},
				rest: "\nrest"},
		},
		{
			name:  "command with quotes and rest after ';'",
			input: "echo 'hello world' ;rest",
			expected: result{cmd: &Command{
				Name: "echo",
				Args: []string{"hello world"},
			},
				rest: ";rest"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, idx, err := parseCmd([]byte(tt.input), 0)

			assert.Equal(t, tt.expected.cmd, cmd)
			assert.Equal(t, string(tt.expected.rest), tt.input[idx:])
			assert.Equal(t, tt.expected.err, err != nil)
		})
	}
}
