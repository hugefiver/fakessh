package conf

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

type ArgsStruct = FlagArgsStruct

func TestGetArg(t *testing.T) {
	tests := []struct {
		name   string
		want   ArgsStruct
		set    StringSet
		osArgs []string
	}{
		// TODO: Add test cases.
		{
			"test_get_args",
			ArgsStruct{
				Help:       true,
				LogFile:    "/tmp/fakessh.log",
				LogFormat:  "json",
				LogLevel:   "debug",
				SSHVersion: "7.0",
				KeyFiles:   []string{"./sshkey"},
				GenKeyFile: true,
				ServPort:   ":24",
				AntiScan:   true,
				MaxTry:     3,
			},
			NewStringSet("help", "log", "format", "level", "bind", "version", "key", "gen"),
			[]string{
				"",
				"-help",
				"-log", "/tmp/fakessh.log",
				"-format", "json",
				"-level", "debug",
				"-bind", ":24",
				"-version", "7.0",
				"-key", "./sshkey",
				"-gen",
			},
		},
		{
			"test_get_args_default",
			ArgsStruct{
				Help:       false,
				LogFile:    "",
				LogFormat:  "plain",
				LogLevel:   "info",
				SSHVersion: DefaultSSHVersion,
				KeyFiles:   []string{},
				GenKeyFile: false,
				ServPort:   ":22",
				AntiScan:   true,
				MaxTry:     3,
			},
			NewStringSet(),
			[]string{""},
		},
		{
			"test_get_args_set_a_flag",
			ArgsStruct{
				Help:       false,
				LogFile:    "",
				LogFormat:  "plain",
				LogLevel:   "info",
				SSHVersion: DefaultSSHVersion,
				KeyFiles:   []string{},
				GenKeyFile: false,
				ServPort:   ":22",
				AntiScan:   true,
				MaxTry:     3,
			},

			NewStringSet("a"),
			[]string{"", "-a"},
		},
		{
			"test_get_args_set_A_flag",
			ArgsStruct{
				Help:       false,
				LogFile:    "",
				LogFormat:  "plain",
				LogLevel:   "info",
				SSHVersion: DefaultSSHVersion,
				KeyFiles:   []string{},
				GenKeyFile: false,
				ServPort:   ":22",
				AntiScan:   false,
				MaxTry:     3,
			},
			NewStringSet("A"),
			[]string{"", "-A"},
		},
		{
			"test_get_args_files",
			ArgsStruct{
				Help:       false,
				LogFile:    "",
				LogFormat:  "plain",
				LogLevel:   "info",
				SSHVersion: DefaultSSHVersion,
				KeyFiles:   []string{"./a", "b", "/tmp/c"},
				GenKeyFile: false,
				ServPort:   ":22",
				AntiScan:   true,
				MaxTry:     3,
			},
			NewStringSet("key"),
			[]string{"", "-key", "./a", "-key", "b", "-key", "/tmp/c"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Args = tt.osArgs
			got, set, _ := GetArg()

			assert.EqualValues(t, &tt.want, got, "GetArg().args")
			if set != nil {
				assert.EqualValues(t, tt.set, set, "GetArg().used")
			}
		})
	}
}
