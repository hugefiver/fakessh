package conf

import (
	"os"
	"reflect"
	"testing"
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
			nil,
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
			if !reflect.DeepEqual(*got, tt.want) {
				t.Errorf("GetArg().args = %v, want %v", *got, tt.want)
			}

			if set != nil && !set.Equals(tt.set) {
				t.Errorf("GetArg().used = %v, want %v", set.Keys(), tt.set.Keys())
			}
		})
	}
}
