package main

import (
	"os"
	"reflect"
	"testing"
)

func TestGetArg(t *testing.T) {
	tests := []struct {
		name   string
		want   ArgsStruct
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
				Version:    "7.0",
				KeyFiles:   []string{"./sshkey"},
				GenKeyFile: true,
				ServPort:   ":24",
				AntiScan:   true,
				MaxTry:     3,
			},
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
				Version:    "OpenSSH_8.2p1",
				KeyFiles:   []string{},
				GenKeyFile: false,
				ServPort:   ":22",
				AntiScan:   true,
				MaxTry:     3,
			},
			[]string{""},
		},
		{
			"test_get_args_set_a_flag",
			ArgsStruct{
				Help:       false,
				LogFile:    "",
				LogFormat:  "plain",
				LogLevel:   "info",
				Version:    "OpenSSH_8.2p1",
				KeyFiles:   []string{},
				GenKeyFile: false,
				ServPort:   ":22",
				AntiScan:   true,
				MaxTry:     3,
			},
			[]string{"", "-a"},
		},
		{
			"test_get_args_set_A_flag",
			ArgsStruct{
				Help:       false,
				LogFile:    "",
				LogFormat:  "plain",
				LogLevel:   "info",
				Version:    "OpenSSH_8.2p1",
				KeyFiles:   []string{},
				GenKeyFile: false,
				ServPort:   ":22",
				AntiScan:   false,
				MaxTry:     3,
			},
			[]string{"", "-A"},
		},
		{
			"test_get_args_files",
			ArgsStruct{
				Help:       false,
				LogFile:    "",
				LogFormat:  "plain",
				LogLevel:   "info",
				Version:    "OpenSSH_8.2p1",
				KeyFiles:   []string{"./a", "b", "/tmp/c"},
				GenKeyFile: false,
				ServPort:   ":22",
				AntiScan:   true,
				MaxTry:     3,
			},
			[]string{"", "-key", "./a", "-key", "b", "-key", "/tmp/c"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Args = tt.osArgs
			if got, _ := GetArg(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetArg() = %v, want %v", got, tt.want)
			}
		})
	}
}
