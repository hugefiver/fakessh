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
				KeyFile:    "./sshkey",
				GenKeyFile: true,
				ServPort:   ":24",
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
				Version:    "SSH-2.0-OpenSSH_8.2p1",
				KeyFile:    "",
				GenKeyFile: false,
				ServPort:   ":22",
			},
			[]string{""},
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
