package main

import (
	"os"
	"reflect"
	"testing"
)

func TestGetArg(t *testing.T) {
	os.Args = []string{
		"",
		"-help",
		"-log", "/tmp/fakessh.log",
		"-format", "json",
		"-level", "debug",
		"-bind", ":24",
		"-version", "7.0",
		"-key", "./sshkey",
		"-gen",
	}

	tests := []struct {
		name string
		want ArgsStruct
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
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetArg(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetArg() = %v, want %v", got, tt.want)
			}
		})
	}
}
