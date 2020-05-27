package main

import (
	"flag"
	"fmt"
)

var _args *ArgsStruct

// ArgsStruct : a struct of args
type ArgsStruct struct {
	Help bool
	// Log
	LogFile   string
	LogLevel  string
	LogFormat string
	// Key
	KeyFile    string
	GenKeyFile bool
	// Serve
	ServPort string
	Version  string
}

// GetArg : get args
func GetArg() ArgsStruct {
	if _args != nil {
		return *_args
	}
	args := ArgsStruct{}

	flag.BoolVar(&args.Help, "h", false, "show this page")
	flag.BoolVar(&args.Help, "help", false, "show this page")

	flag.StringVar(&args.LogFile, "log", "", "log `file`")
	flag.StringVar(&args.LogLevel, "level", "info", "log level: `[debug|info|warning]`")
	flag.StringVar(&args.LogFormat, "format", "plain", "log format: `[plain|json]`")

	flag.StringVar(&args.KeyFile, "key", "", "key file path")
	flag.BoolVar(&args.GenKeyFile, "gen", false, "generate a private key to key file path")

	flag.StringVar(&args.ServPort, "bind", ":22", "binding `port`")
	flag.StringVar(&args.Version, "version", "SSH-2.0-OpenSSH_8.2p1", "ssh server version")

	flag.Parse()
	_args = &args
	return args
}

// FlagValues : for multi values
type FlagValues []string

// String : implement for `flag.Value`
func (p *FlagValues) String() string {
	return fmt.Sprint(*p)
}

// Set : implement for `flag.Value`
func (p *FlagValues) Set(v string) error {
	*p = append(*p, v)
	return nil
}
