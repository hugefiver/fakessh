package main

import (
	"flag"
	"fmt"
	"os"
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

	// Wait time
	Delay     int
	Deviation int

	// Log password
	Passwd bool
}

// GetArg : get args
func GetArg() (ArgsStruct, func()) {
	/*if _args != nil {
		return *_args
	}*/
	args := ArgsStruct{}
	f := flag.NewFlagSet("FakeSSH", flag.ExitOnError)

	f.BoolVar(&args.Help, "h", false, "show this page")
	f.BoolVar(&args.Help, "help", false, "show this page")

	f.StringVar(&args.LogFile, "log", "", "log `file`")
	f.StringVar(&args.LogLevel, "level", "info", "log level: `[debug|info|warning]`")
	f.StringVar(&args.LogFormat, "format", "plain", "log format: `[plain|json]`")

	f.StringVar(&args.KeyFile, "key", "", "key file path")
	f.BoolVar(&args.GenKeyFile, "gen", false, "generate a private key to key file path")

	f.StringVar(&args.ServPort, "bind", ":22", "binding `port`")
	f.StringVar(&args.Version, "version", "OpenSSH_8.2p1", "ssh server version")

	f.IntVar(&args.Delay, "delay", 0, "wait time for each login (ms)")
	f.IntVar(&args.Deviation, "devia", 0, "deviation for wait time (ms)")

	f.BoolVar(&args.Passwd, "passwd", false, "log password to file")

	f.Parse(os.Args[1:])
	//_args = &args
	return args, f.Usage
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
