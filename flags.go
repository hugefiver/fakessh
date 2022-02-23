package main

import (
	"flag"
	"fmt"
	"os"
)

// var _args *ArgsStruct

// ArgsStruct : a struct of args
type ArgsStruct struct {
	Help bool

	// Log
	LogFile   string
	LogLevel  string
	LogFormat string

	// Key
	KeyFiles   []string
	GenKeyFile bool
	KeyType    string

	// Serve
	ServPort string
	Version  string

	// Wait time
	Delay     int
	Deviation int

	// Log password
	Passwd bool

	// Anti honeypot scan
	AntiScan bool

	// Max try times
	MaxTry int
}

// GetArg : get args
func GetArg() (*ArgsStruct, func()) {
	/*if _args != nil {
		return *_args
	}*/
	args := &ArgsStruct{}
	f := flag.NewFlagSet("FakeSSH", flag.ExitOnError)

	f.BoolVar(&args.Help, "h", false, "show this page")
	f.BoolVar(&args.Help, "help", false, "show this page")

	f.StringVar(&args.LogFile, "log", "", "log `file`")
	f.StringVar(&args.LogLevel, "level", "info", "log level: `[debug|info|warning]`")
	f.StringVar(&args.LogFormat, "format", "plain", "log format: `[plain|json]`")

	var files = FlagValues{}
	f.Var(&files, "key", "key file `path`, can set more than one")
	f.BoolVar(&args.GenKeyFile, "gen", false, "generate a private key to key file path")
	f.StringVar(&args.KeyType, "type", "", "type for generate private key (default \"ed25519\")")

	f.StringVar(&args.ServPort, "bind", ":22", "binding `addr`")
	f.StringVar(&args.Version, "version", "OpenSSH_8.8p1", "ssh server version")

	f.IntVar(&args.Delay, "delay", 0, "wait time for each login (ms)")
	f.IntVar(&args.Deviation, "devia", 0, "deviation for wait time (ms)")

	f.BoolVar(&args.Passwd, "passwd", false, "log password to file")

	var NoAntiScan, AntiScan bool
	f.BoolVar(&NoAntiScan, "A", false, "disable anti honeypot scan")
	f.BoolVar(&AntiScan, "a", false, "enable anti honeypot scan (default)")

	f.IntVar(&args.MaxTry, "try", 3, "max try times")

	f.Parse(os.Args[1:])
	//_args = &args

	// if NoAntiScan is set and AntiScan not set, disable it
	args.AntiScan = true
	if !AntiScan && NoAntiScan {
		args.AntiScan = false
	}

	args.KeyFiles = files

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

func StringArrayVar(ps *[]string, name, usage string) {
	// TODO
}
