package conf

import (
	"flag"
	"fmt"
	"os"
)

// var _args *ArgsStruct

// FlagArgsStruct : a struct of args
type FlagArgsStruct struct {
	Help       bool
	AppVersion bool

	// Log
	LogFile   string
	LogLevel  string
	LogFormat string

	// Key
	KeyFiles   []string
	GenKeyFile bool
	KeyType    string

	// Serve
	ServPort   string
	SSHVersion string

	// Wait time
	Delay     int
	Deviation int

	// Log password
	IsLogPasswd bool

	// Anti honeypot scan
	AntiScan bool

	// Max try times
	MaxTry int

	// ConfigPath
	ConfigPath string

	// Success Ratio
	SuccessRatio float64

	// Success Seed
	SuccessSeed string

	// Rate Limit
	RateLimits []string

	// Users
	Users []string

	// Max connections
	MaxConns string

	// Max success connections
	MaxSuccConns string
}

// GetArg : get args
func GetArg() (args *FlagArgsStruct, set StringSet, helper func()) {
	/*if _args != nil {
		return *_args
	}*/
	args = &FlagArgsStruct{
		KeyFiles: []string{},
	}
	f := flag.NewFlagSet("FakeSSH", flag.ExitOnError)

	f.BoolVar(&args.Help, "h", false, "show this page")
	f.BoolVar(&args.Help, "help", false, "show this page")
	f.BoolVar(&args.AppVersion, "V", false, "show version of this binary")

	f.StringVar(&args.LogFile, "log", "", "log `file`")
	f.StringVar(&args.LogLevel, "level", DefaultLogLevel, "log level: `[debug|info|warning]`")
	f.StringVar(&args.LogFormat, "format", DefaultLogFormat, "log format: `[plain|json]`")

	StringArrayVar(f, &args.KeyFiles, "key", "key file `path`, can set more than one")
	f.BoolVar(&args.GenKeyFile, "gen", false, "generate a private key to key file path")
	f.StringVar(&args.KeyType, "type", "", "type for generate private key (default \"ed25519\")")

	f.StringVar(&args.ServPort, "bind", DefaultBind, "binding `addr`")
	f.StringVar(&args.SSHVersion, "version", DefaultSSHVersion, "ssh server version")

	f.IntVar(&args.Delay, "delay", DefaultDelay, "wait time for each login (ms)")
	f.IntVar(&args.Deviation, "devia", DefaultDeviation, "deviation for wait time (ms)")

	f.BoolVar(&args.IsLogPasswd, "passwd", false, "log password to file")

	var NoAntiScan, AntiScan bool
	f.BoolVar(&NoAntiScan, "A", false, "disable anti honeypot scan")
	f.BoolVar(&AntiScan, "a", false, "enable anti honeypot scan (default)")

	f.IntVar(&args.MaxTry, "try", DefaultMaxTry, "max try times")

	f.StringVar(&args.ConfigPath, "c", "", "config `path`")
	f.StringVar(&args.ConfigPath, "config", "", "config `path`")

	f.Float64Var(&args.SuccessRatio, "r", DefaultSuccessRatio, "success ratio float percent age (0.0 ~ 100.0, default: 0)")
	f.StringVar(&args.SuccessSeed, "seed", "", "success seed (any string)")

	StringArrayVar(f, &args.RateLimits, "rate", "rate limit in format `interval:limit`")

	StringArrayVar(f, &args.Users, "user", "users in format `user:password`, can set more than one")

	f.StringVar(&args.MaxConns, "maxconn", "", "max unauthenticated connections in format `max:loss_ratio:hard_max`, optionalable, see README")
	f.StringVar(&args.MaxConns, "max", "", "see `maxconn`")
	f.StringVar(&args.MaxConns, "mc", "", "see `maxconn`")
	f.StringVar(&args.MaxSuccConns, "maxsuccconn", "", "max success connections in format `max:loss_rate:hard_max`, see maxconn")
	f.StringVar(&args.MaxSuccConns, "maxsucc", "", "see `maxsuccconn`")
	f.StringVar(&args.MaxSuccConns, "msc", "", "see `maxsuccconn`")

	f.Parse(os.Args[1:])
	//_args = &args

	// if NoAntiScan is set and AntiScan not set, disable it
	args.AntiScan = true
	if !AntiScan && NoAntiScan {
		args.AntiScan = false
	}

	// detect used flags
	usedFlagsSet := StringSet{}
	f.Visit(func(f *flag.Flag) {
		usedFlagsSet.Add(f.Name)
	})

	return args, usedFlagsSet, f.Usage
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

func StringArrayVar(f *flag.FlagSet, ps *[]string, name, usage string) {
	f.Var((*FlagValues)(ps), name, usage)
}
