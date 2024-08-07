package conf

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/hugefiver/fakessh/modules"
	"github.com/hugefiver/fakessh/modules/fakeshell"
	"github.com/hugefiver/fakessh/modules/gitserver"
	"github.com/hugefiver/fakessh/utils"
	"github.com/pelletier/go-toml/v2"
)

type RateLimitConfig = utils.RateLimitConfig

const DefaultMaxConnections = 100
const DefaultHardMaxConnections = 65535

const DefaultMaxSuccessConnections = 5
const DefaultHardMaxSucessConnections = 10

type AppConfig struct {
	BaseConfig

	Modules ModulesConfig `toml:"modules"`
}

type ModulesConfig struct {
	GitServer gitserver.Config `toml:"gitserver"`
	FakeShell fakeshell.Config `toml:"fakeshell"`
}

func (c *AppConfig) FillDefault() {
	c.BaseConfig.FillDefault()

	c.Modules.FillDefault()
}

func (c *ModulesConfig) FillDefault() {
	c.FakeShell.FillDefault()
}

type BaseConfig struct {
	Server struct {
		ServPort   string `toml:"bind"`
		SSHVersion string `toml:"version"`

		MaxTry    int `toml:"max_try"`
		Delay     int `toml:"delay"`
		Deviation int `toml:"deviation"`

		AntiScan bool `toml:"anti_scan"`

		SuccessRatio float64 `toml:"success_ratio"`
		SuccessSeed  []byte  `toml:"success_seed"`

		RateLimits []*RateLimitConfig `toml:"rate_limit"`

		Users []*User `toml:"users"`

		MaxConn     MaxConnectionsConfig `toml:"max_conn"`
		MaxSuccConn MaxConnectionsConfig `toml:"max_succ_conn"`
	} `toml:"server"`

	Log struct {
		LogFile     string `toml:"file"`
		LogLevel    string `toml:"level"`
		LogFormat   string `toml:"format"`
		IsLogPasswd bool   `toml:"log_passwd"`
	} `toml:"log"`

	Key struct {
		KeyFiles []string `toml:"key"`
		KeyType  string   `toml:"type"`
	} `toml:"key"`
}

type User struct {
	User     string `toml:"user"`
	Password string `toml:"password"`
}

type MaxConnectionsConfig struct {
	Max       int     `toml:"max"`
	HardMax   int     `toml:"hard_max,omitempty"`
	LossRatio float64 `toml:"loss_ratio,omitempty"`
}

func (c *BaseConfig) FillDefault() error {
	c.Server.ServPort = DefaultBind
	c.Server.SSHVersion = DefaultSSHVersion
	c.Server.Delay = DefaultDelay
	c.Server.Deviation = DefaultDeviation
	c.Server.AntiScan = DefaultEnableAntiScan

	c.Log.LogLevel = DefaultLogLevel
	c.Log.LogFormat = DefaultLogFormat
	c.Log.IsLogPasswd = false

	c.Key.KeyType = DefaultKeyType

	return nil
}

func (c *BaseConfig) CheckConfig() error {
	r := c.Server.SuccessRatio
	if r > 100 || r < 0 {
		return fmt.Errorf("`SuccessRatio` must between 0. and 100., but got %f", r)
	}

	users := make(map[string]struct{}, len(c.Server.Users))
	for _, u := range c.Server.Users {
		if _, ok := users[u.User]; ok {
			return fmt.Errorf("duplicated user: %s", u.User)
		}
		users[u.User] = struct{}{}
	}
	return nil
}

// func (c *AppConfig) FillDefault() error {
// 	if err := c.BaseConfig.FillDefault(); err != nil {
// 		return err
// 	}

// 	if err := c.Modules.GitServer.FillDefault(); err != nil {
// 		return err
// 	}
// 	return nil
// }

func NewDefaultAppConfig() *AppConfig {
	c := &AppConfig{}

	c.FillDefault()

	return c
}

func ParseConfig(s []byte) (*AppConfig, error) {
	var config AppConfig
	config.FillDefault()

	if err := toml.Unmarshal(s, &config); err != nil {
		return nil, err
	}

	// Fill default values of Modules.GitServer
	if err := config.Modules.GitServer.FillDefault(); err != nil {
		return nil, err
	}

	return &config, nil
}

func LoadFromFile(file string) (*AppConfig, error) {
	r, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	s, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return ParseConfig(s)
}

func MergeConfig(c *AppConfig, f *FlagArgsStruct, set StringSet) error {
	var enableAnti, disableAnti bool

	set.ForEach(func(s string) error {
		switch s {
		case FlagBind:
			c.Server.ServPort = f.ServPort
		case FlagSSHVersion:
			c.Server.SSHVersion = f.SSHVersion
		case FlagMaxTry:
			c.Server.MaxTry = f.MaxTry
		case FlagDelay:
			c.Server.Delay = f.Delay
		case FlagDeviation:
			c.Server.Deviation = f.Deviation

		case FlagLogFile:
			c.Log.LogFile = f.LogFile
		case FlagLogLevel:
			c.Log.LogLevel = f.LogLevel
		case FlagLogFormat:
			c.Log.LogFormat = f.LogFormat
		case FlagLogPasswd:
			c.Log.IsLogPasswd = f.IsLogPasswd

		case FlagKeyPaths:
			c.Key.KeyFiles = f.KeyFiles
		case FlagKeyType:
			c.Key.KeyType = f.KeyType
		case FlagEnableAntiScan:
			enableAnti = true
		case FlagDisableAntiScan:
			disableAnti = true
		case FlagSuccessRatio:
			c.Server.SuccessRatio = f.SuccessRatio
		case FlagSuccessSeed:
			c.Server.SuccessSeed = []byte(f.SuccessSeed)
		}
		return nil
	})

	if enableAnti || disableAnti {
		c.Server.AntiScan = enableAnti
	}

	if len(f.RateLimits) > 0 {
		rs, err := utils.ParseCmdlineRateLimits(f.RateLimits)
		if err != nil {
			return err
		}
		c.Server.RateLimits = append(c.Server.RateLimits, rs...)
	}

	if len(f.Users) > 0 {
		for _, u := range f.Users {
			xs := strings.SplitN(u, ":", 2)
			if len(xs) != 2 {
				return fmt.Errorf("invalid user password format: %q", u)
			}
			if xs[0] == "" {
				return errors.New("user name cannot be empty")
			}

			c.Server.Users = append(c.Server.Users, &User{User: xs[0], Password: xs[1]})
		}
	}

	if f.MaxConns != "" {
		mc, err := parseMaxConnString(f.MaxConns)
		if err != nil {
			return err
		}
		c.Server.MaxConn = mc
	}

	if f.MaxSuccConns != "" {
		mc, err := parseMaxConnString(f.MaxSuccConns)
		if err != nil {
			return err
		}
		c.Server.MaxSuccConn = mc
	}

	for _, o := range f.Options {
		o, err := modules.ParseOpt(o)
		if err != nil {
			return err
		}

		switch o.Module {
		case "fakeshell":
			if fakeshell.Embedded {
				c.Modules.FakeShell.MergeOptions(o)
			}
		}
	}

	return nil
}

func parseMaxConnString(s string) (MaxConnectionsConfig, error) {
	mc, hmc, ratio := 0, 0, 0.
	var err error

	xs := strings.SplitN(s, ":", 3)

	if len(xs) > 3 {
		return MaxConnectionsConfig{}, fmt.Errorf("invalid max_conns format: %q", s)
	}

	if len(xs) >= 1 {
		x := xs[0]
		if x != "" {
			mc, err = strconv.Atoi(x)
			if err != nil {
				return MaxConnectionsConfig{}, err
			}
		}
	}
	if len(xs) >= 2 {
		x := xs[1]
		if x != "" {
			ratio, err = strconv.ParseFloat(x, 64)
			if err != nil {
				return MaxConnectionsConfig{}, err
			}
		}
	}
	if len(xs) >= 3 {
		x := xs[2]
		if x != "" {
			hmc, err = strconv.Atoi(x)
			if err != nil {
				return MaxConnectionsConfig{}, err
			}
		}
	}

	return MaxConnectionsConfig{Max: mc, LossRatio: ratio, HardMax: hmc}, nil
}
