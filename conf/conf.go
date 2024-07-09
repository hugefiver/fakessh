package conf

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hugefiver/fakessh/modules/gitserver"
	"github.com/pelletier/go-toml/v2"
)

type Duration time.Duration

func (d *Duration) UnmarshalText(text []byte) error {
	if n, err := strconv.ParseFloat(string(text), 64); err == nil {
		*d = Duration(time.Duration(n*1000) * time.Millisecond)
		return nil
	}

	if n, err := time.ParseDuration(string(text)); err == nil {
		*d = Duration(n)
		return nil
	}
	return fmt.Errorf("cannot unmarshal %q into a Duration", text)
}

func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

type AppConfig struct {
	BaseConfig

	Modules ModulesConfig `toml:"modules"`
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

type RateLimitConfig struct {
	Interval Duration `toml:"interval"`
	Limit    int      `toml:"limit"`
	PerIP    bool     `toml:"per_ip,omitempty"`
}

type ModulesConfig struct {
	GitServer gitserver.Config `toml:"gitserver"`
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

	c.BaseConfig.FillDefault()

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
		for _, s := range f.RateLimits {
			// format "interval:limit"
			// or "interval:limit:perip"/"interval:limit:p" or "interval:limit:global"/"interval:limit:g", default global
			// or "interval:limit;interval:limit" for multiple rate limits in one string
			rs := strings.Split(s, ";")
			for _, r := range rs {
				r = strings.TrimSpace(r)
				if r == "" {
					continue
				}

				r, err := parseRateLimit(r)
				if err != nil {
					return err
				}

				c.Server.RateLimits = append(c.Server.RateLimits, r)
			}
		}
	}
	return nil
}

func parseRateLimit(s string) (*RateLimitConfig, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 && len(parts) != 3 {
		return nil, fmt.Errorf("invalid rate limit string: '%s', expected format: `interval:limit[:tag]`", s)
	}

	perip := false
	if len(parts) == 3 {
		switch strings.ToLower(parts[2]) {
		case "p", "perip":
			perip = true
		default:
		}
	}

	var interval Duration
	if err := interval.UnmarshalText([]byte(parts[0])); err != nil {
		return nil, err
	}
	limit, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, err
	}
	return &RateLimitConfig{interval, limit, perip}, nil
}
