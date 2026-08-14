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

	gitserverExplicit gitserverExplicitState
}

type ModulesConfig struct {
	GitServer gitserver.Config `toml:"gitserver"`
	FakeShell fakeshell.Config `toml:"fakeshell"`
}

type gitserverExplicitState struct {
	SSHUser        bool
	RepoRoot       bool
	AuthorizedKeys bool
}

func (c *AppConfig) FillDefault() {
	c.BaseConfig.FillDefault()

	c.Modules.FillDefault()
}

func (c *ModulesConfig) FillDefault() {
	c.GitServer.FillDefault()
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
		SuccessSeed  string  `toml:"success_seed"`

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
	c.Server.MaxTry = DefaultMaxTry
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

	for _, r := range c.Server.RateLimits {
		if r == nil {
			return errors.New("nil rate limit config")
		}
		if r.Interval.Duration() <= 0 {
			return fmt.Errorf("rate limit interval must be positive: %v", r.Interval.Duration())
		}
		if r.Limit <= 0 {
			return fmt.Errorf("rate limit limit must be positive: %d", r.Limit)
		}
	}

	users := make(map[string]struct{}, len(c.Server.Users))
	for _, u := range c.Server.Users {
		if u == nil {
			return errors.New("nil user config")
		}
		if u.User == "" {
			return errors.New("user name cannot be empty")
		}
		if u.Password == "" {
			return fmt.Errorf("password for user %q cannot be empty", u.User)
		}
		if _, ok := users[u.User]; ok {
			return fmt.Errorf("duplicated user: %s", u.User)
		}
		users[u.User] = struct{}{}
	}
	return nil
}

func (c *AppConfig) CheckConfig() error {
	if err := c.BaseConfig.CheckConfig(); err != nil {
		return err
	}
	return c.Modules.CheckConfig()
}

func (c *ModulesConfig) CheckConfig() error {
	if c.GitServer.Enable && !gitserver.Embedded {
		return errors.New("gitserver module is not embedded but config enables it")
	}
	if gitserver.Embedded {
		if err := gitserver.CheckAndFillConfig(&c.GitServer); err != nil {
			return err
		}
	}
	if fakeshell.Embedded {
		return fakeshell.CheckAndFillConfig(&c.FakeShell)
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
	var explicit gitserverTOMLExplicitFields

	// Pre-fill only the base config and fakeshell defaults before TOML
	// decode. GitServer's derived defaults (SSHUser from User, RepoRoot /
	// AuthorizedKeys from GitUserHome) must NOT be applied here: if we
	// filled them now, a TOML file that only sets `user` or
	// `git_user_home` would leave the derived fields pinned to the
	// pre-decode defaults (e.g. SSHUser="git" when user="gitboss") instead
	// of deriving from the final TOML value. We fill GitServer after
	// decode so empty derived fields resolve against the decoded base
	// fields.
	config.BaseConfig.FillDefault()
	config.Modules.FakeShell.FillDefault()

	if err := toml.Unmarshal(s, &explicit); err != nil {
		return nil, err
	}
	config.gitserverExplicit = explicit.state()

	if err := toml.Unmarshal(s, &config); err != nil {
		return nil, err
	}

	// Fill default values of Modules.GitServer now that TOML has decoded
	// the base fields (User, GitUserHome). Empty derived fields (SSHUser,
	// RepoRoot, AuthorizedKeys) resolve against the decoded values.
	if err := config.Modules.GitServer.FillDefault(); err != nil {
		return nil, err
	}

	return &config, nil
}

type gitserverTOMLExplicitFields struct {
	Modules struct {
		GitServer struct {
			SSHUser        *string `toml:"ssh_user"`
			RepoRoot       *string `toml:"repo_root"`
			AuthorizedKeys *string `toml:"authorized_keys"`
		} `toml:"gitserver"`
	} `toml:"modules"`
}

func (f gitserverTOMLExplicitFields) state() gitserverExplicitState {
	return gitserverExplicitState{
		SSHUser:        f.Modules.GitServer.SSHUser != nil && *f.Modules.GitServer.SSHUser != "",
		RepoRoot:       f.Modules.GitServer.RepoRoot != nil && *f.Modules.GitServer.RepoRoot != "",
		AuthorizedKeys: f.Modules.GitServer.AuthorizedKeys != nil && *f.Modules.GitServer.AuthorizedKeys != "",
	}
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
	gitState := newGitserverOptionState(c.Modules.GitServer, c.gitserverExplicit)

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
			c.Server.SuccessSeed = f.SuccessSeed
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

	for i := range f.Options {
		raw := f.Options[i]
		o, err := modules.ParseOpt(raw)
		if err != nil {
			return err
		}

		switch o.Module {
		case "fakeshell":
			if !fakeshell.Embedded || !c.Modules.FakeShell.MergeOptions(o) {
				return fmt.Errorf("unsupported module option %q", raw)
			}
		case "gitserver":
			if !gitserver.Embedded {
				return fmt.Errorf("unsupported module option %q", raw)
			}
			gitState.note(o.Key)
			if !c.Modules.GitServer.MergeOptions(o) {
				return fmt.Errorf("unsupported module option %q", raw)
			}
		default:
			return fmt.Errorf("unsupported module option %q", raw)
		}
	}

	if gitserver.Embedded {
		gitState.apply(&c.Modules.GitServer)
	}

	return nil
}

type gitserverOptionState struct {
	initialUser           string
	initialGitUserHome    string
	initialSSHUser        string
	initialRepoRoot       string
	initialAuthorizedKeys string

	userSet           bool
	gitUserHomeSet    bool
	sshUserSet        bool
	repoRootSet       bool
	authorizedKeysSet bool
}

func newGitserverOptionState(c gitserver.Config, explicit gitserverExplicitState) gitserverOptionState {
	return gitserverOptionState{
		initialUser:           c.User,
		initialGitUserHome:    c.GitUserHome,
		initialSSHUser:        c.SSHUser,
		initialRepoRoot:       c.RepoRoot,
		initialAuthorizedKeys: c.AuthorizedKeys,
		sshUserSet:            explicit.SSHUser,
		repoRootSet:           explicit.RepoRoot,
		authorizedKeysSet:     explicit.AuthorizedKeys,
	}
}

func (s *gitserverOptionState) note(key string) {
	switch strings.ToLower(key) {
	case "user":
		s.userSet = true
	case "git_user_home":
		s.gitUserHomeSet = true
	case "ssh_user":
		s.sshUserSet = true
	case "repo_root":
		s.repoRootSet = true
	case "authorized_keys":
		s.authorizedKeysSet = true
	}
}

func (s gitserverOptionState) apply(c *gitserver.Config) {
	if s.userSet && !s.sshUserSet && (s.initialSSHUser == "" || s.initialSSHUser == s.initialUser) {
		c.SSHUser = c.User
	}

	if s.gitUserHomeSet {
		if !s.repoRootSet && (s.initialRepoRoot == "" || s.initialRepoRoot == s.initialGitUserHome) {
			c.RepoRoot = c.GitUserHome
		}

		oldAuthorizedKeys := s.initialGitUserHome + "/.ssh/authorized_keys"
		if !s.authorizedKeysSet && (s.initialAuthorizedKeys == "" || s.initialAuthorizedKeys == oldAuthorizedKeys) {
			c.AuthorizedKeys = c.GitUserHome + "/.ssh/authorized_keys"
		}
	}
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
