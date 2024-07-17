package fakeshell

import (
	"maps"
	"strconv"
	"strings"

	"github.com/hugefiver/fakessh/modules"
)

type fakeshellConfig struct {
	Enable bool `toml:"enable"`

	EnvConfig `toml:"env"`

	RootFS string `toml:"rootfs"`
}

func (c *fakeshellConfig) fillDefault() {
	c.EnvConfig.FillDefault()
}

func (c *fakeshellConfig) mergeOptions(opt *modules.Opt) bool {
	if strings.ToLower(opt.Module) != "fakeshell" {
		return false
	}
	switch strings.ToLower(opt.Key) {
	case "enable":
		c.Enable = boolFromStr(opt.Value)
	case "rootfs":
		c.RootFS = opt.Value
	default:
		if strings.HasPrefix(opt.Key, "env.") {
			key := strings.TrimPrefix(opt.Key, "env.")
			c.EnvConfig.mergeOption(key, opt.Value)
		} else {
			return false
		}
	}

	return true
}

type EnvConfig struct {
	User   string `toml:"user"`
	Home   string `toml:"home"`
	OS     string `toml:"os"`
	Kernel string `toml:"kernel"`

	GenerateEnv bool `toml:"genenv,omitempty"`

	Envs map[string]string `toml:"envs"`
}

func (c *EnvConfig) mergeOption(key, value string) bool {
	switch strings.ToLower(key) {
	case "user":
		c.User = value
	case "home":
		c.Home = value
	case "os":
		c.OS = value
	case "kernel":
		c.Kernel = value
	case "genenv":
		c.GenerateEnv = boolFromStr(value)
	case "envs", "env":
		parts := strings.SplitN(value, "=", 2)
		var k, v string
		if len(parts) > 0 {
			k = strings.TrimSpace(parts[0])
		}
		if len(parts) > 1 {
			v = strings.TrimSpace(parts[1])
		}
		if k != "" {
			c.Envs[k] = v
		}
	}
	return true
}

func (c *EnvConfig) FillDefault() {
	if c.User == "" {
		c.User = "root"
	}
	if c.Home == "" {
		if c.User == "root" {
			c.Home = "/root"
		} else {
			c.Home = "/home/" + c.User
		}
	}
	if c.OS == "" {
		c.OS = "FairyOS"
	}
	if c.Kernel == "" {
		c.Kernel = "ctOS 3.1"
	}

	c.GenerateEnv = true
}

func (c *EnvConfig) CheckAndFill() error {
	if c.GenerateEnv {
		defaultEnv := map[string]string{
			"USER": c.User,
			"HOME": c.Home,
		}
		envs := make(map[string]string, len(c.Envs)+len(defaultEnv))
		maps.Copy(envs, defaultEnv)

		for k, v := range c.Envs {
			_, ok := envs[strings.ToUpper(k)]
			if ok {
				delete(envs, strings.ToUpper(k))
			}
			envs[k] = v
		}
		c.Envs = envs
	}
	return nil
}

func boolFromStr(s string) bool {
	switch strings.ToLower(s) {
	case "true", "1":
		return true
	case "false", "0", "":
		return false
	}

	i, err := strconv.Atoi(s)
	if err == nil && i != 0 {
		return true
	}
	return false
}
