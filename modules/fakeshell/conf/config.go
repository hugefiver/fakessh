package conf

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hugefiver/fakessh/modules"
)

type FakeshellConfig struct {
	Enable bool `toml:"enable"`

	EnvConfig `toml:"env"`

	RootFS string `toml:"rootfs"`

	LogConfig `toml:"log"`
}

type LogConfig struct {
	Enable bool `toml:"enable"`

	Path     string `toml:"path"`
	Compress string `toml:"compress"`
}

// DefaultLogPath is the default session-log directory used when LogConfig.Path
// is empty. It is relative to the server's working directory. The logger
// creates this directory with 0700 permissions on first use.
const DefaultLogPath = "./sessions"

func (c *FakeshellConfig) fillDefault() {
	c.EnvConfig.FillDefault()
}

func (c *FakeshellConfig) FillDefault() {
	c.fillDefault()
}

func CheckAndFillConfig(c *FakeshellConfig) error {
	if c == nil {
		return nil
	}
	if err := c.EnvConfig.CheckAndFill(); err != nil {
		return err
	}
	if err := validateRootFSConfig(c.RootFS); err != nil {
		return err
	}
	if err := validateLogConfig(&c.LogConfig); err != nil {
		return err
	}
	return nil
}

// validateRootFSConfig validates the rootfs config value.
//
// An empty rootfs is valid and means the embedded rootfs will be used at
// load time. A non-empty rootfs must point to an existing path on the host
// that is either a directory or a supported archive file (".tar", ".tar.gz",
// ".tgz", ".zip"). Any other value is rejected so that an attacker-supplied
// path can never become an unsafe host operation. This function performs
// only metadata checks (Lstat / extension) and never reads file contents.
//
// Lstat (not Stat) is used so that a symlink rootfs is detected here rather
// than later at load time; the loader also rejects symlink roots via Lstat,
// so this keeps validation and load behavior consistent.
func validateRootFSConfig(root string) error {
	if root == "" {
		return nil
	}

	// Reject NUL / control characters outright; they have no legitimate use
	// in a filesystem path and can be used to confuse path handling.
	if err := rejectControlChars(root); err != nil {
		return fmt.Errorf("fakeshell: rootfs %q: %w", root, err)
	}

	info, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("fakeshell: rootfs %q is not accessible: %w", root, err)
	}

	// Reject symlink / special-file roots at validation time, matching the
	// loader's Lstat-based checks.
	mode := info.Mode()
	if mode&os.ModeSymlink != 0 {
		return fmt.Errorf("fakeshell: rootfs %q is a symlink, not allowed", root)
	}
	if mode&os.ModeDevice != 0 || mode&os.ModeNamedPipe != 0 || mode&os.ModeSocket != 0 || mode&os.ModeIrregular != 0 {
		return fmt.Errorf("fakeshell: rootfs %q is a special file, not allowed", root)
	}

	if mode.IsDir() {
		return nil
	}
	if !mode.IsRegular() {
		return fmt.Errorf("fakeshell: rootfs %q is not a regular file or directory", root)
	}

	if !isSupportedArchiveExt(root) {
		return fmt.Errorf("fakeshell: rootfs %q has unsupported type; want a directory or one of .tar, .tar.gz, .tgz, .zip", root)
	}

	return nil
}

// isSupportedArchiveExt reports whether name has a supported archive
// extension. The check is case-insensitive on the extension.
func isSupportedArchiveExt(name string) bool {
	lower := strings.ToLower(filepath.Ext(name))
	switch lower {
	case ".tar", ".zip":
		return true
	}
	// Two-suffix .tar.gz / .tgz
	if lower == ".gz" {
		if strings.ToLower(filepath.Ext(strings.TrimSuffix(name, filepath.Ext(name)))) == ".tar" {
			return true
		}
	}
	if lower == ".tgz" {
		return true
	}
	return false
}

// validateLogConfig validates the session-log config.
//
// When logging is DISABLED, no validation is performed: an empty/unknown
// compress value or a non-existent path is harmless because no logger is
// created. A default path is still filled in so a config dump is
// self-consistent, but the path is NOT required to exist when disabled.
//
// When logging is ENABLED:
//   - Path defaults to DefaultLogPath ("./sessions") when empty. A non-empty
//     path must not contain NUL or control characters.
//   - Compress must be one of "" (no compression) or "gzip". Other values
//     (e.g. "xz", "zstd") are rejected so an operator cannot accidentally
//     select an unsupported codec; the logger only implements gzip.
//
// This function performs NO filesystem access; the logger itself creates the
// directory with 0700 on first use.
func validateLogConfig(lc *LogConfig) error {
	if lc == nil {
		return nil
	}

	// Always fill the default path so a config dump is self-consistent, even
	// when disabled. When disabled we do NOT validate the path further: an
	// operator may leave a stale path and simply turn logging off.
	if lc.Path == "" {
		lc.Path = DefaultLogPath
	}

	if !lc.Enable {
		return nil
	}

	if err := rejectControlChars(lc.Path); err != nil {
		return fmt.Errorf("fakeshell: log path %q: %w", lc.Path, err)
	}

	switch strings.ToLower(lc.Compress) {
	case "", "gzip":
		// valid; normalize to lowercase so the logger can compare with
		// EqualFold but the stored config is canonical.
		lc.Compress = strings.ToLower(lc.Compress)
	default:
		return fmt.Errorf("fakeshell: log compress %q is not supported; only \"\" or \"gzip\" are allowed", lc.Compress)
	}

	return nil
}

// rejectControlChars returns an error if s contains NUL or any control
// character (< 0x20) other than the path separators '/' and '\\'. It is used
// for both rootfs and log path validation; callers wrap the returned error to
// attribute it to the specific config field.
func rejectControlChars(s string) error {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b == '/' || b == '\\' {
			continue
		}
		if b < 0x20 || b == 0x7f {
			return fmt.Errorf("path contains a control character at index %d", i)
		}
	}
	return nil
}

func (c *FakeshellConfig) MergeOptions(opt *modules.Opt) bool {
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
			if !c.EnvConfig.mergeOption(key, opt.Value) {
				return false
			}
		} else {
			return false
		}
	}

	return true
}

type EnvConfig struct {
	User     string `toml:"user"`
	Home     string `toml:"home"`
	OS       string `toml:"os"`
	Kernel   string `toml:"kernel"`
	HostName string `toml:"hostname"`

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
	case "hostname":
		c.HostName = value
	case "genenv":
		c.GenerateEnv = boolFromStr(value)
	case "envs", "env":
		if c.Envs == nil {
			c.Envs = map[string]string{}
		}
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
	default:
		return false
	}
	return true
}

func (c *EnvConfig) FillDefault() {
	if c.User == "" {
		c.User = "root"
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
	if c.Home == "" {
		if c.User == "root" {
			c.Home = "/root"
		} else {
			c.Home = "/home/" + c.User
		}
	}
	if c.GenerateEnv {
		defaultEnv := map[string]string{
			"USER": c.User,
			"HOME": c.Home,
			"NAME": c.HostName,
			"PWD":  c.Home,
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
	} else if c.Envs == nil {
		c.Envs = map[string]string{}
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
