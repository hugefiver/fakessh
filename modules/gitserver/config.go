package gitserver

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/hugefiver/fakessh/modules"
)

// Backend names supported by the gitserver.
const (
	BackendLocal = "local"
	BackendSSH   = "ssh"
)

// RepositoryConfig describes a single git repository exposed by the gitserver.
type RepositoryConfig struct {
	Path        string   `toml:"path"`
	BackendPath string   `toml:"backend_path"`
	ReadKeys    []string `toml:"read_keys"`
	WriteKeys   []string `toml:"write_keys"`
}

// SSHBackendConfig holds connection details for the SSH backend, used when
// Backend == BackendSSH to proxy git requests to a remote git server.
type SSHBackendConfig struct {
	Address        string `toml:"address"`
	User           string `toml:"user"`
	KeyFile        string `toml:"key_file"`
	KnownHosts     string `toml:"known_hosts"`
	TimeoutSeconds int    `toml:"timeout_seconds"`
}

type Config struct {
	Enable bool `toml:"enable"`

	User        string `toml:"user"`
	CurrentUser bool   `toml:"current_user"`
	SSHUser     string `toml:"ssh_user"`

	GitShell    string `toml:"git_shell"`
	GitUserHome string `toml:"git_user_home"`

	AuthorizedKeys string `toml:"authorized_keys"`
	WatchKeys      bool   `toml:"watch_keys"`

	MaxGitShellProcesses int  `toml:"max_git_shell_processes"`
	RefuseWhenBusy       bool `toml:"refuse_when_busy"`

	// Backend selects where repositories are stored/served from. Valid
	// values are BackendLocal ("local") and BackendSSH ("ssh"). Defaults to
	// BackendLocal when empty.
	Backend string `toml:"backend"`

	// RepoRoot is the root directory under which local repositories live.
	// Defaults to GitUserHome.
	RepoRoot string `toml:"repo_root"`

	// Repositories is the list of explicitly configured repositories. When
	// Enable is true and this list is empty, the server denies all git
	// access (deny-all).
	Repositories []RepositoryConfig `toml:"repositories"`

	// SSHBackend holds connection settings for the SSH backend. Only
	// consulted when Backend == BackendSSH.
	SSHBackend SSHBackendConfig `toml:"ssh_backend"`
}

func (c *Config) FillDefault() error {
	if c.User == "" {
		c.User = "git"
	}

	if c.SSHUser == "" {
		c.SSHUser = c.User
	}

	if c.GitShell == "" {
		c.GitShell = "git-shell"
	}

	if c.GitUserHome == "" {
		c.GitUserHome = "/home/git"
	}

	if c.RepoRoot == "" {
		c.RepoRoot = c.GitUserHome
	}

	if c.AuthorizedKeys == "" {
		c.AuthorizedKeys = c.GitUserHome + "/.ssh/authorized_keys"
	}

	if c.Backend == "" {
		c.Backend = BackendLocal
	}

	if c.MaxGitShellProcesses < 0 {
		c.MaxGitShellProcesses = 0
	}
	return nil
}

// CheckAndFillConfig validates and normalizes a gitserver Config. It is safe
// to call with a nil pointer.
func CheckAndFillConfig(c *Config) error {
	if c == nil {
		return nil
	}

	if err := c.FillDefault(); err != nil {
		return err
	}

	switch c.Backend {
	case BackendLocal, BackendSSH:
		// ok
	default:
		return fmt.Errorf("gitserver: unknown backend %q", c.Backend)
	}

	if c.Backend == BackendSSH {
		b := &c.SSHBackend
		var missing []string
		if b.Address == "" {
			missing = append(missing, "address")
		}
		if b.User == "" {
			missing = append(missing, "user")
		}
		if b.KeyFile == "" {
			missing = append(missing, "key_file")
		}
		if b.KnownHosts == "" {
			missing = append(missing, "known_hosts")
		}
		if len(missing) > 0 {
			return fmt.Errorf("gitserver: ssh backend requires %s", strings.Join(missing, ", "))
		}
		if b.TimeoutSeconds <= 0 {
			b.TimeoutSeconds = 30
		}
	}

	// Local backend paths must not carry characters that could be used to
	// inject arguments or break line-based config files.
	if c.Backend == BackendLocal {
		if err := rejectUnsafeLocalPath("repo_root", c.RepoRoot); err != nil {
			return err
		}
		if err := rejectUnsafeLocalPath("git_user_home", c.GitUserHome); err != nil {
			return err
		}
	}

	seen := make(map[string]struct{}, len(c.Repositories))
	for i := range c.Repositories {
		r := &c.Repositories[i]

		normalized, err := NormalizeRepoPath(r.Path)
		if err != nil {
			return fmt.Errorf("gitserver: repository %d: %w", i, err)
		}
		r.Path = normalized

		if r.BackendPath == "" {
			r.BackendPath = r.Path
		} else {
			bp, err := NormalizeRepoPath(r.BackendPath)
			if err != nil {
				return fmt.Errorf("gitserver: repository %d backend_path: %w", i, err)
			}
			r.BackendPath = bp
		}

		if _, ok := seen[r.Path]; ok {
			return fmt.Errorf("gitserver: duplicate repository %q", r.Path)
		}
		seen[r.Path] = struct{}{}

		r.ReadKeys = trimACL(r.ReadKeys)
		r.WriteKeys = trimACL(r.WriteKeys)
	}

	return nil
}

// trimACL removes surrounding whitespace from each fingerprint and drops
// empty entries.
func trimACL(keys []string) []string {
	if len(keys) == 0 {
		return nil
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k != "" {
			out = append(out, k)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// rejectUnsafeLocalPath returns an error if s contains a control character or
// a single quote. These characters could be used to break line-oriented config
// files or perform argument injection into spawned processes.
func rejectUnsafeLocalPath(field, s string) error {
	for _, ch := range s {
		if unicode.IsControl(ch) || ch == '\'' {
			return fmt.Errorf("gitserver: %s contains forbidden character", field)
		}
	}
	return nil
}

// MergeOptions applies a single -o gitserver.key=value option to the config.
// It returns true if the option was handled (module == "gitserver" and key is
// a known scalar), false otherwise. Repository ACLs are TOML-only and cannot
// be set via options.
func (c *Config) MergeOptions(opt *modules.Opt) bool {
	if strings.ToLower(opt.Module) != "gitserver" {
		return false
	}

	switch strings.ToLower(opt.Key) {
	case "enable":
		c.Enable = boolFromStr(opt.Value)
	case "backend":
		c.Backend = opt.Value
	case "user":
		c.User = opt.Value
	case "current_user":
		c.CurrentUser = boolFromStr(opt.Value)
	case "ssh_user":
		c.SSHUser = opt.Value
	case "git_shell":
		c.GitShell = opt.Value
	case "git_user_home":
		c.GitUserHome = opt.Value
	case "repo_root":
		c.RepoRoot = opt.Value
	case "authorized_keys":
		c.AuthorizedKeys = opt.Value
	case "watch_keys":
		c.WatchKeys = boolFromStr(opt.Value)
	case "max_git_shell_processes":
		n, err := strconv.Atoi(opt.Value)
		if err != nil {
			return false
		}
		c.MaxGitShellProcesses = n
	case "refuse_when_busy":
		c.RefuseWhenBusy = boolFromStr(opt.Value)
	case "ssh_backend.address":
		c.SSHBackend.Address = opt.Value
	case "ssh_backend.user":
		c.SSHBackend.User = opt.Value
	case "ssh_backend.key_file":
		c.SSHBackend.KeyFile = opt.Value
	case "ssh_backend.known_hosts":
		c.SSHBackend.KnownHosts = opt.Value
	case "ssh_backend.timeout_seconds":
		n, err := strconv.Atoi(opt.Value)
		if err != nil {
			return false
		}
		c.SSHBackend.TimeoutSeconds = n
	default:
		return false
	}
	return true
}

// boolFromStr mirrors the helper in modules/fakeshell/conf. It is duplicated
// here because we cannot import fakeshell/conf without creating a cycle.
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
