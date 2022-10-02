package gitserver

import "path"

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

	if c.AuthorizedKeys == "" {
		c.AuthorizedKeys = path.Join(c.GitUserHome, ".ssh/authorized_keys")
	}

	if c.MaxGitShellProcesses < 0 {
		c.MaxGitShellProcesses = 0
	}
	return nil
}
