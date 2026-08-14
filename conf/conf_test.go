package conf

import (
	"testing"
	"time"

	"github.com/hugefiver/fakessh/modules/gitserver"
	"github.com/hugefiver/fakessh/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const c1 = `
[modules.gitserver]
enable = false

#user = "git"
#current_user = false
#ssh_user = "git"
#git_shell = "/usr/bin/git-shell"
#git_user_home = "/home/git"
#authorized_keys = "/home/git/.ssh/authorized_keys"
#watch_keys = false
`

const c2 = `
[modules.gitserver]
enable = true

#user = "git"
current_user = true
#ssh_user = "git"
#git_shell = "/usr/bin/git-shell"
#git_user_home = "/home/git"
#authorized_keys = "/home/git/.ssh/authorized_keys"
#watch_keys = false
`

const c3 = `
[modules.gitserver]
enable = true

user = "git"
current_user = false
ssh_user = "git"
git_shell = "/usr/bin/git-shell"
git_user_home = "/home/git"
authorized_keys = "/home/git/.ssh/authorized_keys"
watch_keys = true
`

func TestParseConfig(t *testing.T) {
	t.Parallel()
	t.Run("test_gitserver_1", func(t *testing.T) {
		c, _ := ParseConfig([]byte(c1))
		assert.Equal(t, gitserver.Config{
			Enable:         false,
			User:           "git",
			CurrentUser:    false,
			SSHUser:        "git",
			GitShell:       "git-shell",
			GitUserHome:    "/home/git",
			AuthorizedKeys: "/home/git/.ssh/authorized_keys",
			WatchKeys:      false,
			Backend:        gitserver.BackendLocal,
			RepoRoot:       "/home/git",
		}, c.Modules.GitServer)
	})

	t.Run("test_gitserver_2", func(t *testing.T) {
		c, _ := ParseConfig([]byte(c2))
		assert.Equal(t, gitserver.Config{
			Enable:         true,
			User:           "git",
			CurrentUser:    true,
			SSHUser:        "git",
			GitShell:       "git-shell",
			GitUserHome:    "/home/git",
			AuthorizedKeys: "/home/git/.ssh/authorized_keys",
			WatchKeys:      false,
			Backend:        gitserver.BackendLocal,
			RepoRoot:       "/home/git",
		}, c.Modules.GitServer)
	})

	t.Run("test_gitserver_3", func(t *testing.T) {
		c, _ := ParseConfig([]byte(c3))
		assert.Equal(t, gitserver.Config{
			Enable:         true,
			User:           "git",
			CurrentUser:    false,
			SSHUser:        "git",
			GitShell:       "/usr/bin/git-shell",
			GitUserHome:    "/home/git",
			AuthorizedKeys: "/home/git/.ssh/authorized_keys",
			WatchKeys:      true,
			Backend:        gitserver.BackendLocal,
			RepoRoot:       "/home/git",
		}, c.Modules.GitServer)
	})
}

func TestParseConfigSuccessSeedString(t *testing.T) {
	t.Parallel()

	c, err := ParseConfig([]byte("[server]\nsuccess_seed = \"anything\"\n"))
	assert.NoError(t, err)
	assert.Equal(t, "anything", c.Server.SuccessSeed)
}

func TestDefaultMaxTryFromConfig(t *testing.T) {
	t.Parallel()

	c := NewDefaultAppConfig()
	assert.Equal(t, DefaultMaxTry, c.Server.MaxTry)
}

func TestCheckConfigRejectsInvalidRateLimitsAndUsers(t *testing.T) {
	t.Parallel()

	t.Run("zero_limit", func(t *testing.T) {
		c := NewDefaultAppConfig()
		c.Server.RateLimits = []*RateLimitConfig{{Interval: utils.Duration(time.Second), Limit: 0}}
		assert.Error(t, c.CheckConfig())
	})

	t.Run("empty_user", func(t *testing.T) {
		c := NewDefaultAppConfig()
		c.Server.Users = []*User{{User: "", Password: "x"}}
		assert.Error(t, c.CheckConfig())
	})

	t.Run("empty_password", func(t *testing.T) {
		c := NewDefaultAppConfig()
		c.Server.Users = []*User{{User: "root", Password: ""}}
		assert.Error(t, c.CheckConfig())
	})
}

func TestParseMaxConnString(t *testing.T) {
	t.Parallel()
	tts := []struct {
		input    string
		expected MaxConnectionsConfig
		err      bool
	}{
		{
			input:    "100",
			expected: MaxConnectionsConfig{Max: 100, LossRatio: 0, HardMax: 0},
		},
		{
			input:    "100:0.5",
			expected: MaxConnectionsConfig{Max: 100, LossRatio: 0.5, HardMax: 0},
		},
		{
			input:    "100:0.5:200",
			expected: MaxConnectionsConfig{Max: 100, LossRatio: 0.5, HardMax: 200},
		},
		{
			input:    "abc",
			expected: MaxConnectionsConfig{},
			err:      true,
		},
		{
			input:    "100:abc",
			expected: MaxConnectionsConfig{},
			err:      true,
		},
		{
			input:    "100:0.5:abc",
			expected: MaxConnectionsConfig{},
			err:      true,
		},
		{
			input: "50::200",
			expected: MaxConnectionsConfig{
				Max:       50,
				LossRatio: 0,
				HardMax:   200,
			},
		},
		{
			input: "50::",
			expected: MaxConnectionsConfig{
				Max:       50,
				LossRatio: 0,
				HardMax:   0,
			},
		},
	}

	for _, tt := range tts {
		r, err := parseMaxConnString(tt.input)
		assert.Equal(t, tt.expected, r)
		assert.Equal(t, tt.err, err != nil, "err: %v", err)
	}
}

func TestDefaultAppConfigFillsGitserverDefaults(t *testing.T) {
	t.Parallel()

	c := NewDefaultAppConfig()
	assert.Equal(t, gitserver.BackendLocal, c.Modules.GitServer.Backend)
	assert.Equal(t, "git", c.Modules.GitServer.User)
	assert.Equal(t, "git", c.Modules.GitServer.SSHUser)
	assert.Equal(t, "git-shell", c.Modules.GitServer.GitShell)
	assert.Equal(t, "/home/git", c.Modules.GitServer.GitUserHome)
	assert.Equal(t, "/home/git", c.Modules.GitServer.RepoRoot)
	assert.Equal(t, "/home/git/.ssh/authorized_keys", c.Modules.GitServer.AuthorizedKeys)
}

func TestMergeConfigRoutesGitserverOptions(t *testing.T) {
	t.Parallel()

	if !gitserver.Embedded {
		t.Skip("gitserver module not embedded; -o gitserver.* routing is disabled")
	}

	c := NewDefaultAppConfig()
	f := &FlagArgsStruct{
		Options: []string{
			"gitserver.enable=true",
			"gitserver.backend=ssh",
			"gitserver.user=gitboss",
			"gitserver.repo_root=/srv/repos",
			"gitserver.ssh_backend.address=git.example.com:22",
			"gitserver.ssh_backend.timeout_seconds=42",
		},
	}
	set := StringSet{}

	err := MergeConfig(c, f, set)
	assert.NoError(t, err)

	assert.True(t, c.Modules.GitServer.Enable)
	assert.Equal(t, gitserver.BackendSSH, c.Modules.GitServer.Backend)
	assert.Equal(t, "gitboss", c.Modules.GitServer.User)
	assert.Equal(t, "/srv/repos", c.Modules.GitServer.RepoRoot)
	assert.Equal(t, "git.example.com:22", c.Modules.GitServer.SSHBackend.Address)
	assert.Equal(t, 42, c.Modules.GitServer.SSHBackend.TimeoutSeconds)
}

// TestParseConfigDerivesGitserverDefaultsFromUser verifies that when the TOML
// config sets only `user`, the derived SSHUser follows the final user value
// rather than staying pinned to the pre-decode default "git". This is the
// regression for the stale-derived-defaults blocker.
func TestParseConfigDerivesGitserverDefaultsFromUser(t *testing.T) {
	t.Parallel()

	const src = `
[modules.gitserver]
enable = true
user = "gitboss"
`
	c, err := ParseConfig([]byte(src))
	require.NoError(t, err)

	assert.Equal(t, "gitboss", c.Modules.GitServer.User)
	assert.Equal(t, "gitboss", c.Modules.GitServer.SSHUser,
		"SSHUser must derive from the decoded user, not the pre-decode default")
}

// TestParseConfigDerivesGitserverDefaultsFromHome verifies that when the TOML
// config sets only `git_user_home`, the derived RepoRoot and AuthorizedKeys
// follow the final home value rather than staying pinned to the pre-decode
// defaults based on "/home/git".
func TestParseConfigDerivesGitserverDefaultsFromHome(t *testing.T) {
	t.Parallel()

	const src = `
[modules.gitserver]
enable = true
git_user_home = "/srv/git"
`
	c, err := ParseConfig([]byte(src))
	require.NoError(t, err)

	assert.Equal(t, "/srv/git", c.Modules.GitServer.GitUserHome)
	assert.Equal(t, "/srv/git", c.Modules.GitServer.RepoRoot,
		"RepoRoot must derive from the decoded git_user_home")
	assert.Equal(t, "/srv/git/.ssh/authorized_keys", c.Modules.GitServer.AuthorizedKeys,
		"AuthorizedKeys must derive from the decoded git_user_home")
}

// TestParseConfigExplicitSSHUserOverridesDerived verifies that an explicit
// ssh_user is preserved even when user is also set (the derivation does not
// clobber an explicitly set derived field).
func TestParseConfigExplicitSSHUserOverridesDerived(t *testing.T) {
	t.Parallel()

	const src = `
[modules.gitserver]
enable = true
user = "gitboss"
ssh_user = "git"
`
	c, err := ParseConfig([]byte(src))
	require.NoError(t, err)

	assert.Equal(t, "gitboss", c.Modules.GitServer.User)
	assert.Equal(t, "git", c.Modules.GitServer.SSHUser,
		"explicit ssh_user must be preserved when user is also set")
}

// TestMergeConfigDerivesGitserverFromUserOption verifies that the CLI option
// `gitserver.user=...` keeps SSHUser in sync when SSHUser still tracks the
// old User value (the default-derived case). This is the CLI counterpart to
// TestParseConfigDerivesGitserverDefaultsFromUser.
func TestMergeConfigDerivesGitserverFromUserOption(t *testing.T) {
	t.Parallel()

	if !gitserver.Embedded {
		t.Skip("gitserver module not embedded; -o gitserver.* routing is disabled")
	}

	// Start from NewDefaultAppConfig: User="git", SSHUser="git".
	c := NewDefaultAppConfig()
	f := &FlagArgsStruct{
		Options: []string{"gitserver.user=gitboss"},
	}
	set := StringSet{}

	require.NoError(t, MergeConfig(c, f, set))

	assert.Equal(t, "gitboss", c.Modules.GitServer.User)
	assert.Equal(t, "gitboss", c.Modules.GitServer.SSHUser,
		"SSHUser must sync to the new user when it still tracks the old User")
}

// TestMergeConfigDerivesGitserverFromHomeOption verifies that the CLI option
// `gitserver.git_user_home=...` keeps RepoRoot and AuthorizedKeys in sync
// when they still track the old home (the default-derived case).
func TestMergeConfigDerivesGitserverFromHomeOption(t *testing.T) {
	t.Parallel()

	if !gitserver.Embedded {
		t.Skip("gitserver module not embedded; -o gitserver.* routing is disabled")
	}

	// Start from NewDefaultAppConfig: GitUserHome="/home/git",
	// RepoRoot="/home/git", AuthorizedKeys="/home/git/.ssh/authorized_keys".
	c := NewDefaultAppConfig()
	f := &FlagArgsStruct{
		Options: []string{"gitserver.git_user_home=/srv/git"},
	}
	set := StringSet{}

	require.NoError(t, MergeConfig(c, f, set))

	assert.Equal(t, "/srv/git", c.Modules.GitServer.GitUserHome)
	assert.Equal(t, "/srv/git", c.Modules.GitServer.RepoRoot,
		"RepoRoot must sync to the new home when it still tracks the old home")
	assert.Equal(t, "/srv/git/.ssh/authorized_keys", c.Modules.GitServer.AuthorizedKeys,
		"AuthorizedKeys must sync to the new home when it still tracks the old home")
}

// TestMergeConfigPreservesExplicitSSHUserWhenUserOptionChanges verifies that
// an explicitly set ssh_user is NOT clobbered when the user option later
// changes User.
func TestMergeConfigPreservesExplicitSSHUserWhenUserOptionChanges(t *testing.T) {
	t.Parallel()

	if !gitserver.Embedded {
		t.Skip("gitserver module not embedded; -o gitserver.* routing is disabled")
	}

	c := NewDefaultAppConfig()
	f := &FlagArgsStruct{
		Options: []string{
			"gitserver.ssh_user=gitssh",
			"gitserver.user=gitboss",
		},
	}
	set := StringSet{}

	require.NoError(t, MergeConfig(c, f, set))

	assert.Equal(t, "gitboss", c.Modules.GitServer.User)
	assert.Equal(t, "gitssh", c.Modules.GitServer.SSHUser,
		"explicit ssh_user must be preserved when user option changes")
}

// TestMergeConfigPreservesExplicitDefaultSSHUserWhenUserOptionChanges verifies
// provenance tracking, not value equality: explicitly setting ssh_user to the
// same value as the prior default must still protect it from a later user
// option.
func TestMergeConfigPreservesExplicitDefaultSSHUserWhenUserOptionChanges(t *testing.T) {
	t.Parallel()

	if !gitserver.Embedded {
		t.Skip("gitserver module not embedded; -o gitserver.* routing is disabled")
	}

	c := NewDefaultAppConfig()
	f := &FlagArgsStruct{
		Options: []string{
			"gitserver.ssh_user=git",
			"gitserver.user=gitboss",
		},
	}
	set := StringSet{}

	require.NoError(t, MergeConfig(c, f, set))

	assert.Equal(t, "gitboss", c.Modules.GitServer.User)
	assert.Equal(t, "git", c.Modules.GitServer.SSHUser,
		"explicit ssh_user equal to the old default must be preserved")
}

// TestMergeConfigPreservesTOMLExplicitDefaultSSHUserWhenUserOptionChanges
// verifies TOML provenance tracking: a config-file ssh_user explicitly set to
// the same value as the default must not be inferred as derived when a CLI
// user option is applied later.
func TestMergeConfigPreservesTOMLExplicitDefaultSSHUserWhenUserOptionChanges(t *testing.T) {
	t.Parallel()

	if !gitserver.Embedded {
		t.Skip("gitserver module not embedded; -o gitserver.* routing is disabled")
	}

	c, err := ParseConfig([]byte(`
[modules.gitserver]
enable = true
ssh_user = "git"
`))
	require.NoError(t, err)

	f := &FlagArgsStruct{Options: []string{"gitserver.user=gitboss"}}
	require.NoError(t, MergeConfig(c, f, StringSet{}))

	assert.Equal(t, "gitboss", c.Modules.GitServer.User)
	assert.Equal(t, "git", c.Modules.GitServer.SSHUser,
		"TOML-explicit ssh_user equal to the old default must be preserved")
}

// TestMergeConfigPreservesExplicitRepoRootWhenHomeOptionChanges verifies
// that explicitly set repo_root / authorized_keys are NOT clobbered when the
// git_user_home option later changes GitUserHome.
func TestMergeConfigPreservesExplicitRepoRootWhenHomeOptionChanges(t *testing.T) {
	t.Parallel()

	if !gitserver.Embedded {
		t.Skip("gitserver module not embedded; -o gitserver.* routing is disabled")
	}

	c := NewDefaultAppConfig()
	f := &FlagArgsStruct{
		Options: []string{
			"gitserver.repo_root=/custom/repos",
			"gitserver.authorized_keys=/custom/ak",
			"gitserver.git_user_home=/srv/git",
		},
	}
	set := StringSet{}

	require.NoError(t, MergeConfig(c, f, set))

	assert.Equal(t, "/srv/git", c.Modules.GitServer.GitUserHome)
	assert.Equal(t, "/custom/repos", c.Modules.GitServer.RepoRoot,
		"explicit repo_root must be preserved when git_user_home changes")
	assert.Equal(t, "/custom/ak", c.Modules.GitServer.AuthorizedKeys,
		"explicit authorized_keys must be preserved when git_user_home changes")
}

// TestMergeConfigPreservesExplicitDefaultPathsWhenHomeOptionChanges verifies
// provenance tracking for path options: explicitly setting repo_root and
// authorized_keys to values equal to the prior defaults must still protect them
// from a later git_user_home option.
func TestMergeConfigPreservesExplicitDefaultPathsWhenHomeOptionChanges(t *testing.T) {
	t.Parallel()

	if !gitserver.Embedded {
		t.Skip("gitserver module not embedded; -o gitserver.* routing is disabled")
	}

	c := NewDefaultAppConfig()
	f := &FlagArgsStruct{
		Options: []string{
			"gitserver.repo_root=/home/git",
			"gitserver.authorized_keys=/home/git/.ssh/authorized_keys",
			"gitserver.git_user_home=/srv/git",
		},
	}
	set := StringSet{}

	require.NoError(t, MergeConfig(c, f, set))

	assert.Equal(t, "/srv/git", c.Modules.GitServer.GitUserHome)
	assert.Equal(t, "/home/git", c.Modules.GitServer.RepoRoot,
		"explicit repo_root equal to the old default must be preserved")
	assert.Equal(t, "/home/git/.ssh/authorized_keys", c.Modules.GitServer.AuthorizedKeys,
		"explicit authorized_keys equal to the old default must be preserved")
}

// TestMergeConfigPreservesTOMLExplicitDefaultPathsWhenHomeOptionChanges
// verifies TOML provenance tracking for repo_root and authorized_keys values
// that are explicitly set to the same strings as the defaults.
func TestMergeConfigPreservesTOMLExplicitDefaultPathsWhenHomeOptionChanges(t *testing.T) {
	t.Parallel()

	if !gitserver.Embedded {
		t.Skip("gitserver module not embedded; -o gitserver.* routing is disabled")
	}

	c, err := ParseConfig([]byte(`
[modules.gitserver]
enable = true
repo_root = "/home/git"
authorized_keys = "/home/git/.ssh/authorized_keys"
`))
	require.NoError(t, err)

	f := &FlagArgsStruct{Options: []string{"gitserver.git_user_home=/srv/git"}}
	require.NoError(t, MergeConfig(c, f, StringSet{}))

	assert.Equal(t, "/srv/git", c.Modules.GitServer.GitUserHome)
	assert.Equal(t, "/home/git", c.Modules.GitServer.RepoRoot,
		"TOML-explicit repo_root equal to the old default must be preserved")
	assert.Equal(t, "/home/git/.ssh/authorized_keys", c.Modules.GitServer.AuthorizedKeys,
		"TOML-explicit authorized_keys equal to the old default must be preserved")
}

func TestMergeConfigRejectsUnknownModuleOption(t *testing.T) {
	t.Parallel()

	c := NewDefaultAppConfig()
	f := &FlagArgsStruct{Options: []string{"gitserver.no_such_option=value"}}

	err := MergeConfig(c, f, StringSet{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported module option")
}

func TestMergeConfigRejectsInvalidModuleOptionValue(t *testing.T) {
	t.Parallel()

	c := NewDefaultAppConfig()
	f := &FlagArgsStruct{Options: []string{"gitserver.max_git_shell_processes=not-an-int"}}

	err := MergeConfig(c, f, StringSet{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported module option")
}
