package conf

import (
	"testing"

	"github.com/hugefiver/fakessh/modules/gitserver"
	"github.com/stretchr/testify/assert"
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
		}, c.Modules.GitServer)
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
			expected: MaxConnectionsConfig{Max: 100, LossRate: 0, HardMax: 0},
		},
		{
			input:    "100:0.5",
			expected: MaxConnectionsConfig{Max: 100, LossRate: 0.5, HardMax: 0},
		},
		{
			input:    "100:0.5:200",
			expected: MaxConnectionsConfig{Max: 100, LossRate: 0.5, HardMax: 200},
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
				Max:      50,
				LossRate: 0,
				HardMax:  200,
			},
		},
		{
			input: "50::",
			expected: MaxConnectionsConfig{
				Max:      50,
				LossRate: 0,
				HardMax:  0,
			},
		},
	}

	for _, tt := range tts {
		r, err := parseMaxConnString(tt.input)
		assert.Equal(t, tt.expected, r)
		assert.Equal(t, tt.err, err != nil, "err: %v", err)
	}
}
