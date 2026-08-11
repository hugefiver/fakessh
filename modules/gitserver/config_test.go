package gitserver

import (
	"testing"

	"github.com/hugefiver/fakessh/modules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckAndFillConfigDefaults(t *testing.T) {
	t.Parallel()

	cfg := &Config{Enable: true}
	err := CheckAndFillConfig(cfg)
	require.NoError(t, err)

	assert.Equal(t, BackendLocal, cfg.Backend)
	assert.Equal(t, "git", cfg.User)
	assert.Equal(t, "git", cfg.SSHUser)
	assert.Equal(t, "git-shell", cfg.GitShell)
	assert.Equal(t, "/home/git", cfg.GitUserHome)
	assert.Equal(t, "/home/git", cfg.RepoRoot)
	assert.Equal(t, "/home/git/.ssh/authorized_keys", cfg.AuthorizedKeys)
}

func TestCheckAndFillConfigRejectsUnsafeBackend(t *testing.T) {
	t.Parallel()

	cfg := &Config{Enable: true, Backend: "proxy"}
	err := CheckAndFillConfig(cfg)
	assert.Error(t, err)
}

func TestCheckAndFillConfigRequiresSSHBackendSecurity(t *testing.T) {
	t.Parallel()

	t.Run("missing_all", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{Enable: true, Backend: BackendSSH}
		err := CheckAndFillConfig(cfg)
		assert.Error(t, err)
	})

	t.Run("missing_known_hosts", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			Enable:  true,
			Backend: BackendSSH,
			SSHBackend: SSHBackendConfig{
				Address: "git.example.com:22",
				User:    "git",
				KeyFile: "/etc/fakessh/keys/git",
			},
		}
		err := CheckAndFillConfig(cfg)
		assert.Error(t, err)
	})

	t.Run("complete_ssh_backend_ok", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			Enable:  true,
			Backend: BackendSSH,
			SSHBackend: SSHBackendConfig{
				Address:    "git.example.com:22",
				User:       "git",
				KeyFile:    "/etc/fakessh/keys/git",
				KnownHosts: "/etc/fakessh/known_hosts",
			},
		}
		err := CheckAndFillConfig(cfg)
		require.NoError(t, err)
		assert.Equal(t, 30, cfg.SSHBackend.TimeoutSeconds)
	})
}

func TestCheckAndFillConfigNormalizesRepositories(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Enable: true,
		Repositories: []RepositoryConfig{
			{Path: "/team/project.git"},
		},
	}
	err := CheckAndFillConfig(cfg)
	require.NoError(t, err)

	require.Len(t, cfg.Repositories, 1)
	assert.Equal(t, "team/project.git", cfg.Repositories[0].Path)
	assert.Equal(t, "team/project.git", cfg.Repositories[0].BackendPath)
}

func TestCheckAndFillConfigRejectsRepositoryTraversal(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Enable: true,
		Repositories: []RepositoryConfig{
			{Path: "../secret.git"},
		},
	}
	err := CheckAndFillConfig(cfg)
	assert.Error(t, err)
}

func TestCheckAndFillConfigRejectsDuplicateRepositories(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Enable: true,
		Repositories: []RepositoryConfig{
			{Path: "team/project.git"},
			{Path: "team/project.git"},
		},
	}
	err := CheckAndFillConfig(cfg)
	assert.Error(t, err)
}

func TestCheckAndFillConfigTrimsACLKeys(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Enable: true,
		Repositories: []RepositoryConfig{
			{
				Path:      "team/project.git",
				ReadKeys:  []string{"  fp:alice  ", "  ", ""},
				WriteKeys: []string{"fp:bob", ""},
			},
		},
	}
	err := CheckAndFillConfig(cfg)
	require.NoError(t, err)

	require.Len(t, cfg.Repositories, 1)
	assert.Equal(t, []string{"fp:alice"}, cfg.Repositories[0].ReadKeys)
	assert.Equal(t, []string{"fp:bob"}, cfg.Repositories[0].WriteKeys)
}

func TestCheckAndFillConfigRejectsUnsafeRepoRoot(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{
		"/home/git\rsomething",
		"/home/git\nx",
		"/home/git\tx",
		"/home/git\x00x",
		"/home/git'shell",
	} {
		cfg := &Config{Enable: true, RepoRoot: bad}
		err := CheckAndFillConfig(cfg)
		assert.Error(t, err, "expected error for repo_root %q", bad)
	}
}

func TestCheckAndFillConfigNilSafe(t *testing.T) {
	t.Parallel()
	err := CheckAndFillConfig(nil)
	assert.NoError(t, err)
}

func TestNormalizeRepoPath(t *testing.T) {
	t.Parallel()

	tts := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"leading_slash", "/team/project.git", "team/project.git", false},
		{"plain", "team/project.git", "team/project.git", false},
		{"redundant_slash", "team//project.git", "team/project.git", false},
		{"trailing_slash", "team/project.git/", "team/project.git", false},
		{"dot_segment", "team/./project.git", "team/project.git", false},
		{"empty", "", "", true},
		{"backslash", "team\\project.git", "", true},
		{"colon", "team:project.git", "", true},
		{"dot_only", ".", "", true},
		{"dotdot_only", "..", "", true},
		{"traversal", "../secret.git", "", true},
		{"traversal_mid", "team/../../secret.git", "", true},
		{"traversal_dotdot_collapsed", "team/../secret.git", "", true},
		{"traversal_dotdot_single_segment", "team/..", "", true},
		{"bad_segment_space", "team/pro ject.git", "", true},
		{"at_sign_ok", "team/@alice/project.git", "team/@alice/project.git", false},
		{"plus_ok", "team/a+b.git", "team/a+b.git", false},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeRepoPath(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMergeOptionsGitserverScalars(t *testing.T) {
	t.Parallel()

	scalarCases := []struct {
		name  string
		key   string
		value string
		check func(t *testing.T, c *Config)
	}{
		{"enable", "enable", "true", func(t *testing.T, c *Config) { assert.True(t, c.Enable) }},
		{"backend", "backend", "ssh", func(t *testing.T, c *Config) { assert.Equal(t, BackendSSH, c.Backend) }},
		{"user", "user", "gitboss", func(t *testing.T, c *Config) { assert.Equal(t, "gitboss", c.User) }},
		{"current_user", "current_user", "1", func(t *testing.T, c *Config) { assert.True(t, c.CurrentUser) }},
		{"ssh_user", "ssh_user", "gitssh", func(t *testing.T, c *Config) { assert.Equal(t, "gitssh", c.SSHUser) }},
		{"git_shell", "git_shell", "/bin/git-shell", func(t *testing.T, c *Config) { assert.Equal(t, "/bin/git-shell", c.GitShell) }},
		{"git_user_home", "git_user_home", "/srv/git", func(t *testing.T, c *Config) { assert.Equal(t, "/srv/git", c.GitUserHome) }},
		{"repo_root", "repo_root", "/srv/repos", func(t *testing.T, c *Config) { assert.Equal(t, "/srv/repos", c.RepoRoot) }},
		{"authorized_keys", "authorized_keys", "/etc/ak", func(t *testing.T, c *Config) { assert.Equal(t, "/etc/ak", c.AuthorizedKeys) }},
		{"watch_keys", "watch_keys", "1", func(t *testing.T, c *Config) { assert.True(t, c.WatchKeys) }},
		{"max_git_shell_processes", "max_git_shell_processes", "7", func(t *testing.T, c *Config) { assert.Equal(t, 7, c.MaxGitShellProcesses) }},
		{"refuse_when_busy", "refuse_when_busy", "true", func(t *testing.T, c *Config) { assert.True(t, c.RefuseWhenBusy) }},
		{"ssh_backend_address", "ssh_backend.address", "git.example.com:22", func(t *testing.T, c *Config) { assert.Equal(t, "git.example.com:22", c.SSHBackend.Address) }},
		{"ssh_backend_user", "ssh_backend.user", "deploy", func(t *testing.T, c *Config) { assert.Equal(t, "deploy", c.SSHBackend.User) }},
		{"ssh_backend_key_file", "ssh_backend.key_file", "/etc/k", func(t *testing.T, c *Config) { assert.Equal(t, "/etc/k", c.SSHBackend.KeyFile) }},
		{"ssh_backend_known_hosts", "ssh_backend.known_hosts", "/etc/kh", func(t *testing.T, c *Config) { assert.Equal(t, "/etc/kh", c.SSHBackend.KnownHosts) }},
		{"ssh_backend_timeout", "ssh_backend.timeout_seconds", "42", func(t *testing.T, c *Config) { assert.Equal(t, 42, c.SSHBackend.TimeoutSeconds) }},
	}

	for _, tt := range scalarCases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := &Config{}
			opt := &modules.Opt{Module: "gitserver", Key: tt.key, Value: tt.value}
			ok := c.MergeOptions(opt)
			require.True(t, ok)
			tt.check(t, c)
		})
	}

	t.Run("wrong_module_returns_false", func(t *testing.T) {
		t.Parallel()
		c := &Config{}
		opt := &modules.Opt{Module: "fakeshell", Key: "enable", Value: "true"}
		assert.False(t, c.MergeOptions(opt))
	})

	t.Run("repo_acl_returns_false", func(t *testing.T) {
		t.Parallel()
		c := &Config{}
		opt := &modules.Opt{Module: "gitserver", Key: "repositories.0.read_keys", Value: "fp:abc"}
		assert.False(t, c.MergeOptions(opt))
	})

	t.Run("unknown_key_returns_false", func(t *testing.T) {
		t.Parallel()
		c := &Config{}
		opt := &modules.Opt{Module: "gitserver", Key: "totally_unknown", Value: "x"}
		assert.False(t, c.MergeOptions(opt))
	})
}
