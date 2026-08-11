//go:build !no_gitserver
// +build !no_gitserver

package gitserver

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseGitCommandAcceptsGitSSHForms verifies the parser accepts the two
// canonical Git SSH exec forms (hyphenated single-token command, and
// "git <subcommand>" two-token form) with optional single quotes and an
// optional leading slash on the repository path.
func TestParseGitCommandAcceptsGitSSHForms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		cmd   string
		op    Operation
		repo  string
	}{
		{"hyphenated_single_quoted", "git-upload-pack 'project.git'", "git-upload-pack", OperationRead, "project.git"},
		{"hyphenated_unquoted", "git-receive-pack team/project.git", "git-receive-pack", OperationWrite, "team/project.git"},
		{"hyphenated_leading_slash", "git-upload-archive /team/project.git", "git-upload-archive", OperationRead, "team/project.git"},
		{"split_form_single_quoted", "git upload-pack 'team/project.git'", "git-upload-pack", OperationRead, "team/project.git"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseGitCommand(tt.input)
			require.NoError(t, err, "input: %q", tt.input)
			assert.Equal(t, tt.cmd, got.Command)
			assert.Equal(t, tt.op, got.Operation)
			assert.Equal(t, tt.repo, got.RepoPath)
			assert.Empty(t, got.BackendPath, "ParseGitCommand must not populate BackendPath")
		})
	}
}

// TestParseGitCommandRejectsUnsafeInput verifies the parser rejects every
// class of unsafe or malformed input the Git SSH service must never honor:
// foreign commands, shell metacharacters, command chaining, command
// substitution, variable expansion, path traversal, Windows-style paths,
// unmatched quotes, extra tokens, and NUL/control characters.
func TestParseGitCommandRejectsUnsafeInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{"foreign_command", "bash -c id"},
		{"semicolon_chain", "git-upload-pack 'project.git'; id"},
		{"and_chain", "git-upload-pack project.git && id"},
		{"backtick_substitution", "git-upload-pack `id`"},
		{"variable_expansion", "git-upload-pack $HOME/project.git"},
		{"traversal_dotdot", "git-upload-pack ../secret.git"},
		{"traversal_mid_double", "git-upload-pack team/../../secret.git"},
		{"traversal_mid_single", "git-upload-pack team/../secret.git"},
		{"windows_drive", "git-upload-pack C:/repo.git"},
		{"unc_path", "git-upload-pack \\server\\share\\repo.git"},
		{"unterminated_quote", "git-upload-pack 'unterminated"},
		{"extra_token", "git-upload-pack project.git extra"},
		{"nul_byte", "git-upload-pack \x00project.git"},
		{"pipe_metachar", "git-upload-pack project.git | cat"},
		{"dollar_metachar", "git-upload-pack $(id)"},
		{"redir_metachar", "git-upload-pack project.git > /tmp/x"},
		{"parens_metachar", "git-upload-pack (project.git)"},
		{"amp_metachar", "git-upload-pack project.git &"},
		{"lt_metachar", "git-upload-pack project.git < /etc/passwd"},
		{"empty_command", ""},
		{"whitespace_only", "    "},
		{"unknown_hyphen_command", "git-foo project.git"},
		{"unknown_subcommand", "git foo project.git"},
		{"single_token", "git-upload-pack"},
		{"three_tokens_split_form", "git upload-pack project.git extra"},
		{"newline_control_char", "git-upload-pack project.git\nid"},
		{"carriage_return_control_char", "git-upload-pack project.git\rid"},
		{"control_char_in_repo", "git-upload-pack pro\x01ject.git"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseGitCommand(tt.input)
			assert.Error(t, err, "input: %q", tt.input)
		})
	}
}

// TestParseGitCommandNormalizesRepoPath confirms the parser runs the repo
// token through NormalizeRepoPath, collapsing redundant slashes and trailing
// slashes and stripping a single leading slash, while still rejecting
// traversal.
func TestParseGitCommandNormalizesRepoPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		repo  string
	}{
		{"git-upload-pack team//project.git", "team/project.git"},
		{"git-upload-pack team/project.git/", "team/project.git"},
		{"git-upload-pack /team/./project.git", "team/project.git"},
	}
	for _, tt := range tests {
		got, err := ParseGitCommand(tt.input)
		require.NoError(t, err, "input: %q", tt.input)
		assert.Equal(t, tt.repo, got.RepoPath, "input: %q", tt.input)
	}
}

// TestAuthorizeDistinguishesReadAndWrite verifies that:
//   - a read_keys fingerprint may read but not write;
//   - a write_keys fingerprint may both read and write;
//   - the returned Request carries the configured BackendPath.
func TestAuthorizeDistinguishesReadAndWrite(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, &Config{
		Enable: true,
		Repositories: []RepositoryConfig{{
			Path:        "project.git",
			BackendPath: "internal/project.git",
			ReadKeys:    []string{"SHA256:read"},
			WriteKeys:   []string{"SHA256:write"},
		}},
	})

	readPerms := permissionsForFingerprint("SHA256:read")
	writePerms := permissionsForFingerprint("SHA256:write")

	// Read key: read OK, write denied.
	readReq, err := srv.Authorize(readPerms, Request{Operation: OperationRead, RepoPath: "project.git"})
	require.NoError(t, err)
	assert.Equal(t, "internal/project.git", readReq.BackendPath)
	assert.Equal(t, "project.git", readReq.RepoPath)

	_, writeErrForReadKey := srv.Authorize(readPerms, Request{Operation: OperationWrite, RepoPath: "project.git"})
	assert.Error(t, writeErrForReadKey)

	// Write key: read OK, write OK.
	readReqForWriteKey, err := srv.Authorize(writePerms, Request{Operation: OperationRead, RepoPath: "project.git"})
	require.NoError(t, err)
	assert.Equal(t, "internal/project.git", readReqForWriteKey.BackendPath)

	writeReq, err := srv.Authorize(writePerms, Request{Operation: OperationWrite, RepoPath: "project.git"})
	require.NoError(t, err)
	assert.Equal(t, "internal/project.git", writeReq.BackendPath)
}

// TestAuthorizeAcceptsLeadingSlashAndNormalizesRepoPath verifies Authorize
// re-normalizes the repo path so a request carrying a leading slash still
// matches a configured repository stored without one.
func TestAuthorizeAcceptsLeadingSlashAndNormalizesRepoPath(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, &Config{
		Enable: true,
		Repositories: []RepositoryConfig{{
			Path:      "team/project.git",
			ReadKeys:  []string{"SHA256:read"},
			WriteKeys: []string{"SHA256:write"},
		}},
	})

	perms := permissionsForFingerprint("SHA256:read")
	req, err := srv.Authorize(perms, Request{Operation: OperationRead, RepoPath: "/team/project.git"})
	require.NoError(t, err)
	assert.Equal(t, "team/project.git", req.RepoPath)
}

// TestAuthorizeDeniesUnknownRepo verifies that a request for a repository not
// present in the config is denied, even when the fingerprint would otherwise
// be authorized.
func TestAuthorizeDeniesUnknownRepo(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, &Config{
		Enable: true,
		Repositories: []RepositoryConfig{{
			Path:      "project.git",
			ReadKeys:  []string{"SHA256:read"},
			WriteKeys: []string{"SHA256:write"},
		}},
	})

	perms := permissionsForFingerprint("SHA256:read")
	_, err := srv.Authorize(perms, Request{Operation: OperationRead, RepoPath: "other.git"})
	assert.Error(t, err)
}

// TestAuthorizeDeniesUnknownFingerprint verifies that a fingerprint not in
// either ACL is denied even for a configured repository.
func TestAuthorizeDeniesUnknownFingerprint(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, &Config{
		Enable: true,
		Repositories: []RepositoryConfig{{
			Path:      "project.git",
			ReadKeys:  []string{"SHA256:read"},
			WriteKeys: []string{"SHA256:write"},
		}},
	})

	perms := permissionsForFingerprint("SHA256:intruder")
	_, err := srv.Authorize(perms, Request{Operation: OperationRead, RepoPath: "project.git"})
	assert.Error(t, err)
}

// TestAuthorizeDenyAllWhenNoACLMatch verifies that a server with no
// configured repositories denies every request.
func TestAuthorizeDenyAllWhenNoACLMatch(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, &Config{Enable: true})

	perms := permissionsForFingerprint("SHA256:anyone")
	_, err := srv.Authorize(perms, Request{Operation: OperationRead, RepoPath: "project.git"})
	assert.Error(t, err)
}

// TestAuthorizeRejectsNonGitPermission verifies Authorize refuses permissions
// that were not produced by the gitserver PublicKeyCallback.
func TestAuthorizeRejectsNonGitPermission(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, &Config{
		Enable: true,
		Repositories: []RepositoryConfig{{
			Path:     "project.git",
			ReadKeys: []string{"SHA256:read"},
		}},
	})

	_, err := srv.Authorize(nil, Request{Operation: OperationRead, RepoPath: "project.git"})
	assert.Error(t, err)

	bare := permissionsForFingerprint("SHA256:read")
	bare.Extensions = map[string]string{} // strip gitserver marker
	_, err = srv.Authorize(bare, Request{Operation: OperationRead, RepoPath: "project.git"})
	assert.Error(t, err)
}

// TestResolveLocalRepoReturnsExistingRepo verifies that a real repository
// directory under RepoRoot resolves to its absolute path and stays inside the
// root.
func TestResolveLocalRepoReturnsExistingRepo(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	repo := filepath.Join(root, "project.git")
	require.NoError(t, os.Mkdir(repo, 0o755))

	srv := newTestServer(t, &Config{
		Enable:   true,
		Backend:  BackendLocal,
		RepoRoot: root,
		Repositories: []RepositoryConfig{{
			Path:     "project.git",
			ReadKeys: []string{"SHA256:key"},
		}},
	})

	got, err := srv.ResolveLocalRepo("project.git")
	require.NoError(t, err)

	// EvalSymlinks may change the case or form of the root on Windows
	// (e.g. lowercasing the drive letter), so compare against the
	// resolved root rather than the raw temp dir.
	rootAbs, err := filepath.EvalSymlinks(root)
	require.NoError(t, err)
	expected := filepath.Join(rootAbs, "project.git")
	assert.Equal(t, expected, got)
}

// TestResolveLocalRepoRejectsMissingRepo verifies that a repository path with
// no on-disk directory under RepoRoot returns an error rather than silently
// succeeding (and never creates the directory).
func TestResolveLocalRepoRejectsMissingRepo(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	srv := newTestServer(t, &Config{
		Enable:   true,
		Backend:  BackendLocal,
		RepoRoot: root,
		Repositories: []RepositoryConfig{{
			Path:     "ghost.git",
			ReadKeys: []string{"SHA256:key"},
		}},
	})

	_, err := srv.ResolveLocalRepo("ghost.git")
	assert.Error(t, err)

	// Confirm nothing was created.
	_, statErr := os.Stat(filepath.Join(root, "ghost.git"))
	assert.Error(t, statErr)
}

// TestResolveLocalRepoRejectsSymlinkEscape verifies that a symlink inside
// RepoRoot pointing to a directory outside RepoRoot is rejected by
// ResolveLocalRepo. Symlink creation on Windows requires elevated privileges
// or developer mode; when it fails on Windows the test is skipped rather than
// failed. On Unix a symlink creation failure is a hard test failure.
func TestResolveLocalRepoRejectsSymlinkEscape(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	outside := t.TempDir()

	link := filepath.Join(root, "escape.git")
	err := os.Symlink(outside, link)
	if err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink creation unavailable on Windows: %v", err)
			return
		}
		t.Fatalf("create symlink: %v", err)
	}

	srv := newTestServer(t, &Config{
		Enable:   true,
		Backend:  BackendLocal,
		RepoRoot: root,
		Repositories: []RepositoryConfig{{
			Path:     "escape.git",
			ReadKeys: []string{"SHA256:key"},
		}},
	})

	_, err = srv.ResolveLocalRepo("escape.git")
	assert.Error(t, err)
}

// TestResolveLocalRepoRejectsTraversalRepoPath verifies that a repo path
// containing traversal segments is rejected by ResolveLocalRepo via
// NormalizeRepoPath, before it ever reaches the filesystem.
func TestResolveLocalRepoRejectsTraversalRepoPath(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	srv := newTestServer(t, &Config{
		Enable:   true,
		Backend:  BackendLocal,
		RepoRoot: root,
		Repositories: []RepositoryConfig{{
			Path:     "project.git",
			ReadKeys: []string{"SHA256:key"},
		}},
	})

	for _, bad := range []string{"../secret.git", "team/../../secret.git", "team/../secret.git"} {
		_, err := srv.ResolveLocalRepo(bad)
		assert.Error(t, err, "input: %q", bad)
	}
}
