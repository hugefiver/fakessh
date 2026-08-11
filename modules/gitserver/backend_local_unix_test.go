//go:build !no_gitserver && (linux || freebsd || openbsd || darwin)
// +build !no_gitserver
// +build linux freebsd openbsd darwin

package gitserver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildLocalCommandConstructsGitShellArgvAndEnv verifies that
// buildLocalCommand produces a *exec.Cmd whose argv, Dir, and Env exactly
// match the hardened local-backend contract:
//
//   - argv is exactly [GitShell, "-c", "git-<service> '<absoluteRepo>'"]
//     with no shell interpretation, where <absoluteRepo> is the resolved
//     repository path under RepoRoot;
//   - cmd.Dir is the configured RepoRoot's real (EvalSymlinks-resolved)
//     path, not the per-repo directory;
//   - env contains HOME=<GitUserHome>, USER=<User>, LOGNAME=<User>,
//     PATH=/usr/bin:/bin, and GIT_PROTOCOL=version=2 (because the test passes
//     gitProtocol="version=2").
//
// The test creates a real temp repo directory under a temp RepoRoot so
// ResolveLocalRepo's EvalSymlinks confinement check passes.
func TestBuildLocalCommandConstructsGitShellArgvAndEnv(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	repo := filepath.Join(root, "project.git")
	require.NoError(t, os.Mkdir(repo, 0o755))

	srv := newTestServer(t, &Config{
		Enable:       true,
		Backend:      BackendLocal,
		GitShell:     "/usr/bin/git-shell",
		GitUserHome:  "/home/git",
		User:         "git",
		CurrentUser:  true,
		RepoRoot:     root,
		Repositories: []RepositoryConfig{{Path: "project.git", ReadKeys: []string{"SHA256:k"}}},
	})

	// Resolve the expected absolute repo path (used in argv) and the
	// configured RepoRoot real path (used as cmd.Dir) the same way the
	// server does.
	rootAbs, err := filepath.EvalSymlinks(root)
	require.NoError(t, err)
	expectedRepo := filepath.Join(rootAbs, "project.git")

	req := Request{
		Command:   "git-upload-pack",
		Operation: OperationRead,
		RepoPath:  "project.git",
	}

	cmd, err := srv.buildLocalCommand(req, "version=2")
	require.NoError(t, err)
	require.NotNil(t, cmd)

	expectedCommand := "git-upload-pack '" + expectedRepo + "'"
	assert.Equal(t, "/usr/bin/git-shell", cmd.Path, "cmd.Path must be the configured git-shell")
	assert.Equal(t, []string{"/usr/bin/git-shell", "-c", expectedCommand}, cmd.Args, "cmd.Args must be the fixed argv with no shell expansion")
	assert.Equal(t, rootAbs, cmd.Dir, "cmd.Dir must be the configured RepoRoot's real path, not the per-repo directory")

	// Env must contain the required minimal entries. Extra entries are
	// allowed (e.g. future additions) so this asserts presence, not exact
	// equality.
	envHas := func(kv string) bool {
		for _, e := range cmd.Env {
			if e == kv {
				return true
			}
		}
		return false
	}
	assert.True(t, envHas("HOME=/home/git"), "env must contain HOME=/home/git, got %v", cmd.Env)
	assert.True(t, envHas("USER=git"), "env must contain USER=git, got %v", cmd.Env)
	assert.True(t, envHas("LOGNAME=git"), "env must contain LOGNAME=git, got %v", cmd.Env)
	assert.True(t, envHas("PATH=/usr/bin:/bin"), "env must contain PATH=/usr/bin:/bin, got %v", cmd.Env)
	assert.True(t, envHas("GIT_PROTOCOL=version=2"), "env must contain GIT_PROTOCOL=version=2, got %v", cmd.Env)
}

// TestBuildLocalCommandOmitsGitProtocolWhenEmpty verifies that when
// gitProtocol is empty (the client did not send a GIT_PROTOCOL env), the
// child env does not contain GIT_PROTOCOL.
func TestBuildLocalCommandOmitsGitProtocolWhenEmpty(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	repo := filepath.Join(root, "project.git")
	require.NoError(t, os.Mkdir(repo, 0o755))

	srv := newTestServer(t, &Config{
		Enable:       true,
		Backend:      BackendLocal,
		GitShell:     "/usr/bin/git-shell",
		GitUserHome:  "/home/git",
		User:         "git",
		CurrentUser:  true,
		RepoRoot:     root,
		Repositories: []RepositoryConfig{{Path: "project.git", ReadKeys: []string{"SHA256:k"}}},
	})

	req := Request{
		Command:   "git-receive-pack",
		Operation: OperationWrite,
		RepoPath:  "project.git",
	}

	cmd, err := srv.buildLocalCommand(req, "")
	require.NoError(t, err)
	require.NotNil(t, cmd)

	for _, e := range cmd.Env {
		assert.NotContains(t, e, "GIT_PROTOCOL=", "env must not contain GIT_PROTOCOL when gitProtocol is empty, got %v", cmd.Env)
	}
}

// TestBuildLocalCommandUsesBackendPath verifies local backend path aliasing:
// frontend ACL path (Path/RepoPath) and on-disk backend path (BackendPath) can
// differ, and git-shell must open BackendPath just like the SSH backend does.
func TestBuildLocalCommandUsesBackendPath(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	backendRepo := filepath.Join(root, "internal", "project.git")
	require.NoError(t, os.MkdirAll(backendRepo, 0o755))

	srv := newTestServer(t, &Config{
		Enable:      true,
		Backend:     BackendLocal,
		GitShell:    "/usr/bin/git-shell",
		GitUserHome: "/home/git",
		User:        "git",
		CurrentUser: true,
		RepoRoot:    root,
		Repositories: []RepositoryConfig{{
			Path:        "public.git",
			BackendPath: "internal/project.git",
			ReadKeys:    []string{"SHA256:k"},
		}},
	})

	rootAbs, err := filepath.EvalSymlinks(root)
	require.NoError(t, err)
	expectedRepo := filepath.Join(rootAbs, "internal", "project.git")

	req := Request{
		Command:     "git-upload-pack",
		Operation:   OperationRead,
		RepoPath:    "public.git",
		BackendPath: "internal/project.git",
	}

	cmd, err := srv.buildLocalCommand(req, "")
	require.NoError(t, err)
	require.NotNil(t, cmd)

	expectedCommand := "git-upload-pack '" + expectedRepo + "'"
	assert.Equal(t, []string{"/usr/bin/git-shell", "-c", expectedCommand}, cmd.Args)
	assert.NotContains(t, cmd.Args[2], "public.git", "local backend must not resolve the frontend ACL path when BackendPath is set")
}

// TestBuildLocalCommandRejectsMissingRepo verifies that buildLocalCommand
// returns an error when the requested repo does not exist on disk (the
// ResolveLocalRepo confinement check fails).
func TestBuildLocalCommandRejectsMissingRepo(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	srv := newTestServer(t, &Config{
		Enable:       true,
		Backend:      BackendLocal,
		GitShell:     "/usr/bin/git-shell",
		GitUserHome:  "/home/git",
		User:         "git",
		RepoRoot:     root,
		Repositories: []RepositoryConfig{{Path: "ghost.git", ReadKeys: []string{"SHA256:k"}}},
	})

	req := Request{
		Command:   "git-upload-pack",
		Operation: OperationRead,
		RepoPath:  "ghost.git",
	}

	_, err := srv.buildLocalCommand(req, "")
	assert.Error(t, err, "buildLocalCommand must fail when the repo does not exist on disk")
}

// TestBuildLocalCommandCredentialDropsGroups verifies that ExecWithUid sets
// a syscall.Credential with the resolved uid/gid and a Groups slice of
// exactly one element (the gid), so the child does not inherit the parent's
// supplementary groups.
func TestBuildLocalCommandCredentialDropsGroups(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	repo := filepath.Join(root, "project.git")
	require.NoError(t, os.Mkdir(repo, 0o755))

	srv := newTestServer(t, &Config{
		Enable:       true,
		Backend:      BackendLocal,
		GitShell:     "/usr/bin/git-shell",
		GitUserHome:  "/home/git",
		User:         "git",
		CurrentUser:  true,
		RepoRoot:     root,
		Repositories: []RepositoryConfig{{Path: "project.git", ReadKeys: []string{"SHA256:k"}}},
	})

	req := Request{Command: "git-upload-pack", Operation: OperationRead, RepoPath: "project.git"}

	cmd, err := srv.buildLocalCommand(req, "version=2")
	require.NoError(t, err)
	require.NotNil(t, cmd)

	require.NotNil(t, cmd.SysProcAttr, "SysProcAttr must be set by ExecWithUid")
	require.NotNil(t, cmd.SysProcAttr.Credential, "Credential must be set")
	require.Len(t, cmd.SysProcAttr.Credential.Groups, 1, "Groups must have exactly one entry to avoid inheriting supplementary groups")
	assert.Equal(t, cmd.SysProcAttr.Credential.Gid, cmd.SysProcAttr.Credential.Groups[0], "the single Groups entry must equal Gid")
}

// TestBuildLocalCommandRejectsSymlinkTargetWithUnsafeChar verifies that
// buildLocalCommand rejects a repository whose request path is safe
// ("project.git") but whose on-disk symlink target resolves to a directory
// under the same RepoRoot whose name contains a single quote. The resolved
// real path would break the single-quoted token in the -c argument, so the
// defense-in-depth rejectUnsafeLocalPath check on the resolved path must
// catch it before the command is formed.
//
// The symlink target is intentionally placed INSIDE RepoRoot so that
// ResolveLocalRepo's confinement check (filepath.Rel under root) passes -
// this isolates the test to the resolved-path charset check rather than the
// escape check, which is already covered by TestResolveLocalRepoRejectsSymlinkEscape.
//
// On Unix a symlink creation failure is a hard test failure (not a skip).
func TestBuildLocalCommandRejectsSymlinkTargetWithUnsafeChar(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	// Create a real target directory under root whose name contains a
	// single quote. This is a legal directory name on Unix.
	target := filepath.Join(root, "bad'repo.git")
	require.NoError(t, os.Mkdir(target, 0o755))

	// Create a symlink "project.git" -> "bad'repo.git" inside the same
	// root. The request path "project.git" is charset-safe; only its
	// resolved real path carries the quote.
	link := filepath.Join(root, "project.git")
	require.NoError(t, os.Symlink(target, link))

	srv := newTestServer(t, &Config{
		Enable:       true,
		Backend:      BackendLocal,
		GitShell:     "/usr/bin/git-shell",
		GitUserHome:  "/home/git",
		User:         "git",
		CurrentUser:  true,
		RepoRoot:     root,
		Repositories: []RepositoryConfig{{Path: "project.git", ReadKeys: []string{"SHA256:k"}}},
	})

	req := Request{Command: "git-upload-pack", Operation: OperationRead, RepoPath: "project.git"}

	_, err := srv.buildLocalCommand(req, "")
	require.Error(t, err, "buildLocalCommand must reject a resolved repo path containing a single quote")
	assert.Contains(t, err.Error(), "forbidden character",
		"error must come from the resolved-path charset check")
}
