//go:build !no_gitserver && (linux || freebsd || openbsd || darwin)
// +build !no_gitserver
// +build linux freebsd openbsd darwin

package gitserver

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"

	"github.com/hugefiver/fakessh/third/ssh"
)

// localMinimalPath is the PATH passed to the local git-shell child. It is
// intentionally narrow so the git user cannot accidentally resolve binaries
// from outside the standard system directories.
const localMinimalPath = "/usr/bin:/bin"

// errLocalBackendUnavailable is returned by serveLocal on platforms where the
// local backend is not supported. The unsupported build provides the same
// sentinel via a stub so cross-package error assertions are stable.
var errLocalBackendUnavailable = errors.New("gitserver: local git-shell backend unavailable on this platform")

// buildLocalCommand constructs the *exec.Cmd that runs the authorized Git
// request under the configured git-shell, as a fixed argv with no shell
// interpretation. It does not start the process.
//
// The argv is exactly:
//
//	[GitShell, "-c", "<Command> '<absoluteRepo>'"]
//
// where <Command> is req.Command (already whitelisted to one of
// git-upload-pack / git-receive-pack / git-upload-archive by ParseGitCommand)
// and <absoluteRepo> is the filepath.EvalSymlinks-resolved absolute path of
// req.BackendPath under RepoRoot (via ResolveLocalRepo). BackendPath is filled
// by Authorize from repository config, so local and SSH backends honor the same
// frontend path -> backend path aliasing contract.
//
// Before forming the -c argument, the resolved repoRoot and absoluteRepo are
// passed through rejectUnsafeLocalPath. ResolveLocalRepo confines the
// resolved path to live under RepoRoot and NormalizeRepoPath constrains the
// request path's charset, but a symlink whose target is inside RepoRoot can
// still have a real path containing a single quote / NUL / CR / LF that
// would break the single-quoted token or inject into the child. The
// resolved-path check closes that gap.
//
// cmd.Dir is set to the configured RepoRoot's real (EvalSymlinks-resolved)
// path so git-shell launches with the repositories root as its working
// directory, not the individual repository directory. The per-repo path is
// still passed to git via the -c argument.
//
// The environment is minimal: HOME, USER, LOGNAME, PATH, and GIT_PROTOCOL
// (only when gitProtocol == "version=2").
func (s *Server) buildLocalCommand(req Request, gitProtocol string) (*exec.Cmd, error) {
	backendPath := req.BackendPath
	if backendPath == "" {
		backendPath = req.RepoPath
	}
	absoluteRepo, err := s.ResolveLocalRepo(backendPath)
	if err != nil {
		return nil, fmt.Errorf("gitserver: resolve local repo: %w", err)
	}

	repoRoot, err := filepath.EvalSymlinks(s.config.RepoRoot)
	if err != nil {
		return nil, fmt.Errorf("gitserver: resolve repo root: %w", err)
	}

	// Defense-in-depth: ResolveLocalRepo confines the resolved path to live
	// under RepoRoot, but a symlink whose target is inside RepoRoot can
	// still have a real path containing characters (single quote or control
	// characters) that would break the single-quoted token in the -c argument or
	// inject into the spawned process. CheckAndFillConfig already validated
	// the configured RepoRoot, but the EvalSymlinks-resolved root and the
	// resolved repo path may differ (e.g. root itself is a symlink, or a
	// repo path resolves through a symlink to a directory with a quote in
	// its name). Reject both before forming the command.
	if err := rejectUnsafeLocalPath("resolved repo_root", repoRoot); err != nil {
		return nil, err
	}
	if err := rejectUnsafeLocalPath("resolved repository path", absoluteRepo); err != nil {
		return nil, err
	}

	uid, gid, err := GetUid(s.config.User, s.config.CurrentUser)
	if err != nil {
		return nil, fmt.Errorf("gitserver: resolve git user: %w", err)
	}

	command := req.Command + " '" + absoluteRepo + "'"
	cmd := ExecWithUid(uid, gid, s.config.GitShell, "-c", command)
	cmd.Dir = repoRoot
	cmd.Env = s.localEnv(gitProtocol)
	return cmd, nil
}

// localEnv returns the minimal environment slice for a local git-shell child.
func (s *Server) localEnv(gitProtocol string) []string {
	env := []string{
		"HOME=" + s.config.GitUserHome,
		"USER=" + s.config.User,
		"LOGNAME=" + s.config.User,
		"PATH=" + localMinimalPath,
	}
	if gitProtocol == gitProtocolEnvValue {
		env = append(env, gitProtocolEnvName+"="+gitProtocol)
	}
	return env
}

// serveLocal is the local-backend implementation of backendRunner. It
// enforces the MaxGitShellProcesses concurrency limit, drops privileges to
// the configured git user via ExecWithUid, and pipes the ssh.Channel to the
// child git-shell process's stdin/stdout/stderr. Context cancellation kills
// the child and waits for it to exit.
func (s *Server) serveLocal(ctx context.Context, req Request, gitProtocol string, channel ssh.Channel) error {
	acquired, err := s.acquireLocalSlot(ctx)
	if err != nil {
		return err
	}
	if !acquired {
		return errLocalSlotsBusy
	}
	defer s.releaseLocalSlot()

	cmd, err := s.buildLocalCommand(req, gitProtocol)
	if err != nil {
		return err
	}

	cmd.Stdin = channel
	cmd.Stdout = channel
	cmd.Stderr = channel.Stderr()

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("gitserver: start git-shell: %w", err)
	}

	waitErr := make(chan error, 1)
	go func() {
		waitErr <- cmd.Wait()
	}()

	select {
	case err := <-waitErr:
		return err
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		<-waitErr
		return ctx.Err()
	}
}
