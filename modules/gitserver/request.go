//go:build !no_gitserver
// +build !no_gitserver

package gitserver

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/hugefiver/fakessh/third/ssh"
)

// Operation classifies a parsed Git request as a read or a write. It is the
// only thing the ACL layer needs to know about a request beyond the target
// repository, because git-upload-pack and git-upload-archive are strictly
// read-only and git-receive-pack is the only write path.
type Operation string

const (
	// OperationRead covers git-upload-pack (clone/fetch) and
	// git-upload-archive (archive). Read access is granted by either
	// read_keys or write_keys.
	OperationRead Operation = "read"
	// OperationWrite covers git-receive-pack (push). Write access is
	// granted only by write_keys.
	OperationWrite Operation = "write"
)

// Request is the sanitized, normalized representation of a client's Git exec
// command. It is produced by ParseGitCommand and consumed by Authorize and the
// backend dispatch layer. RepoPath is the forward-slash, NormalizeRepoPath'd
// repository path as the client supplied it; BackendPath is the
// NormalizeRepoPath'd path configured for that repository (which may differ
// from RepoPath when a fronting alias maps to a different backend repo).
type Request struct {
	// Command is the canonical hyphenated git command, e.g.
	// "git-upload-pack", "git-receive-pack", or "git-upload-archive".
	Command string
	// Operation is OperationRead or OperationWrite.
	Operation Operation
	// RepoPath is the normalized repository path the client asked for.
	RepoPath string
	// BackendPath is the normalized backend repository path populated by
	// Authorize from the matched RepositoryConfig. It is empty until
	// Authorize fills it in.
	BackendPath string
}

// gitServiceSubcommand maps the second token of the "git <subcommand> repo"
// form to its canonical hyphenated command name and operation.
var gitServiceSubcommand = map[string]struct {
	command   string
	operation Operation
}{
	"upload-pack":    {"git-upload-pack", OperationRead},
	"receive-pack":   {"git-receive-pack", OperationWrite},
	"upload-archive": {"git-upload-archive", OperationRead},
}

// gitHyphenCommand maps the "git-<service> repo" form's first token to its
// canonical command name and operation. The canonical name is identical to
// the key; the map exists so the accepted set is explicit and unknown
// hyphenated commands are rejected.
var gitHyphenCommand = map[string]struct {
	command   string
	operation Operation
}{
	"git-upload-pack":    {"git-upload-pack", OperationRead},
	"git-receive-pack":   {"git-receive-pack", OperationWrite},
	"git-upload-archive": {"git-upload-archive", OperationRead},
}

// unsafeShellMetacharacters are characters that, if they appear anywhere in
// the raw command string, cause ParseGitCommand to reject the input
// immediately. They are shell-meaningful even inside a properly-quoted token
// in some contexts (e.g. when the parsed command is later re-assembled into a
// `git-shell -c` invocation), so rejecting them up front is defense in depth
// rather than reliance on the tokenizer alone. Backtick is included as the
// Go raw-string form of "`".
var unsafeShellMetacharacters = ";&|`$<>()"

// tokenize splits a command string into shell-like tokens. It supports
// unquoted tokens (split on ASCII whitespace), single-quoted tokens (no
// escaping inside), and double-quoted tokens (no escaping inside either,
// matching the minimal subset git client configs use). It returns an error
// for:
//   - any control character (code point < 0x20) or 0x7F, including NUL;
//   - any byte that is not valid UTF-8;
//   - an unmatched quote (EOF while inside a quoted segment);
//   - a completely empty input (zero tokens).
//
// Metacharacter rejection is handled by the caller via rejectUnsafeChars so
// that the tokenizer stays focused on quote/whitespace semantics.
func tokenize(s string) ([]string, error) {
	var tokens []string
	var cur strings.Builder
	inToken := false
	inSingle := false
	inDouble := false

	flush := func() {
		if inToken {
			tokens = append(tokens, cur.String())
			cur.Reset()
			inToken = false
		}
	}

	i := 0
	for i < len(s) {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return nil, fmt.Errorf("invalid UTF-8 byte at offset %d", i)
		}

		// Reject all control characters (C0 plus DEL). NUL is a control
		// char and is caught here, so there is no separate NUL check.
		if r < 0x20 || r == 0x7F {
			return nil, fmt.Errorf("control character 0x%02X at offset %d", r, i)
		}

		switch {
		case inSingle:
			if r == '\'' {
				inSingle = false
			} else {
				cur.WriteRune(r)
			}
		case inDouble:
			if r == '"' {
				inDouble = false
			} else {
				cur.WriteRune(r)
			}
		default:
			switch r {
			case '\'':
				inSingle = true
				inToken = true
			case '"':
				inDouble = true
				inToken = true
			case ' ', '\t':
				flush()
			default:
				cur.WriteRune(r)
				inToken = true
			}
		}
		i += size
	}

	if inSingle {
		return nil, errors.New("unterminated single quote")
	}
	if inDouble {
		return nil, errors.New("unterminated double quote")
	}

	flush()
	if len(tokens) == 0 {
		return nil, errors.New("empty command")
	}
	return tokens, nil
}

// rejectUnsafeChars reports whether s contains any shell metacharacter that
// the parser never needs to honor. This is a second line of defense on top of
// the tokenizer: even if a metacharacter were inside quotes, we do not want
// it to survive into a later `git-shell -c` reconstruction.
func rejectUnsafeChars(s string) error {
	if strings.ContainsAny(s, unsafeShellMetacharacters) {
		return fmt.Errorf("command contains forbidden shell metacharacter")
	}
	return nil
}

// ParseGitCommand parses a Git SSH exec command into a normalized Request.
//
// It accepts exactly two shapes:
//
//  1. `git-upload-pack|git-receive-pack|git-upload-archive <repo>`
//  2. `git upload-pack|receive-pack|upload-archive <repo>`
//
// The second form is normalized to the hyphenated command of the first form.
// The repository token is canonicalized with NormalizeRepoPath, so leading
// slashes are stripped, traversal segments are rejected, backslashes and
// colons are rejected, and every surviving segment must match
// [A-Za-z0-9._@+-]+.
//
// Any control character, NUL, unmatched quote, shell metacharacter
// (; & | ` $ < > ( )), unknown command, or extra token causes an error. The
// returned Request.RepoPath is the normalized path; BackendPath is left empty
// for Authorize to fill.
func ParseGitCommand(command string) (Request, error) {
	if err := rejectUnsafeChars(command); err != nil {
		return Request{}, err
	}

	tokens, err := tokenize(command)
	if err != nil {
		return Request{}, err
	}

	var cmd string
	var op Operation
	var repoToken string

	switch {
	case len(tokens) == 3 && tokens[0] == "git":
		// Split form: "git <subcommand> <repo>". The subcommand must be one
		// of the bare service names (upload-pack, receive-pack,
		// upload-archive); it is normalized to the hyphenated command.
		sub, ok := gitServiceSubcommand[tokens[1]]
		if !ok {
			return Request{}, fmt.Errorf("unknown git subcommand %q", tokens[1])
		}
		cmd = sub.command
		op = sub.operation
		repoToken = tokens[2]
	case len(tokens) == 2:
		// Hyphenated form: "git-<service> <repo>". The first token must be
		// one of the canonical hyphenated command names. A bare "git" here
		// (with only one following token) is not a valid split form because
		// the subcommand would be missing; gitHyphenCommand["git"] does not
		// exist, so that case is rejected as an unknown command.
		sub, ok := gitHyphenCommand[tokens[0]]
		if !ok {
			return Request{}, fmt.Errorf("unknown git command %q", tokens[0])
		}
		cmd = sub.command
		op = sub.operation
		repoToken = tokens[1]
	default:
		return Request{}, fmt.Errorf("expected 2 tokens (git-<service> <repo>) or 3 tokens (git <service> <repo>), got %d", len(tokens))
	}

	repoNorm, err := NormalizeRepoPath(repoToken)
	if err != nil {
		return Request{}, fmt.Errorf("invalid repository path: %w", err)
	}

	return Request{
		Command:   cmd,
		Operation: op,
		RepoPath:  repoNorm,
	}, nil
}

// Authorize checks whether the SSH public key that produced perms is allowed
// to perform req.Operation against req.RepoPath, and returns a copy of req
// with BackendPath populated from the matched RepositoryConfig.
//
// Authorization is fail-closed:
//
//   - perms must be a gitserver permission (IsGitPermission);
//   - the key fingerprint must be present;
//   - req.RepoPath is re-normalized defensively and must exactly match a
//     configured repository (ParseGitCommand already normalizes, but Authorize
//     is also reachable from direct Request construction in tests and future
//     callers, so it normalizes again);
//   - read access requires the fingerprint to be in ReadKeys or WriteKeys;
//   - write access requires the fingerprint to be in WriteKeys only;
//   - empty ACLs deny all.
//
// On success the returned Request is a shallow copy of req with BackendPath
// set, so callers cannot mutate the in-memory config via the returned value.
func (s *Server) Authorize(perms *ssh.Permissions, req Request) (Request, error) {
	if !IsGitPermission(perms) {
		return Request{}, errors.New("gitserver: not a git permission")
	}
	fp := GitKeyFingerprint(perms)
	if fp == "" {
		return Request{}, errors.New("gitserver: missing key fingerprint")
	}

	repoNorm, err := NormalizeRepoPath(req.RepoPath)
	if err != nil {
		return Request{}, fmt.Errorf("gitserver: invalid repository path: %w", err)
	}

	s.mu.RLock()
	rc, ok := s.repos[repoNorm]
	s.mu.RUnlock()
	if !ok {
		return Request{}, fmt.Errorf("gitserver: repository %q not configured", repoNorm)
	}

	allowed := false
	switch req.Operation {
	case OperationRead:
		allowed = containsFingerprint(rc.ReadKeys, fp) || containsFingerprint(rc.WriteKeys, fp)
	case OperationWrite:
		allowed = containsFingerprint(rc.WriteKeys, fp)
	default:
		return Request{}, fmt.Errorf("gitserver: unknown operation %q", req.Operation)
	}
	if !allowed {
		return Request{}, fmt.Errorf("gitserver: fingerprint %q not authorized for %s on %q", fp, req.Operation, repoNorm)
	}

	out := req
	out.RepoPath = repoNorm
	out.BackendPath = rc.BackendPath
	return out, nil
}

// containsFingerprint reports whether fps contains fp with exact, case-
// sensitive equality. Fingerprints are SHA256:... strings and are not
// normalized case-wise here; CheckAndFillConfig already trimmed whitespace.
func containsFingerprint(fps []string, fp string) bool {
	for _, k := range fps {
		if k == fp {
			return true
		}
	}
	return false
}

// ResolveLocalRepo resolves a repository path to an absolute filesystem path
// under s.config.RepoRoot, proving via filepath.EvalSymlinks that the final
// target remains inside RepoRoot.
//
// The repoPath argument is first normalized with NormalizeRepoPath so the
// forward-slash semantics of the parser carry over to the local-filesystem
// layer. The normalized path is then joined to RepoRoot with filepath.Join
// (which produces an OS-appropriate absolute path) and EvalSymlinks is run on
// both RepoRoot and the candidate. If the candidate does not exist, does not
// resolve, or resolves outside RepoRoot, an error is returned. Repositories
// are never created.
//
// The confinement check uses filepath.Rel(root, candidate). If the relative
// path is exactly "..", begins with ".." followed by a separator, or is an
// absolute path (which happens on Windows when root and candidate are on
// different drives), the candidate is treated as an escape and rejected.
func (s *Server) ResolveLocalRepo(repoPath string) (string, error) {
	repoNorm, err := NormalizeRepoPath(repoPath)
	if err != nil {
		return "", fmt.Errorf("gitserver: invalid repository path: %w", err)
	}

	root := s.config.RepoRoot
	if root == "" {
		return "", errors.New("gitserver: repo_root is empty")
	}

	rootAbs, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("gitserver: resolve repo_root %q: %w", root, err)
	}

	candidate := filepath.Join(rootAbs, filepath.FromSlash(repoNorm))
	candAbs, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", fmt.Errorf("gitserver: resolve repository %q: %w", repoNorm, err)
	}

	rel, err := filepath.Rel(rootAbs, candAbs)
	if err != nil {
		// On Windows this happens when root and candidate are on different
		// drives, which is itself an escape.
		return "", fmt.Errorf("gitserver: repository %q escapes repo_root: %w", repoNorm, err)
	}
	if isEscapeRel(rel) {
		return "", fmt.Errorf("gitserver: repository %q escapes repo_root (resolved to %q)", repoNorm, candAbs)
	}

	return candAbs, nil
}

// isEscapeRel reports whether rel, the result of filepath.Rel(root, candidate),
// indicates that candidate is outside root. A relative path escapes when it is
// "..", begins with ".." + separator, or is absolute (cross-drive on Windows).
func isEscapeRel(rel string) bool {
	if rel == ".." {
		return true
	}
	if strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return true
	}
	if filepath.IsAbs(rel) {
		return true
	}
	return false
}
