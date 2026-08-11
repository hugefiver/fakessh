package gitserver

import (
	"errors"
	"path"
	"regexp"
	"strings"
)

// repoSegmentPattern defines the set of characters allowed within a single
// path segment of a repository path. Segments must be non-empty and match
// [A-Za-z0-9._@+-]+. A "." segment is allowed structurally (it is collapsed
// by path.Clean) but a ".." segment is NEVER allowed.
var repoSegmentPattern = regexp.MustCompile(`^[A-Za-z0-9._@+-]+$`)

// NormalizeRepoPath canonicalizes a repository path supplied by config or by a
// client request. It is deliberately filesystem-agnostic: it operates on
// forward-slash paths only and uses path.Clean (not filepath.Clean) so the
// result is identical on every platform.
//
// Rules:
//   - A single leading slash is stripped ("/team/project.git" -> "team/project.git").
//   - Backslashes are rejected (Windows-style paths are not allowed).
//   - Colons are rejected (drive letters / scp-style URIs are not allowed).
//   - Empty input is rejected.
//   - RAW ".." segments are always rejected, BEFORE path.Clean runs. This
//     means "team/../secret.git" is rejected even though path.Clean would
//     collapse it to "secret.git". Traversal must be explicit-denied, not
//     silently rewritten.
//   - RAW "." segments are allowed (they are no-ops); path.Clean collapses
//     them, so "team/./project.git" normalizes to "team/project.git".
//   - Empty raw segments (e.g. from "team//project.git" or a trailing slash)
//     are allowed structurally and collapsed by path.Clean.
//   - After cleaning, the result is re-validated: it must not be ".", "..",
//     or "", and every surviving segment must match [A-Za-z0-9._@+-]+.
func NormalizeRepoPath(repo string) (string, error) {
	if repo == "" {
		return "", errors.New("repository path cannot be empty")
	}

	if strings.ContainsRune(repo, '\\') {
		return "", errors.New("repository path cannot contain backslash")
	}
	if strings.ContainsRune(repo, ':') {
		return "", errors.New("repository path cannot contain colon")
	}

	// Strip a single leading slash so "/team/project.git" is accepted.
	repo = strings.TrimPrefix(repo, "/")

	// Reject any RAW ".." segment before path.Clean can collapse it. A ".."
	// segment is a traversal attempt regardless of where it appears; we never
	// want to silently rewrite "team/../secret.git" into "secret.git". We
	// deliberately do NOT reject "." here, because "team/./project.git" is a
	// harmless no-op that path.Clean will normalize.
	for _, seg := range strings.Split(repo, "/") {
		if seg == ".." {
			return "", errors.New("repository path cannot contain traversal segment")
		}
	}

	// Collapse redundant slashes, trailing slashes, and "." segments.
	cleaned := path.Clean(repo)

	// path.Clean(".") == ".", path.Clean("..") == "..", path.Clean("") == ".".
	// Any of these means the path was empty or pure-traversal after cleaning.
	if cleaned == "" || cleaned == "." || cleaned == ".." {
		return "", errors.New("repository path cannot be empty or traversal")
	}

	// Validate every segment of the cleaned path. After Clean there should be
	// no "." or ".." segments and no empty segments, but we guard defensively.
	for _, seg := range strings.Split(cleaned, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", errors.New("repository path cannot contain empty or traversal segments")
		}
		if !repoSegmentPattern.MatchString(seg) {
			return "", errors.New("repository path contains invalid segment: " + seg)
		}
	}

	return cleaned, nil
}
