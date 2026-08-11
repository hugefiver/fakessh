package cmds

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

// ErrExit is returned by the exit built-in to signal that the shell run loop
// should terminate cleanly. RunLoop treats errors.Is(err, ErrExit) as a
// successful exit and returns nil to its caller.
var ErrExit = errors.New("exit")

// CmdExit is the Command implementation of exit. It always returns ErrExit so
// the dispatcher can detect a clean shutdown request without relying on
// sentinel strings.
var CmdExit = FuncCmd(cmdExit)

func cmdExit(r *CommandRunner, args ...string) error {
	return ErrExit
}

// ResolvePath resolves a user-supplied path argument relative to cwd into an
// absolute POSIX path confined to the fake root.
//
// Resolution rules (fail closed on anything suspicious):
//
//   - If arg starts '/', the path is resolved from the fake root "/".
//     Otherwise it is joined onto cwd. cwd is expected to already be an
//     absolute POSIX path; if it is empty it is treated as "/".
//
//   - Any raw ".." segment is rejected BEFORE cleaning. "..", "../etc",
//     "../../x", "/../x" and "a/../b" all error. The resolver never lets a
//     traversal attempt escape the root by silently rewriting it; this
//     matches the fail-closed posture of the archive loader.
//
//   - Backslash, colon, NUL and any control byte (< 0x20 or 0x7f) are
//     rejected anywhere in arg. These have no legitimate use in a POSIX
//     fake path and can be used to confuse naive cleaners or smuggle
//     Windows-style / NTFS alternate-data-stream references.
//
//   - "." segments and repeated '/' are collapsed via path.Clean, so
//     ResolvePath("/home/root", "./docs//file") == "/home/root/docs/file".
//
//   - The returned path is always absolute POSIX (leading '/') and never
//     empty.
//
// cwd must already be a trusted, validated absolute path owned by the shell
// (typically r.GetEnv("PWD")). It is not re-validated here; if it is empty
// the resolver assumes "/". If cwd itself is somehow invalid the resolution
// still only ever return a path confined under "/" because the join is done
// with path.Join which strips any leading-slash on cwd via the join semantics
// and the final result is re-rooted under "/".
//
// This function performs NO filesystem access; it is pure string logic and
// safe to call without holding the runner mutex. Callers that need to check
// whether the resolved path exists must do so themselves on r.RootFS.
func ResolvePath(cwd, arg string) (string, error) {
	if err := validatePathChars(arg); err != nil {
		return "", err
	}

	var joined string
	if strings.HasPrefix(arg, "/") {
		// Absolute fake path: ignore cwd and resolve from the fake root.
		joined = arg
	} else {
		joined = joinPosix(cwd, arg)
	}

	// Reject any raw ".." segment before cleaning. path.Clean would collapse
	// "a/../b" to "b", but we want to fail closed on traversal attempts rather
	// than silently rewrite them, exactly like cleanArchivePath does.
	for _, seg := range strings.Split(joined, "/") {
		if seg == ".." {
			return "", errors.New("path: \"..\" segment not allowed")
		}
	}

	cleaned := path.Clean(joined)
	// path.Clean("/") is "/", path.Clean("") is ".". Normalize empty/root to
	// "/" so callers always get an absolute path.
	if cleaned == "." || cleaned == "" {
		return "/", nil
	}
	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}
	// Defensive: after cleaning, an escape would indicate a logic bug.
	if strings.HasPrefix(cleaned, "../") || cleaned == ".." {
		return "", errors.New("path: resolved path escapes root")
	}
	return cleaned, nil
}

// validatePathChars rejects backslash, colon, NUL and any control byte in a
// user-supplied path argument. '/' is the only allowed separator. Printable
// ASCII (>= 0x20 and != 0x7f and != '\\' and != ':') is accepted; non-ASCII
// bytes are allowed (filenames may contain UTF-8).
func validatePathChars(s string) error {
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch {
		case b < 0x20 || b == 0x7f:
			return fmt.Errorf("path: control character at index %d", i)
		case b == '\\':
			return errors.New("path: backslash not allowed")
		case b == ':':
			return errors.New("path: colon not allowed")
		}
	}
	return nil
}

// joinPosix joins cwd and arg with a single '/' separator, without using
// filepath.Join (which would use the host OS separator). cwd may be empty.
func joinPosix(cwd, arg string) string {
	if cwd == "" {
		cwd = "/"
	}
	if strings.HasSuffix(cwd, "/") {
		return cwd + arg
	}
	return cwd + "/" + arg
}
