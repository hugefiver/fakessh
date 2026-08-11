package cmds

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/spf13/afero"
)

// ICmd is the internal interface a built-in command implements. It mirrors
// Command but is kept as a separate type so that internal helpers can be
// mocked or wrapped without exporting Command to the rest of the module.
type ICmd interface {
	Run(runner *CommandRunner, args ...string) error
}

// FuncCmd adapts a plain function into an ICmd.
type FuncCmd func(runner *CommandRunner, args ...string) error

func (f FuncCmd) Run(runner *CommandRunner, args ...string) error {
	return f(runner, args...)
}

// Built-in command instances. These are referenced by the dispatcher in
// fakeshell.go via the runCmd switch. Each command writes its own user-facing
// error messages to r.Stderr and returns a non-nil error to signal that the
// run loop should not consume a following prompt as if the command succeeded;
// the loop currently logs the returned error but the stderr line is the
// canonical shell-visible feedback.
var (
	CmdLs       = FuncCmd(ls)
	CmdPwd      = FuncCmd(pwd)
	CmdCd       = FuncCmd(cd)
	CmdWhoami   = FuncCmd(whoami)
	CmdHostname = FuncCmd(hostname)
	CmdEcho     = FuncCmd(echo)
	CmdUname    = FuncCmd(uname)
	CmdEnv      = FuncCmd(env)
	CmdTouch    = FuncCmd(touch)
)

// pwd writes the current working directory (the PWD env var) followed by a
// single newline. PWD is always an absolute POSIX path maintained by cd.
func pwd(r *CommandRunner, args ...string) error {
	r.mu.Lock()
	cwd := r.GetEnv("PWD")
	r.mu.Unlock()
	if cwd == "" {
		cwd = "/"
	}
	_, err := fmt.Fprintln(r.Stdout, cwd)
	return err
}

// cd changes the current working directory. With no argument it targets HOME.
// The target must exist and be a directory in RootFS; otherwise a shell-like
// message is written to stderr and an error is returned so the dispatcher can
// surface it. On success PWD (and HOME, when the target equals HOME, to match
// common shell behavior) is updated.
func cd(r *CommandRunner, args ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	target := ""
	if len(args) > 0 {
		target = args[0]
	}
	if target == "" || target == "~" {
		target = r.GetEnv("HOME")
		if target == "" {
			target = "/"
		}
	}

	resolved, err := ResolvePath(r.GetEnv("PWD"), target)
	if err != nil {
		fmt.Fprintf(r.Stderr, "cd: %s\n", err.Error())
		return err
	}

	exists, err := afero.Exists(r.RootFS, resolved)
	if err != nil {
		fmt.Fprintf(r.Stderr, "cd: %s\n", err.Error())
		return err
	}
	if !exists {
		fmt.Fprintf(r.Stderr, "cd: %s: No such file or directory\n", resolved)
		return fmt.Errorf("cd: %s: no such directory", resolved)
	}
	isDir, err := afero.IsDir(r.RootFS, resolved)
	if err != nil {
		fmt.Fprintf(r.Stderr, "cd: %s\n", err.Error())
		return err
	}
	if !isDir {
		fmt.Fprintf(r.Stderr, "cd: %s: Not a directory\n", resolved)
		return fmt.Errorf("cd: %s: not a directory", resolved)
	}

	r.SetEnv("PWD", resolved)
	return nil
}

// ls lists directory contents or prints a file basename. With no argument it
// targets PWD. If the target is a directory, child names are printed sorted,
// separated by two spaces, followed by a newline. If the target is a regular
// file, its basename is printed followed by a newline.
//
// In addition to the static RootFS, ls consults the per-session Dynamic store:
//   - A target that is a static directory has its static child names merged
//     with the basenames of same-session dynamic entries whose direct parent
//     is that directory (sorted + deduped).
//   - A target absent from static RootFS but present as a dynamic "file" entry
//     prints its basename (so `touch /tmp/a` then `ls /tmp/a` works).
//   - A target absent from static RootFS but present as a dynamic "dir" entry
//     lists its direct dynamic children (future-compatible; no command records
//     dir entries yet).
//
// Missing targets (neither static nor dynamic) produce a shell-like stderr
// message and a non-nil error. ls never touches the host filesystem. The
// runner mu is held for the whole call so the static+dynamic view is
// consistent; lock order is runner.mu -> DynamicStore.mu, never reversed.
func ls(r *CommandRunner, args ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	target := ""
	if len(args) > 0 {
		target = args[0]
	}
	if target == "" {
		target = r.GetEnv("PWD")
		if target == "" {
			target = "/"
		}
	}

	resolved, err := ResolvePath(r.GetEnv("PWD"), target)
	if err != nil {
		fmt.Fprintf(r.Stderr, "ls: %s\n", err.Error())
		return err
	}

	// First, try the static RootFS. If the target exists there we use the
	// existing static path (file -> basename, dir -> static names merged with
	// per-session dynamic children). If it does NOT exist in static RootFS we
	// fall through to the dynamic-only path below, so that `touch /tmp/a`
	// followed by `ls /tmp/a` resolves to the dynamic file entry rather than
	// "No such file or directory".
	staticExists, err := afero.Exists(r.RootFS, resolved)
	if err != nil {
		fmt.Fprintf(r.Stderr, "ls: %s\n", err.Error())
		return err
	}

	if staticExists {
		info, err := r.RootFS.Stat(resolved)
		if err != nil {
			fmt.Fprintf(r.Stderr, "ls: %s\n", err.Error())
			return err
		}

		if !info.IsDir() {
			_, err := fmt.Fprintln(r.Stdout, path.Base(resolved))
			return err
		}

		entries, err := afero.ReadDir(r.RootFS, resolved)
		if err != nil {
			fmt.Fprintf(r.Stderr, "ls: %s\n", err.Error())
			return err
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}

		// Merge same-session dynamic metadata: a dynamic entry whose direct
		// parent is the listed directory adds its basename to the output. This
		// lets `ls` show files created by `touch` even though touch never
		// writes to RootFS. Dynamic entries are per-session only (r.Dynamic is
		// never shared), so this cannot leak across sessions. The runner mu is
		// held for the whole ls, so a concurrent touch cannot insert mid-merge
		// and produce a torn view.
		names = append(names, dynamicChildNames(r, resolved)...)

		_, err = fmt.Fprintln(r.Stdout, strings.Join(sortDedup(names), "  "))
		return err
	}

	// Static RootFS does not have the target. Check the per-session dynamic
	// store so that `touch /tmp/a` then `ls /tmp/a` prints the basename of the
	// touched (metadata-only) file, and a future dynamic `dir` entry lists its
	// dynamic children. This never accesses the host filesystem.
	if r.Dynamic != nil {
		if de, ok := lookupDynamicPath(r, resolved); ok {
			switch de.Kind {
			case "file":
				_, err := fmt.Fprintln(r.Stdout, path.Base(resolved))
				return err
			case "dir":
				// A dynamic directory: list its direct dynamic children. There
				// is no static RootFS equivalent here (staticExists was false),
				// so we only merge dynamic children. Sorted + deduped.
				names := dynamicChildNames(r, resolved)
				_, err := fmt.Fprintln(r.Stdout, strings.Join(sortDedup(names), "  "))
				return err
			}
		}
	}

	// Neither static RootFS nor the per-session dynamic store has the target:
	// preserve the original "No such file or directory" behavior.
	fmt.Fprintf(r.Stderr, "ls: %s: No such file or directory\n", target)
	return fmt.Errorf("ls: %s: no such file", target)
}

// lookupDynamicPath returns the per-session dynamic entry whose Path equals
// resolved, if any. The caller must hold the runner mu (so the Dynamic store
// is not concurrently mutated mid-scan); lookupDynamicPath itself only calls
// Dynamic.Entries() which takes the store's internal mutex. Lock order is
// always runner.mu -> DynamicStore.mu, never the reverse.
func lookupDynamicPath(r *CommandRunner, resolved string) (DynamicEntry, bool) {
	if r.Dynamic == nil {
		return DynamicEntry{}, false
	}
	for _, de := range r.Dynamic.Entries() {
		if de.Path == resolved {
			return de, true
		}
	}
	return DynamicEntry{}, false
}

// dynamicChildNames returns the basenames of all per-session dynamic entries
// whose direct parent (path.Dir) equals parent. The caller must hold the
// runner mu. Names are NOT sorted/deduped here; the caller is responsible.
func dynamicChildNames(r *CommandRunner, parent string) []string {
	if r.Dynamic == nil {
		return nil
	}
	var names []string
	for _, de := range r.Dynamic.Entries() {
		if path.Dir(de.Path) == parent {
			names = append(names, path.Base(de.Path))
		}
	}
	return names
}

// sortDedup returns a sorted, de-duplicated copy of names. It sorts in place
// then compacts so each name appears exactly once.
func sortDedup(names []string) []string {
	sort.Strings(names)
	deduped := names[:0]
	for i, n := range names {
		if i == 0 || names[i-1] != n {
			deduped = append(deduped, n)
		}
	}
	return deduped
}

// touch records metadata-only "creation" of a file. It accepts exactly one
// path argument, resolves it from cwd, requires the parent directory to exist
// (as a directory in static RootFS or as a dynamic dir metadata entry), and
// records a {kind: file, size: 0, preview: nil, sha256: ""} entry in the
// session's DynamicStore.
//
// touch performs NO RootFS writes and NO content storage. It does not create
// parent directories (no mkdir -p semantics). This keeps the static rootfs
// immutable per session and bounds dynamic state to a small metadata record.
//
// Failure modes (shell-like stderr + non-nil error):
//   - wrong arg count (0 or >1): "touch: missing file operand" / "touch: too many arguments"
//   - invalid path (rejected by ResolvePath): "touch: <err>"
//   - missing parent directory: "touch: cannot touch '<path>': No such file or directory"
//
// A parent directory is considered to exist if either:
//   - it exists in static RootFS and is a directory, OR
//   - it has a dynamic metadata entry with kind "dir" (future-proofing; today
//     only touch produces entries and it only records kind "file", so the
//     dynamic-dir branch is effectively inert until a mkdir-like command is
//     added. It is included so the parent-existence rule degrades safely).
func touch(r *CommandRunner, args ...string) error {
	if len(args) == 0 {
		fmt.Fprintln(r.Stderr, "touch: missing file operand")
		return errors.New("touch: missing file operand")
	}
	if len(args) > 1 {
		fmt.Fprintln(r.Stderr, "touch: too many arguments")
		return errors.New("touch: too many arguments")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	cwd := r.GetEnv("PWD")
	if cwd == "" {
		cwd = "/"
	}

	resolved, err := ResolvePath(cwd, args[0])
	if err != nil {
		fmt.Fprintf(r.Stderr, "touch: %s\n", err.Error())
		return err
	}

	parent := path.Dir(resolved)
	if !parentExists(r, parent) {
		fmt.Fprintf(r.Stderr, "touch: cannot touch '%s': No such file or directory\n", args[0])
		return fmt.Errorf("touch: %s: parent %s does not exist", resolved, parent)
	}

	if r.Dynamic == nil {
		// Defensive: NewCommandRunner always sets Dynamic, but a test or
		// migration that constructs a runner by hand could leave it nil. We
		// treat nil as "no dynamic state available" and refuse to record.
		fmt.Fprintln(r.Stderr, "touch: dynamic store unavailable")
		return errors.New("touch: dynamic store unavailable")
	}

	if _, err := r.Dynamic.Record(resolved, "file", 0, nil, ""); err != nil {
		fmt.Fprintf(r.Stderr, "touch: %s\n", err.Error())
		return err
	}
	return nil
}

// parentExists reports whether dir exists as a directory in static RootFS or
// as a dynamic dir metadata entry. The root "/" always exists. The caller must
// hold the runner mu so the RootFS/Dynamic view is consistent.
func parentExists(r *CommandRunner, dir string) bool {
	if dir == "/" {
		return true
	}

	// Static RootFS check.
	exists, err := afero.Exists(r.RootFS, dir)
	if err == nil && exists {
		isDir, derr := afero.IsDir(r.RootFS, dir)
		if derr == nil && isDir {
			return true
		}
	}

	// Dynamic dir metadata check (future-proofing for mkdir-like commands).
	if r.Dynamic != nil {
		for _, de := range r.Dynamic.Entries() {
			if de.Path == dir && de.Kind == "dir" {
				return true
			}
		}
	}
	return false
}

// whoami prints the configured user (USER env, sourced from c.EnvConfig.User
// via the generated default env map) or, if unset, LOGNAME, followed by a
// newline.
func whoami(r *CommandRunner, args ...string) error {
	user := r.GetEnv("USER")
	if user == "" {
		user = r.GetEnv("LOGNAME")
	}
	_, err := fmt.Fprintln(r.Stdout, user)
	return err
}

// hostname prints the configured hostname (NAME / hostname env) followed by a
// newline. The configured value comes from c.EnvConfig.HostName.
func hostname(r *CommandRunner, args ...string) error {
	name := r.GetEnv("NAME")
	if name == "" {
		name = r.GetEnv("HOSTNAME")
	}
	_, err := fmt.Fprintln(r.Stdout, name)
	return err
}

// echo prints its arguments joined by single spaces followed by a newline. It
// performs no command substitution, pipe handling or env-var expansion; it is
// a literal echo.
func echo(r *CommandRunner, args ...string) error {
	_, err := fmt.Fprintln(r.Stdout, strings.Join(args, " "))
	return err
}

// uname prints a fake uname-style banner. This is a legacy cosmetic command
// kept for compatibility; it is not part of the Task 2 required set but is
// retained so existing dispatch does not break.
func uname(r *CommandRunner, args ...string) error {
	c := r.C
	_, err := fmt.Fprintf(r.Stdout, "%s %s %s © FakeShell 2024\n", c.OS, c.HostName, c.Kernel)
	return err
}

// env prints all visible environment variables (TempEnv shadowing Env) in
// KEY=VALUE form, newline-separated. This is a legacy command kept for
// compatibility.
func env(r *CommandRunner, args ...string) error {
	buf := bytes.NewBuffer(nil)

	envs := r.GetEnvs()
	for i, e := range envs {
		_, err := fmt.Fprintf(buf, "%s=%s", e.Key, e.Value)
		if err != nil {
			return err
		}
		if i < len(envs)-1 {
			buf.WriteByte('\n')
		}
	}
	_, err := io.Copy(r.Stdout, buf)
	return err
}
