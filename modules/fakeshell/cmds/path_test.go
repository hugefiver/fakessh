package cmds

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	fsconf "github.com/hugefiver/fakessh/modules/fakeshell/conf"
	"github.com/spf13/afero"
)

// ---------------------------------------------------------------------------
// ResolvePath - accept cases
// ---------------------------------------------------------------------------

func TestResolvePath_AcceptsValid(t *testing.T) {
	t.Parallel()

	cases := []struct {
		cwd  string
		arg  string
		want string
	}{
		// absolute arg ignores cwd
		{"/home/root", "/etc/passwd", "/etc/passwd"},
		{"/home/root", "/", "/"},
		// relative arg joins cwd
		{"/home/root", "docs", "/home/root/docs"},
		{"/home/root", "docs/file", "/home/root/docs/file"},
		// "." and repeated slash are cleaned
		{"/home/root", "./docs//file", "/home/root/docs/file"},
		{"/home/root", "././docs", "/home/root/docs"},
		{"/home/root", "docs/.", "/home/root/docs"},
		{"/home/root", "docs//", "/home/root/docs"},
		// empty cwd is treated as "/"
		{"", "etc/passwd", "/etc/passwd"},
		// root itself
		{"/", ".", "/"},
		{"/", "", "/"},
		// trailing slash on cwd joins cleanly
		{"/home/root/", "docs", "/home/root/docs"},
		// absolute arg with internal dot/dup-slash
		{"/home", "/etc//passwd", "/etc/passwd"},
		{"/home", "/etc/./passwd", "/etc/passwd"},
	}

	for _, tc := range cases {
		got, err := ResolvePath(tc.cwd, tc.arg)
		if err != nil {
			t.Errorf("ResolvePath(%q,%q) unexpected error: %v", tc.cwd, tc.arg, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ResolvePath(%q,%q) = %q, want %q", tc.cwd, tc.arg, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// ResolvePath - escape / reject cases
// ---------------------------------------------------------------------------

func TestResolvePath_RejectsUnsafe(t *testing.T) {
	t.Parallel()

	cases := []struct {
		cwd string
		arg string
	}{
		// raw ".." anywhere must fail before cleaning
		{"/home/root", ".."},
		{"/home/root", "../etc"},
		{"/home/root", "../../x"},
		{"/home/root", "/../x"},
		{"/home/root", "a/../b"},
		{"/home/root", "safe/../escape"},
		{"/", ".."},
		{"/", "../foo"},
		// backslash
		{"/home/root", `team\x`},
		{"/home/root", `\etc\passwd`},
		// colon (drive letters + NTFS ADS)
		{"/home/root", "C:/x"},
		{"/home/root", "c:/x"},
		{"/home/root", "foo:bar"},
		{"/home/root", "/etc/passwd:ads"},
		// NUL
		{"/home/root", "etc\x00passwd"},
		// control chars
		{"/home/root", "etc/\x01passwd"},
		{"/home/root", "etc/\x7fpasswd"},
		{"/home/root", "etc/\x1fpasswd"},
	}

	for _, tc := range cases {
		if _, err := ResolvePath(tc.cwd, tc.arg); err == nil {
			t.Errorf("ResolvePath(%q,%q) expected error, got nil", tc.cwd, tc.arg)
		}
	}
}

func TestResolvePath_AlwaysReturnsAbsolute(t *testing.T) {
	t.Parallel()

	cases := []string{"docs", "./docs", "a/b/c", "x"}
	for _, arg := range cases {
		got, err := ResolvePath("/home/root", arg)
		if err != nil {
			t.Fatalf("ResolvePath(%q) unexpected error: %v", arg, err)
		}
		if !strings.HasPrefix(got, "/") {
			t.Errorf("ResolvePath(%q) = %q, must start with /", arg, got)
		}
	}
}

// ---------------------------------------------------------------------------
// Command fixtures
// ---------------------------------------------------------------------------

// newTestRunner builds a CommandRunner wired to a memmap rootfs containing
// /home/root, /bin, /etc/passwd. stdout/stderr are captured buffers the caller
// can read back. PWD is set to /home/root.
func newTestRunner(t *testing.T) (*CommandRunner, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()

	cfg := &fsconf.FakeshellConfig{}
	// Match the fixture dir: default user "root" would derive Home=/root,
	// but the fixture creates /home/root. Pin Home so cd-default lands there.
	cfg.EnvConfig.Home = "/home/root"
	cfg.FillDefault()
	if err := fsconf.CheckAndFillConfig(cfg); err != nil {
		t.Fatalf("CheckAndFillConfig: %v", err)
	}

	fs := afero.NewMemMapFs()
	for _, dir := range []string{"/home", "/home/root", "/bin", "/etc"} {
		if err := fs.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	// /etc/passwd as a zero-byte regular file
	f, err := fs.Create("/etc/passwd")
	if err != nil {
		t.Fatalf("create /etc/passwd: %v", err)
	}
	f.Close()

	r := NewCommandRunner(cfg)
	r.RootFS = fs
	r.SetEnv("PWD", "/home/root")

	var out, errb bytes.Buffer
	r.Stdout = &out
	r.Stderr = &errb
	return r, &out, &errb
}

// ---------------------------------------------------------------------------
// pwd
// ---------------------------------------------------------------------------

func TestCmdPwd_PrintsPwdWithNewline(t *testing.T) {
	t.Parallel()

	r, out, _ := newTestRunner(t)
	if err := CmdPwd.Run(r); err != nil {
		t.Fatalf("pwd: %v", err)
	}
	want := "/home/root\n"
	if got := out.String(); got != want {
		t.Errorf("pwd output = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// cd
// ---------------------------------------------------------------------------

func TestCmdCd_DefaultsToHome(t *testing.T) {
	t.Parallel()

	r, _, _ := newTestRunner(t)
	if err := CmdCd.Run(r); err != nil {
		t.Fatalf("cd (no arg): %v", err)
	}
	if got := r.GetEnv("PWD"); got != "/home/root" {
		t.Errorf("cd PWD = %q, want /home/root", got)
	}
}

func TestCmdCd_ToBinUpdatesPwd(t *testing.T) {
	t.Parallel()

	r, _, _ := newTestRunner(t)
	if err := CmdCd.Run(r, "/bin"); err != nil {
		t.Fatalf("cd /bin: %v", err)
	}
	if got := r.GetEnv("PWD"); got != "/bin" {
		t.Errorf("cd /bin PWD = %q, want /bin", got)
	}
}

func TestCmdCd_RelativeTarget(t *testing.T) {
	t.Parallel()

	r, _, _ := newTestRunner(t)
	// cwd is /home/root; go up via absolute /home then relative root
	if err := CmdCd.Run(r, "/home"); err != nil {
		t.Fatalf("cd /home: %v", err)
	}
	if err := CmdCd.Run(r, "root"); err != nil {
		t.Fatalf("cd root (relative): %v", err)
	}
	if got := r.GetEnv("PWD"); got != "/home/root" {
		t.Errorf("cd relative PWD = %q, want /home/root", got)
	}
}

func TestCmdCd_MissingFails(t *testing.T) {
	t.Parallel()

	r, _, errb := newTestRunner(t)
	err := CmdCd.Run(r, "/nope")
	if err == nil {
		t.Fatal("cd /nope expected error, got nil")
	}
	if !strings.Contains(errb.String(), "No such file or directory") {
		t.Errorf("stderr = %q, want substring 'No such file or directory'", errb.String())
	}
	// PWD must not change on failure
	if got := r.GetEnv("PWD"); got != "/home/root" {
		t.Errorf("PWD after failed cd = %q, want /home/root", got)
	}
}

func TestCmdCd_NonDirFails(t *testing.T) {
	t.Parallel()

	r, _, errb := newTestRunner(t)
	err := CmdCd.Run(r, "/etc/passwd")
	if err == nil {
		t.Fatal("cd /etc/passwd expected error, got nil")
	}
	if !strings.Contains(errb.String(), "Not a directory") {
		t.Errorf("stderr = %q, want substring 'Not a directory'", errb.String())
	}
}

func TestCmdCd_TraversalRejected(t *testing.T) {
	t.Parallel()

	r, _, errb := newTestRunner(t)
	err := CmdCd.Run(r, "..")
	if err == nil {
		t.Fatal("cd .. expected error, got nil")
	}
	if !strings.Contains(errb.String(), "..") && !strings.Contains(errb.String(), "not allowed") {
		t.Errorf("stderr = %q, want traversal rejection", errb.String())
	}
}

// ---------------------------------------------------------------------------
// ls
// ---------------------------------------------------------------------------

func TestCmdLs_DefaultsToPwd(t *testing.T) {
	t.Parallel()

	r, out, _ := newTestRunner(t)
	if err := CmdLs.Run(r); err != nil {
		t.Fatalf("ls (no arg): %v", err)
	}
	// /home/root is empty -> empty line
	if got := out.String(); got != "\n" {
		t.Errorf("ls empty dir output = %q, want %q", got, "\n")
	}
}

func TestCmdLs_RootListsSortedNames(t *testing.T) {
	t.Parallel()

	r, out, _ := newTestRunner(t)
	if err := CmdLs.Run(r, "/"); err != nil {
		t.Fatalf("ls /: %v", err)
	}
	// / contains: bin etc home
	want := "bin  etc  home\n"
	if got := out.String(); got != want {
		t.Errorf("ls / output = %q, want %q", got, want)
	}
}

func TestCmdLs_FilePrintsBasename(t *testing.T) {
	t.Parallel()

	r, out, _ := newTestRunner(t)
	if err := CmdLs.Run(r, "/etc/passwd"); err != nil {
		t.Fatalf("ls /etc/passwd: %v", err)
	}
	want := "passwd\n"
	if got := out.String(); got != want {
		t.Errorf("ls /etc/passwd output = %q, want %q", got, want)
	}
}

func TestCmdLs_MissingErrors(t *testing.T) {
	t.Parallel()

	r, _, errb := newTestRunner(t)
	err := CmdLs.Run(r, "/nope")
	if err == nil {
		t.Fatal("ls /nope expected error, got nil")
	}
	if !strings.Contains(errb.String(), "No such file or directory") {
		t.Errorf("stderr = %q, want 'No such file or directory'", errb.String())
	}
}

func TestCmdLs_RelativePath(t *testing.T) {
	t.Parallel()

	r, out, _ := newTestRunner(t)
	// cwd is /home/root; list /home via relative ".." is rejected; use absolute
	if err := CmdLs.Run(r, "/home"); err != nil {
		t.Fatalf("ls /home: %v", err)
	}
	if got := out.String(); got != "root\n" {
		t.Errorf("ls /home output = %q, want 'root\\n'", got)
	}
}

// ---------------------------------------------------------------------------
// whoami / hostname / echo / exit
// ---------------------------------------------------------------------------

func TestCmdWhoami_PrintsUser(t *testing.T) {
	t.Parallel()

	r, out, _ := newTestRunner(t)
	if err := CmdWhoami.Run(r); err != nil {
		t.Fatalf("whoami: %v", err)
	}
	want := "root\n"
	if got := out.String(); got != want {
		t.Errorf("whoami output = %q, want %q", got, want)
	}
}

func TestCmdHostname_PrintsHostname(t *testing.T) {
	t.Parallel()

	r, out, _ := newTestRunner(t)
	// hostname is sourced from the generated env NAME = cfg.HostName (empty
	// by default -> empty line). Set it explicitly so the test is stable.
	r.SetEnv("NAME", "fake-host")
	if err := CmdHostname.Run(r); err != nil {
		t.Fatalf("hostname: %v", err)
	}
	want := "fake-host\n"
	if got := out.String(); got != want {
		t.Errorf("hostname output = %q, want %q", got, want)
	}
}

func TestCmdEcho_JoinsArgs(t *testing.T) {
	t.Parallel()

	r, out, _ := newTestRunner(t)
	if err := CmdEcho.Run(r, "hello", "world"); err != nil {
		t.Fatalf("echo: %v", err)
	}
	want := "hello world\n"
	if got := out.String(); got != want {
		t.Errorf("echo output = %q, want %q", got, want)
	}
}

func TestCmdEcho_NoArgsPrintsNewline(t *testing.T) {
	t.Parallel()

	r, out, _ := newTestRunner(t)
	if err := CmdEcho.Run(r); err != nil {
		t.Fatalf("echo: %v", err)
	}
	want := "\n"
	if got := out.String(); got != want {
		t.Errorf("echo output = %q, want %q", got, want)
	}
}

func TestCmdExit_ReturnsErrExit(t *testing.T) {
	t.Parallel()

	r, _, _ := newTestRunner(t)
	err := CmdExit.Run(r)
	if !errors.Is(err, ErrExit) {
		t.Errorf("exit err = %v, want ErrExit", err)
	}
}

// ---------------------------------------------------------------------------
// SetRootFS
// ---------------------------------------------------------------------------

func TestSetRootFS_NilCreatesSafeMemfs(t *testing.T) {
	t.Parallel()

	r, _, _ := newTestRunner(t)
	r.SetRootFS(nil)
	if r.RootFS == nil {
		t.Fatal("SetRootFS(nil) left RootFS nil")
	}
	// must be a usable empty fs
	exists, err := afero.Exists(r.RootFS, "/anything")
	if err != nil {
		t.Fatalf("Exists on nil-set fs: %v", err)
	}
	if exists {
		t.Error("empty memfs should not contain /anything")
	}
}

func TestSetRootFS_ReplacesFs(t *testing.T) {
	t.Parallel()

	r, _, _ := newTestRunner(t)
	newFs := afero.NewMemMapFs()
	if err := newFs.MkdirAll("/custom", 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	r.SetRootFS(newFs)
	ok, err := afero.IsDir(r.RootFS, "/custom")
	if err != nil {
		t.Fatalf("IsDir: %v", err)
	}
	if !ok {
		t.Error("SetRootFS did not replace RootFS")
	}
}
