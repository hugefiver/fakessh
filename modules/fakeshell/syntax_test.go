//go:build !no_fakeshell && !plan9
// +build !no_fakeshell,!plan9

package fakeshell

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hugefiver/fakessh/modules/fakeshell/cmds"
	fsconf "github.com/hugefiver/fakessh/modules/fakeshell/conf"
	"github.com/spf13/afero"
)

func TestParseShellLineLogicalOperators(t *testing.T) {
	t.Parallel()

	line := mustParseShellLine(t, "echo ok && whoami || id")
	if got, want := len(line.Pipelines), 3; got != want {
		t.Fatalf("len(Pipelines) = %d, want %d", got, want)
	}
	if got, want := line.Operators, []string{"&&", "||"}; !stringSlicesEqual(got, want) {
		t.Fatalf("Operators = %#v, want %#v", got, want)
	}

	commands := []simpleCommand{
		line.Pipelines[0].Parts[0].Command,
		line.Pipelines[1].Parts[0].Command,
		line.Pipelines[2].Parts[0].Command,
	}
	if commands[0].Name != "echo" || !stringSlicesEqual(commands[0].Args, []string{"ok"}) {
		t.Fatalf("first command = %#v, want echo ok", commands[0])
	}
	if commands[1].Name != "whoami" || len(commands[1].Args) != 0 {
		t.Fatalf("second command = %#v, want whoami", commands[1])
	}
	if commands[2].Name != "id" || len(commands[2].Args) != 0 {
		t.Fatalf("third command = %#v, want id", commands[2])
	}
}

func TestParseShellLineComments(t *testing.T) {
	t.Parallel()

	line := mustParseShellLine(t, "echo ok # ignored")
	cmd := onlyCommand(t, line)
	if cmd.Name != "echo" || !stringSlicesEqual(cmd.Args, []string{"ok"}) {
		t.Fatalf("command = %#v, want echo ok", cmd)
	}

	line = mustParseShellLine(t, `echo "# not a comment"`)
	cmd = onlyCommand(t, line)
	if cmd.Name != "echo" || !stringSlicesEqual(cmd.Args, []string{"# not a comment"}) {
		t.Fatalf("quoted hash command = %#v, want literal hash arg", cmd)
	}
}

func TestParseShellLineRedirections(t *testing.T) {
	t.Parallel()

	line := mustParseShellLine(t, "echo ok > out 2> err 2>&1")
	cmd := onlyCommand(t, line)
	if cmd.Name != "echo" || !stringSlicesEqual(cmd.Args, []string{"ok"}) {
		t.Fatalf("command = %#v, want echo ok with redirection tokens stripped from argv", cmd)
	}
	if got, want := len(cmd.Redirects), 3; got != want {
		t.Fatalf("len(Redirects) = %d, want %d: %#v", got, want, cmd.Redirects)
	}
	if got := cmd.Redirects[0]; got.FD != 1 || got.Operator != ">" || got.Target != "out" || got.Duplicate {
		t.Fatalf("Redirects[0] = %#v, want stdout output target out", got)
	}
	if got := cmd.Redirects[1]; got.FD != 2 || got.Operator != "2>" || got.Target != "err" || got.Duplicate {
		t.Fatalf("Redirects[1] = %#v, want stderr output target err", got)
	}
	if got := cmd.Redirects[2]; got.FD != 2 || got.Operator != ">&" || !got.Duplicate || got.DuplicateFD != 1 {
		t.Fatalf("Redirects[2] = %#v, want stderr duplicate stdout", got)
	}
}

func TestParseShellLineRejectsGluedRedirectionCommentSuffix(t *testing.T) {
	t.Parallel()

	_, err := parseShellLine([]byte("echo ok 2>&1# ignored"))
	if !errors.Is(err, errSyntaxParse) || isSyntaxLimitError(err) {
		t.Fatalf("parseShellLine() error = %v, want non-limit syntax error", err)
	}

	if _, err := parseShellLine([]byte("echo ok 2>&1 # comment")); err != nil {
		t.Fatalf("parseShellLine() spaced comment error = %v, want nil", err)
	}
}

func TestParseShellLineEnvAssignments(t *testing.T) {
	t.Parallel()

	line := mustParseShellLine(t, "FOO=bar USER=bob echo $FOO")
	cmd := onlyCommand(t, line)
	if got, want := cmd.EnvAssignments, []string{"FOO=bar", "USER=bob"}; !stringSlicesEqual(got, want) {
		t.Fatalf("EnvAssignments = %#v, want %#v", got, want)
	}
	if cmd.Name != "echo" || !stringSlicesEqual(cmd.Args, []string{"$FOO"}) {
		t.Fatalf("command = %#v, want echo $FOO", cmd)
	}

	line = mustParseShellLine(t, "FOO=bar")
	cmd = onlyCommand(t, line)
	if got, want := cmd.EnvAssignments, []string{"FOO=bar"}; !stringSlicesEqual(got, want) {
		t.Fatalf("assignment-only EnvAssignments = %#v, want %#v", got, want)
	}
	if cmd.Name != "" || len(cmd.Args) != 0 {
		t.Fatalf("assignment-only command = %#v, want no command name or args", cmd)
	}
}

func TestParseShellLinePipeline(t *testing.T) {
	t.Parallel()

	line := mustParseShellLine(t, "cat /etc/passwd | wc -l")
	if got, want := len(line.Pipelines), 1; got != want {
		t.Fatalf("len(Pipelines) = %d, want %d", got, want)
	}
	pipe := line.Pipelines[0]
	if got, want := len(pipe.Parts), 2; got != want {
		t.Fatalf("len(Parts) = %d, want %d", got, want)
	}
	if got, want := pipe.Operators, []string{"|"}; !stringSlicesEqual(got, want) {
		t.Fatalf("pipeline Operators = %#v, want %#v", got, want)
	}
	if cmd := pipe.Parts[0].Command; cmd.Name != "cat" || !stringSlicesEqual(cmd.Args, []string{"/etc/passwd"}) {
		t.Fatalf("first pipeline command = %#v, want cat /etc/passwd", cmd)
	}
	if cmd := pipe.Parts[1].Command; cmd.Name != "wc" || !stringSlicesEqual(cmd.Args, []string{"-l"}) {
		t.Fatalf("second pipeline command = %#v, want wc -l", cmd)
	}
}

func TestSyntaxRejectsVisibleUnsupported(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
	}{
		{name: "command substitution", in: "echo $(id)"},
		{name: "backticks", in: "echo `id`"},
		{name: "heredoc", in: "cat << EOF"},
		{name: "process substitution", in: "cat <(id)"},
		{name: "grouping", in: "( echo ok )"},
		{name: "background", in: "echo ok &"},
		{name: "brace expansion", in: "echo {a,b}"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseShellLine([]byte(tt.in))
			if err == nil {
				t.Fatalf("parseShellLine(%q) error = nil, want parse error", tt.in)
			}
			if !errors.Is(err, errSyntaxParse) {
				t.Fatalf("parseShellLine(%q) error = %v, want errSyntaxParse", tt.in, err)
			}
			if isSyntaxLimitError(err) {
				t.Fatalf("parseShellLine(%q) returned limit error for visible unsupported syntax: %v", tt.in, err)
			}
			if got, want := syntaxErrorMessage(err), "fakeshell: syntax error"; got != want {
				t.Fatalf("syntaxErrorMessage() = %q, want %q", got, want)
			}
		})
	}
}

func TestSyntaxSingleQuotedUnsupportedFormsAreLiteral(t *testing.T) {
	t.Setenv("SECRET_TOKEN", "host-secret")
	runner := newSyntaxTestRunner(t, map[string]string{
		"PWD":          "/",
		"SECRET_TOKEN": "fake-secret",
	})

	line := mustParseShellLine(t, `echo '$SECRET_TOKEN' '$(id)' '()' '{}'`)
	cmd := onlyCommand(t, line)
	expanded, cleanup, err := expandSimpleCommand(runner, cmd, 0)
	if err != nil {
		t.Fatalf("expandSimpleCommand single quoted literals: %v", err)
	}
	defer cleanup()
	want := []string{"$SECRET_TOKEN", "$(id)", "()", "{}"}
	if !stringSlicesEqual(expanded.Args, want) {
		t.Fatalf("expanded.Args = %#v, want %#v", expanded.Args, want)
	}
	if strings.Contains(strings.Join(expanded.Args, " "), "fake-secret") || strings.Contains(strings.Join(expanded.Args, " "), "host-secret") {
		t.Fatalf("single quoted expansion leaked env: %#v", expanded.Args)
	}
}

func TestSyntaxMixedSingleQuotedTokensDoNotMaskUnquotedParts(t *testing.T) {
	t.Setenv("SECRET_TOKEN", "host-secret")
	runner := newSyntaxTestRunner(t, map[string]string{
		"PWD":          "/",
		"SECRET_TOKEN": "fake-secret",
		"OTHER":        "fake-other",
	})

	for _, in := range []string{`echo ''$(id)`, `echo x'$VAR'()`} {
		t.Run(in, func(t *testing.T) {
			_, err := parseShellLine([]byte(in))
			if err == nil || !errors.Is(err, errSyntaxParse) || isSyntaxLimitError(err) {
				t.Fatalf("parseShellLine(%q) error = %v, want visible syntax error", in, err)
			}
		})
	}

	line := mustParseShellLine(t, `echo x'$SECRET_TOKEN'$OTHER`)
	cmd := onlyCommand(t, line)
	expanded, cleanup, err := expandSimpleCommand(runner, cmd, 0)
	if err != nil {
		t.Fatalf("expandSimpleCommand mixed token: %v", err)
	}
	defer cleanup()
	if want := []string{"x$SECRET_TOKENfake-other"}; !stringSlicesEqual(expanded.Args, want) {
		t.Fatalf("expanded mixed token args = %#v, want %#v", expanded.Args, want)
	}
	if strings.Contains(strings.Join(expanded.Args, " "), "host-secret") {
		t.Fatalf("mixed token expansion leaked host env: %#v", expanded.Args)
	}
}

func TestExpandMixedQuoteSegments(t *testing.T) {
	runner := newSyntaxTestRunner(t, map[string]string{"PWD": "/tmp", "SECRET": "fake-secret", "OTHER": "fake-other"})
	line := mustParseShellLine(t, `echo x'$SECRET'$OTHER`)
	expanded, cleanup, err := expandSimpleCommand(runner, onlyCommand(t, line), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got, want := expanded.Args, []string{"x$SECRETfake-other"}; !stringSlicesEqual(got, want) {
		t.Fatalf("Args = %#v, want %#v", got, want)
	}

	cmd := onlyCommand(t, mustParseShellLine(t, `echo \$SECRET`))
	expanded, cleanup, err = expandSimpleCommand(runner, cmd, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got, want := expanded.Args, []string{"$SECRET"}; !stringSlicesEqual(got, want) {
		t.Fatalf("escaped dollar Args = %#v, want %#v", got, want)
	}
}

func TestExpandPreservesEmptyQuotedArgument(t *testing.T) {
	runner := newSyntaxTestRunner(t, map[string]string{"PWD": "/tmp"})
	cmd := onlyCommand(t, mustParseShellLine(t, `echo ""`))
	expanded, cleanup, err := expandSimpleCommand(runner, cmd, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got, want := expanded.Args, []string{""}; !stringSlicesEqual(got, want) {
		t.Fatalf("Args = %#v, want one empty argument", got)
	}
}

func TestExpandQuotedGlobIsLiteral(t *testing.T) {
	runner := newSyntaxTestRunner(t, map[string]string{"PWD": "/tmp"})
	writeSyntaxFile(t, runner.RootFS, "/tmp/a.txt")
	writeSyntaxFile(t, runner.RootFS, "/tmp/b.txt")
	cmd := onlyCommand(t, mustParseShellLine(t, `echo "*.txt" '*.txt' \*.txt`))
	expanded, cleanup, err := expandSimpleCommand(runner, cmd, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got, want := expanded.Args, []string{"*.txt", "*.txt", "*.txt"}; !stringSlicesEqual(got, want) {
		t.Fatalf("Args = %#v, want %#v", got, want)
	}
}

func TestSyntaxRejectsUnimplementedForms(t *testing.T) {
	t.Parallel()

	for _, in := range []string{
		"cat < /etc/passwd",
		"echo ok >> out",
		"echo ok 2>> err",
		"echo ~",
		"echo ~/tmp",
		"FOO=$BAR echo ok",
		`FOO="bar" echo ok`,
		`FOO='bar' echo ok`,
		"FOO=* echo ok",
		"FOO=? echo ok",
		"FOO=~ echo ok",
		`FOO=bar\ baz echo ok`,
	} {
		t.Run(in, func(t *testing.T) {
			_, err := parseShellLine([]byte(in))
			if !errors.Is(err, errSyntaxParse) || isSyntaxLimitError(err) {
				t.Fatalf("parseShellLine(%q) error = %v, want non-limit syntax error", in, err)
			}
		})
	}
}

func TestSyntaxLiteralAssignmentRHS(t *testing.T) {
	line := mustParseShellLine(t, "FOO=bar echo $FOO")
	cmd := onlyCommand(t, line)
	if got, want := cmd.EnvAssignments, []string{"FOO=bar"}; !stringSlicesEqual(got, want) {
		t.Fatalf("EnvAssignments = %#v, want %#v", got, want)
	}
	cmd = onlyCommand(t, mustParseShellLine(t, "FOO=bar"))
	if got, want := cmd.EnvAssignments, []string{"FOO=bar"}; !stringSlicesEqual(got, want) {
		t.Fatalf("assignment-only EnvAssignments = %#v, want %#v", got, want)
	}
}

func TestExpandQuotedRedirectTargetIsLiteral(t *testing.T) {
	runner := newSyntaxTestRunner(t, map[string]string{"PWD": "/tmp"})
	writeSyntaxFile(t, runner.RootFS, "/tmp/a.txt")
	writeSyntaxFile(t, runner.RootFS, "/tmp/b.txt")
	cmd := onlyCommand(t, mustParseShellLine(t, `echo ok > "*.txt"`))
	expanded, cleanup, err := expandSimpleCommand(runner, cmd, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got, want := expanded.Redirects[0].Target, "*.txt"; got != want {
		t.Fatalf("redirect target = %q, want %q", got, want)
	}
}

func TestSyntaxRejectsUnsupportedNumericFDRedirection(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"echo ok 3>out", "echo ok 10>>out", "cat 4<input"} {
		t.Run(in, func(t *testing.T) {
			_, err := parseShellLine([]byte(in))
			if err == nil {
				t.Fatalf("parseShellLine(%q) error = nil, want syntax error", in)
			}
			if !errors.Is(err, errSyntaxParse) || isSyntaxLimitError(err) {
				t.Fatalf("parseShellLine(%q) error = %v, want visible syntax parse error", in, err)
			}
		})
	}
}

func TestSyntaxLimitErrors(t *testing.T) {
	t.Parallel()

	t.Run("tokens", func(t *testing.T) {
		t.Parallel()
		assertSyntaxLimitError(t, strings.Repeat("x ", MaxSyntaxTokens+1))
	})
	t.Run("operators", func(t *testing.T) {
		t.Parallel()
		assertSyntaxLimitError(t, strings.Repeat("&& ", MaxSyntaxOperators+1))
	})
	t.Run("redirections", func(t *testing.T) {
		t.Parallel()
		parts := []string{"cat"}
		for i := 0; i < MaxRedirectionsPerCommand+1; i++ {
			parts = append(parts, ">", fmt.Sprintf("out%d", i))
		}
		assertSyntaxLimitError(t, strings.Join(parts, " "))
	})
}

func TestExpandVariablesUsesFakeEnvAndStatus(t *testing.T) {
	t.Setenv("PATH", "/real/host/path")
	t.Setenv("SECRET_TOKEN", "host-secret")

	runner := newSyntaxTestRunner(t, map[string]string{
		"USER": "alice",
		"HOME": "/home/alice",
		"PWD":  "/home/alice",
	})

	expanded, cleanup, err := expandSimpleCommand(runner, simpleCommand{
		Name: "echo",
		Args: []string{"$USER", "$HOME", "$?", "$UNKNOWN", "$PATH", "$SECRET_TOKEN"},
	}, 17)
	if err != nil {
		t.Fatalf("expandSimpleCommand: %v", err)
	}
	defer cleanup()

	if expanded.Name != "echo" {
		t.Fatalf("expanded.Name = %q, want echo", expanded.Name)
	}
	want := []string{"alice", "/home/alice", "17", "", "", ""}
	if !stringSlicesEqual(expanded.Args, want) {
		t.Fatalf("expanded.Args = %#v, want %#v", expanded.Args, want)
	}
	if got := os.Getenv("SECRET_TOKEN"); got != "host-secret" {
		t.Fatalf("test host env changed: SECRET_TOKEN = %q", got)
	}
}

func TestExpandCommandScopedEnvRestoresAndAssignmentOnlyPersists(t *testing.T) {
	runner := newSyntaxTestRunner(t, map[string]string{
		"FOO": "base",
		"PWD": "/",
	})
	runner.SetEnv("TEMP", "old")

	expanded, cleanup, err := expandSimpleCommand(runner, simpleCommand{
		EnvAssignments: []string{"FOO=scoped", "BAR=new", "TEMP=changed"},
		Name:           "echo",
		Args:           []string{"$FOO", "$BAR", "$TEMP"},
	}, 0)
	if err != nil {
		t.Fatalf("expandSimpleCommand command scoped: %v", err)
	}
	if want := []string{"scoped", "new", "changed"}; !stringSlicesEqual(expanded.Args, want) {
		t.Fatalf("expanded.Args = %#v, want %#v", expanded.Args, want)
	}
	if got := runner.GetEnv("FOO"); got != "scoped" {
		t.Fatalf("FOO before cleanup = %q, want scoped", got)
	}
	cleanup()
	if got := runner.GetEnv("FOO"); got != "base" {
		t.Fatalf("FOO after cleanup = %q, want base", got)
	}
	if got := runner.GetEnv("BAR"); got != "" {
		t.Fatalf("BAR after cleanup = %q, want empty", got)
	}
	if got := runner.GetEnv("TEMP"); got != "old" {
		t.Fatalf("TEMP after cleanup = %q, want old", got)
	}

	if err := executeAssignmentOnly(runner, []string{"FOO=persist", "BAR=kept"}); err != nil {
		t.Fatalf("executeAssignmentOnly: %v", err)
	}
	if got := runner.GetEnv("FOO"); got != "persist" {
		t.Fatalf("FOO after assignment-only = %q, want persist", got)
	}
	if got := runner.GetEnv("BAR"); got != "kept" {
		t.Fatalf("BAR after assignment-only = %q, want kept", got)
	}
}

func TestAssignmentOnlyEnvIsBounded(t *testing.T) {
	runner := newSyntaxTestRunner(t, map[string]string{"PWD": "/"})

	if err := executeAssignmentOnly(runner, []string{"BIG=" + strings.Repeat("x", MaxInputTokenBytes+1)}); err == nil || !isSyntaxLimitError(err) {
		t.Fatalf("overlong assignment error = %v, want syntax limit", err)
	}
	if got := runner.GetEnv("BIG"); got != "" {
		t.Fatalf("BIG persisted after rejected assignment = %q", got)
	}

	var assignments []string
	for i := 0; i < MaxSessionEnvEntries+1; i++ {
		assignments = append(assignments, fmt.Sprintf("K%02d=v", i))
	}
	if err := executeAssignmentOnly(runner, assignments); err == nil || !isSyntaxLimitError(err) {
		t.Fatalf("too many assignments error = %v, want syntax limit", err)
	}

	assignments = assignments[:0]
	for i := 0; i < MaxSessionEnvEntries; i++ {
		assignments = append(assignments, fmt.Sprintf("E%02d=v", i))
	}
	if err := executeAssignmentOnly(runner, assignments); err != nil {
		t.Fatalf("assignment at entry cap rejected: %v", err)
	}
	if err := executeAssignmentOnly(runner, []string{"E00=updated"}); err != nil {
		t.Fatalf("updating existing assignment at cap rejected: %v", err)
	}
	if err := executeAssignmentOnly(runner, []string{"EXTRA=v"}); err == nil || !isSyntaxLimitError(err) {
		t.Fatalf("new assignment past cap error = %v, want syntax limit", err)
	}
}

func TestAssignmentOnlyEnvTotalBytesBounded(t *testing.T) {
	runner := newSyntaxTestRunner(t, map[string]string{"PWD": "/"})
	value := strings.Repeat("x", MaxInputTokenBytes-8)
	var assignments []string
	for i := 0; i < MaxSessionEnvEntries; i++ {
		assignments = append(assignments, fmt.Sprintf("B%02d=%s", i, value))
	}
	if err := executeAssignmentOnly(runner, assignments); err == nil || !isSyntaxLimitError(err) {
		t.Fatalf("oversized session env error = %v, want syntax limit", err)
	}
}

func TestExpandEmptyCommandNameStillEnforcesArgsLimit(t *testing.T) {
	runner := newSyntaxTestRunner(t, map[string]string{"PWD": "/"})
	args := make([]string, MaxInputArgs+1)
	for i := range args {
		args[i] = "x"
	}
	_, cleanup, err := expandSimpleCommand(runner, simpleCommand{Name: "$UNSET", Args: args}, 0)
	defer cleanup()
	if err == nil || !isSyntaxLimitError(err) {
		t.Fatalf("empty command with too many args error = %v, want syntax limit", err)
	}
}

func TestExpandOverlongVariableReturnsSyntaxLimit(t *testing.T) {
	runner := newSyntaxTestRunner(t, map[string]string{
		"FOO": strings.Repeat("x", MaxInputTokenBytes+1),
		"PWD": "/tmp",
	})

	_, cleanup, err := expandSimpleCommand(runner, simpleCommand{Name: "echo", Args: []string{"$FOO"}}, 0)
	defer cleanup()
	if err == nil {
		t.Fatal("expandSimpleCommand overlong arg error = nil, want syntax limit")
	}
	if !isSyntaxLimitError(err) {
		t.Fatalf("expandSimpleCommand overlong arg error = %v, want syntax limit", err)
	}
	if strings.Contains(err.Error(), runner.GetEnv("FOO")) {
		t.Fatal("overlong expansion error leaked attacker-controlled value")
	}

	_, cleanup, err = expandSimpleCommand(runner, simpleCommand{
		Name:      "echo",
		Redirects: []redirectSpec{{FD: 1, Operator: ">", Target: "$FOO"}},
	}, 0)
	defer cleanup()
	if err == nil {
		t.Fatal("expandSimpleCommand overlong redirect target error = nil, want syntax limit")
	}
	if !isSyntaxLimitError(err) {
		t.Fatalf("expandSimpleCommand overlong redirect target error = %v, want syntax limit", err)
	}
	if strings.Contains(err.Error(), runner.GetEnv("FOO")) {
		t.Fatal("overlong redirect target error leaked attacker-controlled value")
	}
}

func TestGlobExpandsStaticAndDynamicEntries(t *testing.T) {
	runner := newSyntaxTestRunner(t, map[string]string{"PWD": "/home/root"})
	writeSyntaxFile(t, runner.RootFS, "/home/root/static.txt")
	writeSyntaxFile(t, runner.RootFS, "/home/root/other.log")
	writeSyntaxFile(t, runner.RootFS, "/tmp/abs-a")
	writeSyntaxFile(t, runner.RootFS, "/tmp/abs-b")
	if _, err := runner.Dynamic.Record("/home/root/dynamic.txt", "file", 0, nil, ""); err != nil {
		t.Fatalf("record dynamic.txt: %v", err)
	}
	if _, err := runner.Dynamic.Record("/home/root/static.txt", "file", 0, nil, ""); err != nil {
		t.Fatalf("record duplicate static.txt: %v", err)
	}

	expanded, cleanup, err := expandSimpleCommand(runner, simpleCommand{
		Name: "echo",
		Args: []string{"*.txt", "none*", "/tmp/abs-?"},
	}, 0)
	if err != nil {
		t.Fatalf("expandSimpleCommand glob: %v", err)
	}
	defer cleanup()

	want := []string{"dynamic.txt", "static.txt", "none*", "/tmp/abs-a", "/tmp/abs-b"}
	if !stringSlicesEqual(expanded.Args, want) {
		t.Fatalf("expanded.Args = %#v, want %#v", expanded.Args, want)
	}
}

func TestGlobOverCapReturnsSyntaxLimit(t *testing.T) {
	runner := newSyntaxTestRunner(t, map[string]string{"PWD": "/tmp"})
	for i := 0; i < MaxGlobMatches+1; i++ {
		writeSyntaxFile(t, runner.RootFS, fmt.Sprintf("/tmp/m%02d", i))
	}

	_, cleanup, err := expandSimpleCommand(runner, simpleCommand{Name: "echo", Args: []string{"m*"}}, 0)
	defer cleanup()
	if err == nil {
		t.Fatal("expandSimpleCommand over-cap glob error = nil, want syntax limit")
	}
	if !isSyntaxLimitError(err) {
		t.Fatalf("expandSimpleCommand over-cap glob error = %v, want syntax limit", err)
	}
}

func TestRedirectionRecordsMetadataSuppressesOutputAndIsSessionLocal(t *testing.T) {
	runner := newSyntaxTestRunner(t, map[string]string{"PWD": "/tmp"})
	other := newSyntaxTestRunner(t, map[string]string{"PWD": "/tmp"})

	var visibleOut, visibleErr bytes.Buffer
	out, errw, cleanup, err := applyFakeRedirections(runner, simpleCommand{
		Redirects: []redirectSpec{{FD: 1, Operator: ">", Target: "out.txt"}},
	}, &visibleOut, &visibleErr)
	if err != nil {
		t.Fatalf("applyFakeRedirections: %v", err)
	}
	if _, err := out.Write([]byte("hello world")); err != nil {
		t.Fatalf("write redirected stdout: %v", err)
	}
	if _, err := errw.Write([]byte("visible stderr")); err != nil {
		t.Fatalf("write stderr: %v", err)
	}
	cleanup()

	if got := visibleOut.String(); got != "" {
		t.Fatalf("visible stdout = %q, want suppressed", got)
	}
	if got := visibleErr.String(); got != "visible stderr" {
		t.Fatalf("visible stderr = %q, want visible stderr", got)
	}
	entries := runner.Dynamic.Entries()
	if len(entries) != 1 {
		t.Fatalf("runner dynamic entries = %d, want 1: %#v", len(entries), entries)
	}
	entry := entries[0]
	if entry.Path != "/tmp/out.txt" || entry.Kind != "file" || entry.Size != int64(len("hello world")) || entry.Preview != nil || entry.SHA256 != "" {
		t.Fatalf("redirect metadata = %#v, want /tmp/out.txt file size only", entry)
	}
	if entries := other.Dynamic.Entries(); len(entries) != 0 {
		t.Fatalf("other runner dynamic entries = %#v, want none", entries)
	}
}

func TestRedirectionDuplicateStderrFollowsStdoutRedirection(t *testing.T) {
	runner := newSyntaxTestRunner(t, map[string]string{"PWD": "/tmp"})
	var visibleOut, visibleErr bytes.Buffer
	out, errw, cleanup, err := applyFakeRedirections(runner, simpleCommand{
		Redirects: []redirectSpec{
			{FD: 1, Operator: ">", Target: "combined.log"},
			{FD: 2, Operator: ">&", Duplicate: true, DuplicateFD: 1},
		},
	}, &visibleOut, &visibleErr)
	if err != nil {
		t.Fatalf("applyFakeRedirections 2>&1: %v", err)
	}
	if _, err := out.Write([]byte("out")); err != nil {
		t.Fatalf("write stdout: %v", err)
	}
	if _, err := errw.Write([]byte("err")); err != nil {
		t.Fatalf("write stderr: %v", err)
	}
	cleanup()

	if visibleOut.String() != "" || visibleErr.String() != "" {
		t.Fatalf("visible out/err = %q/%q, want both suppressed", visibleOut.String(), visibleErr.String())
	}
	entries := runner.Dynamic.Entries()
	if len(entries) != 1 {
		t.Fatalf("dynamic entries = %d, want 1", len(entries))
	}
	if got, want := entries[0].Size, int64(len("outerr")); got != want {
		t.Fatalf("combined redirection size = %d, want %d", got, want)
	}
}

func TestRedirectionRuntimeRejectsParserUnsupportedForms(t *testing.T) {
	runner := newSyntaxTestRunner(t, map[string]string{"PWD": "/tmp"})
	for _, redir := range []redirectSpec{
		{FD: 0, Operator: "<", Target: "in.txt"},
		{FD: 1, Operator: ">>", Target: "out.txt"},
		{FD: 2, Operator: "2>>", Target: "err.txt"},
	} {
		_, _, cleanup, err := applyFakeRedirections(runner, simpleCommand{Redirects: []redirectSpec{redir}}, &bytes.Buffer{}, &bytes.Buffer{})
		cleanup()
		if err == nil || err.Error() != "fakeshell: unsupported redirection" {
			t.Fatalf("applyFakeRedirections(%#v) error = %v, want unsupported redirection", redir, err)
		}
	}
}

func TestRedirectionPreflightsDynamicStoreCapacity(t *testing.T) {
	runner := newSyntaxTestRunner(t, map[string]string{"PWD": "/tmp"})
	for i := 0; i < cmds.MaxDynamicEntries; i++ {
		if _, err := runner.Dynamic.Record(fmt.Sprintf("/tmp/f%03d", i), "file", 0, nil, ""); err != nil {
			t.Fatalf("fill dynamic store entry %d: %v", i, err)
		}
	}

	_, _, cleanup, err := applyFakeRedirections(runner, simpleCommand{
		Redirects: []redirectSpec{{FD: 1, Operator: ">", Target: "new.out"}},
	}, &bytes.Buffer{}, &bytes.Buffer{})
	defer cleanup()
	if err == nil {
		t.Fatal("applyFakeRedirections with full dynamic store accepted new target, want error")
	}

	var visible bytes.Buffer
	out, _, cleanup, err := applyFakeRedirections(runner, simpleCommand{
		Redirects: []redirectSpec{{FD: 1, Operator: ">", Target: "f000"}},
	}, &visible, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("applyFakeRedirections existing target at capacity: %v", err)
	}
	if _, err := out.Write([]byte("updated-size")); err != nil {
		t.Fatalf("write existing redirected target: %v", err)
	}
	cleanup()
	if visible.String() != "" {
		t.Fatalf("visible stdout = %q, want suppressed", visible.String())
	}
	found := false
	for _, entry := range runner.Dynamic.Entries() {
		if entry.Path == "/tmp/f000" {
			found = true
			if got, want := entry.Size, int64(len("updated-size")); got != want {
				t.Fatalf("updated existing target size = %d, want %d", got, want)
			}
		}
	}
	if !found {
		t.Fatal("existing dynamic target /tmp/f000 missing after cleanup")
	}
}

func TestRedirectionPreflightsMultipleNewTargetsTogether(t *testing.T) {
	runner := newSyntaxTestRunner(t, map[string]string{"PWD": "/tmp"})
	for i := 0; i < cmds.MaxDynamicEntries-1; i++ {
		if _, err := runner.Dynamic.Record(fmt.Sprintf("/tmp/f%03d", i), "file", 0, nil, ""); err != nil {
			t.Fatalf("fill dynamic store entry %d: %v", i, err)
		}
	}

	_, _, cleanup, err := applyFakeRedirections(runner, simpleCommand{
		Redirects: []redirectSpec{
			{FD: 1, Operator: ">", Target: "one.out"},
			{FD: 2, Operator: "2>", Target: "two.err"},
		},
	}, &bytes.Buffer{}, &bytes.Buffer{})
	defer cleanup()
	if err == nil {
		t.Fatal("applyFakeRedirections accepted two new targets with one slot left, want error")
	}
	for _, entry := range runner.Dynamic.Entries() {
		if entry.Path == "/tmp/one.out" || entry.Path == "/tmp/two.err" {
			t.Fatalf("redirection metadata recorded despite preflight failure: %#v", entry)
		}
	}
}

func TestRedirectionOverlongOutputPathReturnsLimit(t *testing.T) {
	runner := newSyntaxTestRunner(t, map[string]string{"PWD": "/"})
	target := "/" + strings.Repeat("x", cmds.MaxDynamicPathLen)
	_, _, cleanup, err := applyFakeRedirections(runner, simpleCommand{
		Redirects: []redirectSpec{{FD: 1, Operator: ">", Target: target}},
	}, &bytes.Buffer{}, &bytes.Buffer{})
	defer cleanup()
	if err == nil {
		t.Fatal("applyFakeRedirections overlong target error = nil, want error")
	}
	if !isSyntaxLimitError(err) {
		t.Fatalf("applyFakeRedirections overlong target error = %v, want syntax limit", err)
	}
	if strings.Contains(err.Error(), target) {
		t.Fatal("overlong output path error leaked attacker-controlled path")
	}
}

func mustParseShellLine(t *testing.T, in string) shellLine {
	t.Helper()
	line, err := parseShellLine([]byte(in))
	if err != nil {
		t.Fatalf("parseShellLine(%q) error = %v", in, err)
	}
	return line
}

func onlyCommand(t *testing.T, line shellLine) simpleCommand {
	t.Helper()
	if len(line.Pipelines) != 1 || len(line.Pipelines[0].Parts) != 1 {
		t.Fatalf("line = %#v, want exactly one command", line)
	}
	return line.Pipelines[0].Parts[0].Command
}

func assertSyntaxLimitError(t *testing.T, in string) {
	t.Helper()
	_, err := parseShellLine([]byte(in))
	if err == nil {
		t.Fatalf("parseShellLine(%q) error = nil, want limit error", in)
	}
	if !errors.Is(err, errSyntaxParse) {
		t.Fatalf("parseShellLine(%q) error = %v, want errSyntaxParse", in, err)
	}
	if !isSyntaxLimitError(err) {
		t.Fatalf("parseShellLine(%q) error = %v, want syntax limit error", in, err)
	}
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func newSyntaxTestRunner(t *testing.T, env map[string]string) *cmds.CommandRunner {
	t.Helper()
	cfg := &fsconf.FakeshellConfig{}
	cfg.EnvConfig.Envs = env
	runner := cmds.NewCommandRunner(cfg)
	fs := afero.NewMemMapFs()
	for _, dir := range []string{"/home", "/home/root", "/home/alice", "/tmp", "/etc", "/proc"} {
		if err := fs.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	runner.RootFS = fs
	if runner.GetEnv("PWD") == "" {
		runner.SetEnv("PWD", "/")
	}
	return runner
}

func writeSyntaxFile(t *testing.T, fs afero.Fs, filePath string) {
	t.Helper()
	f, err := fs.Create(filePath)
	if err != nil {
		t.Fatalf("create %s: %v", filePath, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", filePath, err)
	}
}
