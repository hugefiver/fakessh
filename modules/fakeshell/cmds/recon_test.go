package cmds

import (
	"bytes"
	"strings"
	"testing"

	fsconf "github.com/hugefiver/fakessh/modules/fakeshell/conf"
	"github.com/spf13/afero"
)

func TestProfileTruncateOutputWithinCapAndMarksTruncation(t *testing.T) {
	t.Parallel()

	input := strings.Repeat("a", MaxCommandOutputBytes+1024)
	got := truncateOutput(input)

	if len(got) > MaxCommandOutputBytes {
		t.Fatalf("truncateOutput length = %d, want <= %d", len(got), MaxCommandOutputBytes)
	}
	if !strings.Contains(got, outputTruncatedMarker) {
		t.Fatalf("truncateOutput missing marker %q", outputTruncatedMarker)
	}
	if !strings.HasSuffix(got, outputTruncatedMarker) {
		t.Fatalf("truncateOutput should end with marker, got suffix %q", got[len(got)-len(outputTruncatedMarker):])
	}
}

func TestProfileTruncateOutputLeavesSmallOutputUnchanged(t *testing.T) {
	t.Parallel()

	input := "small fake output\n"
	if got := truncateOutput(input); got != input {
		t.Fatalf("truncateOutput(%q) = %q, want unchanged", input, got)
	}
}

func TestProfileWriteBoundedDoesNotWriteBeyondCap(t *testing.T) {
	t.Parallel()

	input := strings.Repeat("b", MaxCommandOutputBytes*2)
	var buf bytes.Buffer
	if err := writeBounded(&buf, input); err != nil {
		t.Fatalf("writeBounded: %v", err)
	}

	if got := buf.Len(); got > MaxCommandOutputBytes {
		t.Fatalf("buffer length = %d, want <= %d", got, MaxCommandOutputBytes)
	}
	if !strings.Contains(buf.String(), outputTruncatedMarker) {
		t.Fatalf("writeBounded output missing marker %q", outputTruncatedMarker)
	}
}

func TestFakeFileContentAllowsOnlyExactTinyFakePaths(t *testing.T) {
	t.Parallel()

	allowed := []string{
		"/etc/hostname",
		"/etc/os-release",
		"/etc/passwd",
		"/proc/version",
		"/proc/uptime",
	}
	for _, path := range allowed {
		got, ok := fakeFileContent(path)
		if !ok {
			t.Fatalf("fakeFileContent(%q) ok = false, want true", path)
		}
		if got == "" {
			t.Fatalf("fakeFileContent(%q) returned empty content", path)
		}
		if len(got) >= 1024 {
			t.Fatalf("fakeFileContent(%q) length = %d, want tiny content", path, len(got))
		}
	}

	rejected := []string{
		"/etc/shadow",
		"/arbitrary/path",
		"/etc/../etc/passwd",
		"../etc/passwd",
		"C:/Windows/System32/drivers/etc/hosts",
		`C:\Windows\System32\drivers\etc\hosts`,
		"/host/etc/passwd",
		"/proc/self/environ",
	}
	for _, path := range rejected {
		if got, ok := fakeFileContent(path); ok || got != "" {
			t.Fatalf("fakeFileContent(%q) = (%q, %v), want empty false", path, got, ok)
		}
	}
}

func TestUnsupportedOptionReturnsStableError(t *testing.T) {
	t.Parallel()

	err := unsupportedOption("cat", "-A")
	if err == nil {
		t.Fatal("unsupportedOption returned nil")
	}
	if got := err.Error(); got != "cat: unsupported option -A" {
		t.Fatalf("unsupportedOption error = %q, want stable message", got)
	}
}

func TestUnsupportedOptionBoundsAttackerInput(t *testing.T) {
	t.Parallel()

	longOpt := "-" + strings.Repeat("x", 200)
	err := unsupportedOption("cmd", longOpt)
	if err == nil {
		t.Fatal("unsupportedOption returned nil")
	}
	if len(err.Error()) > len("cmd: unsupported option ")+83 {
		t.Fatalf("unsupportedOption error length = %d, want bounded", len(err.Error()))
	}
	if !strings.HasSuffix(err.Error(), "...") {
		t.Fatalf("unsupportedOption long input should end with ellipsis, got %q", err.Error())
	}
}

func TestCmdReconIdentityAndSessionCommands(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cmd  Command
		want []string
	}{
		{name: "id", cmd: CmdId, want: []string{"uid=0(root)", "gid=0(root)", "groups=0(root)"}},
		{name: "groups", cmd: CmdGroups, want: []string{"root\n"}},
		{name: "who", cmd: CmdWho, want: []string{"root", "pts/0", "1970-01-01"}},
		{name: "w", cmd: CmdW, want: []string{"USER", "load average", "root"}},
		{name: "last", cmd: CmdLast, want: []string{"root", "still logged in", "reboot"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner, stdout, stderr := newReconTestRunner(t)
			if err := tc.cmd.Run(runner); err != nil {
				t.Fatalf("%s returned error: %v", tc.name, err)
			}
			if stderr.String() != "" {
				t.Fatalf("%s stderr = %q, want empty", tc.name, stderr.String())
			}
			for _, want := range tc.want {
				if !strings.Contains(stdout.String(), want) {
					t.Fatalf("%s stdout %q missing %q", tc.name, stdout.String(), want)
				}
			}
			if stdout.Len() > MaxCommandOutputBytes {
				t.Fatalf("%s stdout length = %d, want <= cap", tc.name, stdout.Len())
			}
		})
	}
}

func TestCmdReconSystemProfileCommands(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cmd  Command
		args []string
		want []string
	}{
		{name: "date", cmd: CmdDate, want: []string{"Thu Jan  1 00:00:00 UTC 1970\n"}},
		{name: "uptime", cmd: CmdUptime, want: []string{"up 3:25", "load average"}},
		{name: "df", cmd: CmdDf, args: []string{"-h"}, want: []string{"Filesystem", "fakeshellfs", "/"}},
		{name: "free", cmd: CmdFree, args: []string{"-m"}, want: []string{"Mem:", "Swap:"}},
		{name: "ps", cmd: CmdPs, args: []string{"-ef"}, want: []string{"PID", "init", "ps"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner, stdout, stderr := newReconTestRunner(t)
			if err := tc.cmd.Run(runner, tc.args...); err != nil {
				t.Fatalf("%s returned error: %v", tc.name, err)
			}
			if stderr.String() != "" {
				t.Fatalf("%s stderr = %q, want empty", tc.name, stderr.String())
			}
			for _, want := range tc.want {
				if !strings.Contains(stdout.String(), want) {
					t.Fatalf("%s stdout %q missing %q", tc.name, stdout.String(), want)
				}
			}
		})
	}

	runner, stdout, _ := newReconTestRunner(t)
	if err := CmdDate.Run(runner); err != nil {
		t.Fatalf("date returned error: %v", err)
	}
	if got := stdout.String(); got != "Thu Jan  1 00:00:00 UTC 1970\n" {
		t.Fatalf("date stdout = %q, want exact epoch string", got)
	}
}

func TestCmdReconNetworkCommands(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cmd  Command
		args []string
		want []string
	}{
		{name: "netstat", cmd: CmdNetstat, args: []string{"-ant"}, want: []string{"Proto", "LISTEN", "0.0.0.0:22"}},
		{name: "ss", cmd: CmdSs, args: []string{"-tulpn"}, want: []string{"Netid", "LISTEN", "sshd"}},
		{name: "ip", cmd: CmdIp, args: []string{"addr"}, want: []string{"eth0", "10.0.0.10/24", "127.0.0.1"}},
		{name: "ifconfig", cmd: CmdIfconfig, want: []string{"eth0", "inet 10.0.0.10", "lo:"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner, stdout, stderr := newReconTestRunner(t)
			if err := tc.cmd.Run(runner, tc.args...); err != nil {
				t.Fatalf("%s returned error: %v", tc.name, err)
			}
			if stderr.String() != "" {
				t.Fatalf("%s stderr = %q, want empty", tc.name, stderr.String())
			}
			for _, want := range tc.want {
				if !strings.Contains(stdout.String(), want) {
					t.Fatalf("%s stdout %q missing %q", tc.name, stdout.String(), want)
				}
			}
		})
	}
}

func TestCmdWhichOnlyResolvesKnownBuiltinsAndFakeSh(t *testing.T) {
	t.Parallel()

	runner, stdout, stderr := newReconTestRunner(t)
	if err := CmdWhich.Run(runner, "sh", "cat", "nosuchcmd"); err == nil {
		t.Fatal("which unknown command returned nil error, want non-nil")
	}
	out := stdout.String()
	if !strings.Contains(out, "/bin/sh\n") || !strings.Contains(out, "/bin/cat\n") {
		t.Fatalf("which stdout = %q, want fake paths for sh and cat", out)
	}
	if strings.Contains(out, "nosuchcmd") {
		t.Fatalf("which stdout = %q, must not resolve unknown command", out)
	}
	if got := stderr.String(); !strings.Contains(got, "which: no nosuchcmd in (/bin:/usr/bin)") {
		t.Fatalf("which stderr = %q, want shell-like not-found", got)
	}
}

func TestCmdFileCommandsUseAllowlistedFakeContent(t *testing.T) {
	t.Parallel()

	passwd, ok := fakeFileContent("/etc/passwd")
	if !ok {
		t.Fatal("/etc/passwd missing from fakeFileContent")
	}

	cases := []struct {
		name string
		cmd  Command
		want []string
	}{
		{name: "cat", cmd: CmdCat, want: []string{passwd}},
		{name: "head", cmd: CmdHead, want: []string{"root:x:0:0:root:/root:/bin/sh\n"}},
		{name: "tail", cmd: CmdTail, want: []string{"root:x:0:0:root:/root:/bin/sh\n"}},
		{name: "wc", cmd: CmdWc, want: []string{"1 1 30 /etc/passwd\n"}},
		{name: "stat", cmd: CmdStat, want: []string{"File: /etc/passwd", "Size: 30"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner, stdout, stderr := newReconTestRunner(t)
			if err := tc.cmd.Run(runner, "/etc/passwd"); err != nil {
				t.Fatalf("%s /etc/passwd returned error: %v", tc.name, err)
			}
			if stderr.String() != "" {
				t.Fatalf("%s stderr = %q, want empty", tc.name, stderr.String())
			}
			for _, want := range tc.want {
				if !strings.Contains(stdout.String(), want) {
					t.Fatalf("%s stdout %q missing %q", tc.name, stdout.String(), want)
				}
			}
		})
	}
}

func TestCmdHeadTailLineCountOptions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cmd  Command
		args []string
		want string
	}{
		{name: "head_space_n", cmd: CmdHead, args: []string{"-n", "1", "/etc/passwd"}, want: "root:x:0:0:root:/root:/bin/sh\n"},
		{name: "head_joined_n", cmd: CmdHead, args: []string{"-n1", "/etc/passwd"}, want: "root:x:0:0:root:/root:/bin/sh\n"},
		{name: "head_compact_n", cmd: CmdHead, args: []string{"-1", "/etc/passwd"}, want: "root:x:0:0:root:/root:/bin/sh\n"},
		{name: "tail_space_n", cmd: CmdTail, args: []string{"-n", "1", "/etc/passwd"}, want: "root:x:0:0:root:/root:/bin/sh\n"},
		{name: "tail_joined_n", cmd: CmdTail, args: []string{"-n1", "/etc/passwd"}, want: "root:x:0:0:root:/root:/bin/sh\n"},
		{name: "tail_compact_n", cmd: CmdTail, args: []string{"-1", "/etc/passwd"}, want: "root:x:0:0:root:/root:/bin/sh\n"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner, stdout, stderr := newReconTestRunner(t)
			if err := tc.cmd.Run(runner, tc.args...); err != nil {
				t.Fatalf("%s returned error: %v", tc.name, err)
			}
			if got := stdout.String(); got != tc.want {
				t.Fatalf("%s stdout = %q, want %q", tc.name, got, tc.want)
			}
			if stderr.String() != "" {
				t.Fatalf("%s stderr = %q, want empty", tc.name, stderr.String())
			}
		})
	}
}

func TestCmdHeadTailLineCountOptionErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cmd  Command
		args []string
		want string
	}{
		{name: "head_zero", cmd: CmdHead, args: []string{"-n", "0", "/etc/passwd"}, want: "head: line count out of range 0"},
		{name: "head_too_large", cmd: CmdHead, args: []string{"-n", "101", "/etc/passwd"}, want: "head: line count out of range 101"},
		{name: "head_not_number", cmd: CmdHead, args: []string{"-n", "abc", "/etc/passwd"}, want: "head: invalid line count abc"},
		{name: "head_missing_count", cmd: CmdHead, args: []string{"-n"}, want: "head: option requires an argument -- n"},
		{name: "head_missing_file", cmd: CmdHead, args: []string{"-n", "1"}, want: "head: missing file operand"},
		{name: "head_multiple_files", cmd: CmdHead, args: []string{"-n", "1", "/etc/passwd", "/etc/hostname"}, want: "head: too many arguments"},
		{name: "tail_zero", cmd: CmdTail, args: []string{"-n", "0", "/etc/passwd"}, want: "tail: line count out of range 0"},
		{name: "tail_too_large", cmd: CmdTail, args: []string{"-n", "101", "/etc/passwd"}, want: "tail: line count out of range 101"},
		{name: "tail_not_number", cmd: CmdTail, args: []string{"-n", "abc", "/etc/passwd"}, want: "tail: invalid line count abc"},
		{name: "tail_missing_count", cmd: CmdTail, args: []string{"-n"}, want: "tail: option requires an argument -- n"},
		{name: "tail_missing_file", cmd: CmdTail, args: []string{"-n", "1"}, want: "tail: missing file operand"},
		{name: "tail_multiple_files", cmd: CmdTail, args: []string{"-n", "1", "/etc/passwd", "/etc/hostname"}, want: "tail: too many arguments"},
		{name: "tail_follow", cmd: CmdTail, args: []string{"-f", "/etc/passwd"}, want: "tail: unsupported option -f"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner, _, stderr := newReconTestRunner(t)
			if err := tc.cmd.Run(runner, tc.args...); err == nil {
				t.Fatalf("%s returned nil error, want non-nil", tc.name)
			} else if err.Error() != tc.want {
				t.Fatalf("%s error = %q, want %q", tc.name, err.Error(), tc.want)
			}
			if got := strings.TrimSpace(stderr.String()); got != tc.want {
				t.Fatalf("%s stderr = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

func TestCmdFileCommandsTreatRootFSPlaceholdersAsEmpty(t *testing.T) {
	t.Parallel()

	runner, stdout, stderr := newReconTestRunner(t)
	if err := CmdCat.Run(runner, "/var/placeholder"); err != nil {
		t.Fatalf("cat placeholder returned error: %v", err)
	}
	if stdout.String() != "" || stderr.String() != "" {
		t.Fatalf("cat placeholder stdout=%q stderr=%q, want both empty", stdout.String(), stderr.String())
	}

	runner, stdout, stderr = newReconTestRunner(t)
	if err := CmdWc.Run(runner, "/var/placeholder"); err != nil {
		t.Fatalf("wc placeholder returned error: %v", err)
	}
	if got := stdout.String(); got != "0 0 0 /var/placeholder\n" {
		t.Fatalf("wc placeholder stdout = %q, want zero counts", got)
	}
	if stderr.String() != "" {
		t.Fatalf("wc placeholder stderr = %q, want empty", stderr.String())
	}

	runner, stdout, stderr = newReconTestRunner(t)
	if err := CmdStat.Run(runner, "/var/placeholder"); err != nil {
		t.Fatalf("stat placeholder returned error: %v", err)
	}
	if got := stdout.String(); !strings.Contains(got, "Size: 0") {
		t.Fatalf("stat placeholder stdout = %q, want Size: 0", got)
	}
	if stderr.String() != "" {
		t.Fatalf("stat placeholder stderr = %q, want empty", stderr.String())
	}
}

func TestCmdFileCommandsResolveRelativePathsAndRejectMissing(t *testing.T) {
	t.Parallel()

	runner, stdout, stderr := newReconTestRunner(t)
	runner.SetEnv("PWD", "/etc")
	if err := CmdCat.Run(runner, "hostname"); err != nil {
		t.Fatalf("cat relative hostname returned error: %v", err)
	}
	if got := stdout.String(); got != "fakeshell\n" {
		t.Fatalf("cat relative hostname stdout = %q, want fake hostname", got)
	}
	if stderr.String() != "" {
		t.Fatalf("cat relative hostname stderr = %q, want empty", stderr.String())
	}

	runner, _, stderr = newReconTestRunner(t)
	if err := CmdCat.Run(runner, "/etc/shadow"); err == nil {
		t.Fatal("cat missing returned nil error, want non-nil")
	}
	if got := stderr.String(); !strings.Contains(got, "cat: /etc/shadow: No such file or directory") {
		t.Fatalf("cat missing stderr = %q, want no-such-file", got)
	}
}

func TestCmdHistoryAndClearSafeOutput(t *testing.T) {
	t.Parallel()

	runner, stdout, stderr := newReconTestRunner(t)
	if err := CmdHistory.Run(runner); err != nil {
		t.Fatalf("history returned error: %v", err)
	}
	if stdout.String() != "" || stderr.String() != "" {
		t.Fatalf("history stdout=%q stderr=%q, want safe empty output", stdout.String(), stderr.String())
	}

	runner, stdout, stderr = newReconTestRunner(t)
	if err := CmdClear.Run(runner); err != nil {
		t.Fatalf("clear returned error: %v", err)
	}
	if got := stdout.String(); got != "\x1b[H\x1b[2J" {
		t.Fatalf("clear stdout = %q, want ANSI clear", got)
	}
	if stderr.String() != "" {
		t.Fatalf("clear stderr = %q, want empty", stderr.String())
	}
}

func TestCmdReconUnsupportedOptions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cmd  Command
		args []string
		want string
	}{
		{name: "tail_follow", cmd: CmdTail, args: []string{"-f", "/etc/passwd"}, want: "tail: unsupported option -f"},
		{name: "cat_show_all", cmd: CmdCat, args: []string{"-A", "/etc/passwd"}, want: "cat: unsupported option -A"},
		{name: "head_bytes", cmd: CmdHead, args: []string{"-c", "10", "/etc/passwd"}, want: "head: unsupported option -c"},
		{name: "wc_bytes", cmd: CmdWc, args: []string{"-c", "/etc/passwd"}, want: "wc: unsupported option -c"},
		{name: "stat_format", cmd: CmdStat, args: []string{"--format=%s", "/etc/passwd"}, want: "stat: unsupported option --format=%s"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner, _, stderr := newReconTestRunner(t)
			if err := tc.cmd.Run(runner, tc.args...); err == nil {
				t.Fatalf("%s returned nil error, want unsupported option", tc.name)
			} else if err.Error() != tc.want {
				t.Fatalf("%s error = %q, want %q", tc.name, err.Error(), tc.want)
			}
			if got := strings.TrimSpace(stderr.String()); got != tc.want {
				t.Fatalf("%s stderr = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

func TestCmdFileCommandsRejectMultipleFiles(t *testing.T) {
	t.Parallel()

	runner, _, stderr := newReconTestRunner(t)
	if err := CmdCat.Run(runner, "/etc/passwd", "/etc/hostname"); err == nil {
		t.Fatal("cat multiple files returned nil error, want non-nil")
	}
	if got := strings.TrimSpace(stderr.String()); got != "cat: too many arguments" {
		t.Fatalf("cat multiple stderr = %q, want too many arguments", got)
	}
}

func newReconTestRunner(t *testing.T) (*CommandRunner, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	cfg := &fsconf.FakeshellConfig{}
	cfg.EnvConfig.HostName = "fakeshell"
	cfg.FillDefault()
	if err := fsconf.CheckAndFillConfig(cfg); err != nil {
		t.Fatalf("CheckAndFillConfig: %v", err)
	}
	runner := NewCommandRunner(cfg)
	fs := afero.NewMemMapFs()
	for _, dir := range []string{"/etc", "/proc", "/var", "/tmp", "/bin"} {
		if err := fs.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	f, err := fs.Create("/var/placeholder")
	if err != nil {
		t.Fatalf("create placeholder: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close placeholder: %v", err)
	}
	runner.SetRootFS(fs)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	runner.Stdout = stdout
	runner.Stderr = stderr
	return runner, stdout, stderr
}
