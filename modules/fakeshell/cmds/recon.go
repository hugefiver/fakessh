package cmds

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/afero"
)

// Read-only recon command instances. These commands are deterministic fake
// simulations only: they never execute host binaries, inspect host state, open
// network sockets, or read attacker-provided file contents.
var (
	CmdId       = FuncCmd(id)
	CmdGroups   = FuncCmd(groups)
	CmdWho      = FuncCmd(who)
	CmdW        = FuncCmd(w)
	CmdLast     = FuncCmd(last)
	CmdUptime   = FuncCmd(uptime)
	CmdDate     = FuncCmd(date)
	CmdDf       = FuncCmd(df)
	CmdFree     = FuncCmd(free)
	CmdPs       = FuncCmd(ps)
	CmdNetstat  = FuncCmd(netstat)
	CmdSs       = FuncCmd(ss)
	CmdIp       = FuncCmd(ip)
	CmdIfconfig = FuncCmd(ifconfigCmd)
	CmdWhich    = FuncCmd(which)
	CmdStat     = FuncCmd(stat)
	CmdWc       = FuncCmd(wc)
	CmdHead     = FuncCmd(head)
	CmdTail     = FuncCmd(tail)
	CmdCat      = FuncCmd(cat)
	CmdHistory  = FuncCmd(history)
	CmdClear    = FuncCmd(clear)
)

func id(r *CommandRunner, args ...string) error {
	if err := rejectOptions(r, "id", args); err != nil {
		return err
	}
	user := reconUser(r)
	uid, gid := "1000", "1000"
	if user == "root" {
		uid, gid = "0", "0"
	}
	return writeBounded(r.Stdout, fmt.Sprintf("uid=%s(%s) gid=%s(%s) groups=%s(%s)\n", uid, user, gid, user, gid, user))
}

func groups(r *CommandRunner, args ...string) error {
	if err := rejectOptions(r, "groups", args); err != nil {
		return err
	}
	return writeBounded(r.Stdout, reconUser(r)+"\n")
}

func who(r *CommandRunner, args ...string) error {
	if err := rejectOptions(r, "who", args); err != nil {
		return err
	}
	return writeBounded(r.Stdout, fmt.Sprintf("%s     pts/0        1970-01-01 00:00 (10.0.0.1)\n", reconUser(r)))
}

func w(r *CommandRunner, args ...string) error {
	if err := rejectOptions(r, "w", args); err != nil {
		return err
	}
	out := " 00:00:00 up 3:25,  1 user,  load average: 0.00, 0.01, 0.05\n" +
		"USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n" +
		fmt.Sprintf("%-8s pts/0    10.0.0.1         00:00    0.00s  0.00s  0.00s -sh\n", reconUser(r))
	return writeBounded(r.Stdout, out)
}

func last(r *CommandRunner, args ...string) error {
	if err := rejectOptions(r, "last", args); err != nil {
		return err
	}
	out := fmt.Sprintf("%-8s pts/0        10.0.0.1         Thu Jan  1 00:00   still logged in\n", reconUser(r)) +
		"reboot   system boot  6.1.0-fakeshell Thu Jan  1 00:00   still running\n"
	return writeBounded(r.Stdout, out)
}

func uptime(r *CommandRunner, args ...string) error {
	if err := rejectOptions(r, "uptime", args); err != nil {
		return err
	}
	return writeBounded(r.Stdout, " 00:00:00 up 3:25,  1 user,  load average: 0.00, 0.01, 0.05\n")
}

func date(r *CommandRunner, args ...string) error {
	if len(args) > 0 {
		return rejectUnsupportedOption(r, "date", args[0])
	}
	return writeBounded(r.Stdout, "Thu Jan  1 00:00:00 UTC 1970\n")
}

func df(r *CommandRunner, args ...string) error {
	if err := rejectOptionsExcept(r, "df", args, map[string]bool{"-h": true, "-k": true}); err != nil {
		return err
	}
	out := "Filesystem      Size  Used Avail Use% Mounted on\n" +
		"fakeshellfs      16G  1.2G   15G   8% /\n" +
		"tmpfs            64M     0   64M   0% /tmp\n"
	return writeBounded(r.Stdout, out)
}

func free(r *CommandRunner, args ...string) error {
	if err := rejectOptionsExcept(r, "free", args, map[string]bool{"-h": true, "-k": true, "-m": true, "-g": true}); err != nil {
		return err
	}
	out := "              total        used        free      shared  buff/cache   available\n" +
		"Mem:           2048         256        1536           0         256        1792\n" +
		"Swap:             0           0           0\n"
	return writeBounded(r.Stdout, out)
}

func ps(r *CommandRunner, args ...string) error {
	if err := rejectOptionsExcept(r, "ps", args, map[string]bool{"-ef": true, "-aux": true}); err != nil {
		return err
	}
	out := "  PID TTY          TIME CMD\n" +
		"    1 ?        00:00:00 init\n" +
		"  101 pts/0    00:00:00 sh\n" +
		"  128 pts/0    00:00:00 ps\n"
	return writeBounded(r.Stdout, out)
}

func netstat(r *CommandRunner, args ...string) error {
	if err := rejectShortOptions(r, "netstat", args, "antulp"); err != nil {
		return err
	}
	out := "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n" +
		"tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      101/sshd\n"
	return writeBounded(r.Stdout, out)
}

func ss(r *CommandRunner, args ...string) error {
	if err := rejectShortOptions(r, "ss", args, "antulp"); err != nil {
		return err
	}
	out := "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n" +
		"tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*     users:(\"sshd\",pid=101,fd=3)\n"
	return writeBounded(r.Stdout, out)
}

func ip(r *CommandRunner, args ...string) error {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") && arg != "-" {
			return rejectUnsupportedOption(r, "ip", arg)
		}
	}
	out := "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default\n" +
		"    inet 127.0.0.1/8 scope host lo\n" +
		"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default\n" +
		"    inet 10.0.0.10/24 brd 10.0.0.255 scope global eth0\n"
	return writeBounded(r.Stdout, out)
}

func ifconfigCmd(r *CommandRunner, args ...string) error {
	if err := rejectOptions(r, "ifconfig", args); err != nil {
		return err
	}
	out := "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n" +
		"        inet 10.0.0.10  netmask 255.255.255.0  broadcast 10.0.0.255\n" +
		"lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n" +
		"        inet 127.0.0.1  netmask 255.0.0.0\n"
	return writeBounded(r.Stdout, out)
}

func which(r *CommandRunner, args ...string) error {
	if err := rejectOptions(r, "which", args); err != nil {
		return err
	}
	if len(args) == 0 {
		fmt.Fprintln(r.Stderr, "which: missing command")
		return errors.New("which: missing command")
	}

	var out strings.Builder
	var missing []string
	for _, name := range args {
		if resolved, ok := knownReconCommandPaths()[name]; ok {
			out.WriteString(resolved)
			out.WriteByte('\n')
			continue
		}
		missing = append(missing, name)
		fmt.Fprintf(r.Stderr, "which: no %s in (/bin:/usr/bin)\n", clipErrorToken(name))
	}
	if err := writeBounded(r.Stdout, out.String()); err != nil {
		return err
	}
	if len(missing) > 0 {
		return fmt.Errorf("which: %s not found", clipErrorToken(missing[0]))
	}
	return nil
}

func stat(r *CommandRunner, args ...string) error {
	f, err := resolveSingleFakeFile(r, "stat", args)
	if err != nil {
		return err
	}
	out := fmt.Sprintf("  File: %s\n  Size: %d\tBlocks: 0\tIO Block: 4096   regular file\nAccess: (0644/-rw-r--r--)\n", f.path, len(f.content))
	return writeBounded(r.Stdout, out)
}

func wc(r *CommandRunner, args ...string) error {
	f, err := resolveSingleFakeFile(r, "wc", args)
	if err != nil {
		return err
	}
	out := fmt.Sprintf("%d %d %d %s\n", strings.Count(f.content, "\n"), len(strings.Fields(f.content)), len(f.content), f.path)
	return writeBounded(r.Stdout, out)
}

func head(r *CommandRunner, args ...string) error {
	n, fileArgs, err := parseHeadTailArgs(r, "head", args)
	if err != nil {
		return err
	}
	f, err := resolveSingleFakeFile(r, "head", fileArgs)
	if err != nil {
		return err
	}
	return writeBounded(r.Stdout, firstLines(f.content, n))
}

func tail(r *CommandRunner, args ...string) error {
	n, fileArgs, err := parseHeadTailArgs(r, "tail", args)
	if err != nil {
		return err
	}
	f, err := resolveSingleFakeFile(r, "tail", fileArgs)
	if err != nil {
		return err
	}
	return writeBounded(r.Stdout, lastLines(f.content, n))
}

func cat(r *CommandRunner, args ...string) error {
	f, err := resolveSingleFakeFile(r, "cat", args)
	if err != nil {
		return err
	}
	return writeBounded(r.Stdout, f.content)
}

func history(r *CommandRunner, args ...string) error {
	if err := rejectOptions(r, "history", args); err != nil {
		return err
	}
	return writeBounded(r.Stdout, "")
}

func clear(r *CommandRunner, args ...string) error {
	if err := rejectOptions(r, "clear", args); err != nil {
		return err
	}
	return writeBounded(r.Stdout, "\x1b[H\x1b[2J")
}

func reconUser(r *CommandRunner) string {
	if r == nil {
		return "root"
	}
	if user := r.GetEnv("USER"); user != "" {
		return user
	}
	if user := r.GetEnv("LOGNAME"); user != "" {
		return user
	}
	if r.C != nil && r.C.EnvConfig.User != "" {
		return r.C.EnvConfig.User
	}
	return "root"
}

func rejectOptions(r *CommandRunner, cmd string, args []string) error {
	return rejectOptionsExcept(r, cmd, args, nil)
}

func rejectOptionsExcept(r *CommandRunner, cmd string, args []string, allowed map[string]bool) error {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") && arg != "-" && !allowed[arg] {
			return rejectUnsupportedOption(r, cmd, arg)
		}
	}
	return nil
}

func rejectShortOptions(r *CommandRunner, cmd string, args []string, allowedLetters string) error {
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			continue
		}
		if strings.HasPrefix(arg, "--") {
			return rejectUnsupportedOption(r, cmd, arg)
		}
		for _, ch := range strings.TrimPrefix(arg, "-") {
			if !strings.ContainsRune(allowedLetters, ch) {
				return rejectUnsupportedOption(r, cmd, arg)
			}
		}
	}
	return nil
}

func rejectUnsupportedOption(r *CommandRunner, cmd, opt string) error {
	err := unsupportedOption(cmd, opt)
	fmt.Fprintln(r.Stderr, err.Error())
	return err
}

type reconFile struct {
	path    string
	content string
}

func parseHeadTailArgs(r *CommandRunner, cmd string, args []string) (int, []string, error) {
	const (
		defaultLineCount = 10
		maxLineCount     = 100
	)

	n := defaultLineCount
	fileArgs := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-n" {
			if i+1 >= len(args) {
				return 0, nil, missingLineCount(r, cmd)
			}
			count, err := parseLineCount(cmd, args[i+1], maxLineCount)
			if err != nil {
				fmt.Fprintln(r.Stderr, err.Error())
				return 0, nil, err
			}
			n = count
			i++
			continue
		}

		if strings.HasPrefix(arg, "-n") && len(arg) > len("-n") {
			count, err := parseLineCount(cmd, strings.TrimPrefix(arg, "-n"), maxLineCount)
			if err != nil {
				fmt.Fprintln(r.Stderr, err.Error())
				return 0, nil, err
			}
			n = count
			continue
		}

		if strings.HasPrefix(arg, "-") && arg != "-" {
			if count, ok, err := parseCompactLineCount(cmd, arg, maxLineCount); ok {
				if err != nil {
					fmt.Fprintln(r.Stderr, err.Error())
					return 0, nil, err
				}
				n = count
				continue
			}
			return 0, nil, rejectUnsupportedOption(r, cmd, arg)
		}

		fileArgs = append(fileArgs, arg)
	}

	return n, fileArgs, nil
}

func missingLineCount(r *CommandRunner, cmd string) error {
	err := fmt.Errorf("%s: option requires an argument -- n", cmd)
	fmt.Fprintln(r.Stderr, err.Error())
	return err
}

func parseCompactLineCount(cmd, arg string, max int) (int, bool, error) {
	if len(arg) <= 1 {
		return 0, false, nil
	}
	for _, ch := range arg[1:] {
		if ch < '0' || ch > '9' {
			return 0, false, nil
		}
	}
	n, err := parseLineCount(cmd, arg[1:], max)
	return n, true, err
}

func parseLineCount(cmd, raw string, max int) (int, error) {
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid line count %s", cmd, clipErrorToken(raw))
	}
	if n < 1 || n > max {
		return 0, fmt.Errorf("%s: line count out of range %s", cmd, clipErrorToken(raw))
	}
	return n, nil
}

func resolveSingleFakeFile(r *CommandRunner, cmd string, args []string) (reconFile, error) {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") && arg != "-" {
			return reconFile{}, rejectUnsupportedOption(r, cmd, arg)
		}
	}
	if len(args) == 0 {
		fmt.Fprintf(r.Stderr, "%s: missing file operand\n", cmd)
		return reconFile{}, fmt.Errorf("%s: missing file operand", cmd)
	}
	if len(args) > 1 {
		fmt.Fprintf(r.Stderr, "%s: too many arguments\n", cmd)
		return reconFile{}, fmt.Errorf("%s: too many arguments", cmd)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	cwd := r.GetEnv("PWD")
	if cwd == "" {
		cwd = "/"
	}
	resolved, err := ResolvePath(cwd, args[0])
	if err != nil {
		fmt.Fprintf(r.Stderr, "%s: %s\n", cmd, err.Error())
		return reconFile{}, err
	}

	if content, ok := fakeFileContent(resolved); ok {
		return reconFile{path: resolved, content: content}, nil
	}

	if exists, err := afero.Exists(r.RootFS, resolved); err != nil {
		fmt.Fprintf(r.Stderr, "%s: %s\n", cmd, err.Error())
		return reconFile{}, err
	} else if exists {
		info, err := r.RootFS.Stat(resolved)
		if err != nil {
			fmt.Fprintf(r.Stderr, "%s: %s\n", cmd, err.Error())
			return reconFile{}, err
		}
		if info.IsDir() {
			fmt.Fprintf(r.Stderr, "%s: %s: Is a directory\n", cmd, resolved)
			return reconFile{}, fmt.Errorf("%s: %s: is a directory", cmd, resolved)
		}
		// RootFS regular files are placeholders. Never read their bodies.
		return reconFile{path: resolved, content: ""}, nil
	}

	if de, ok := lookupDynamicPath(r, resolved); ok {
		switch de.Kind {
		case "file":
			return reconFile{path: resolved, content: ""}, nil
		case "dir":
			fmt.Fprintf(r.Stderr, "%s: %s: Is a directory\n", cmd, resolved)
			return reconFile{}, fmt.Errorf("%s: %s: is a directory", cmd, resolved)
		}
	}

	fmt.Fprintf(r.Stderr, "%s: %s: No such file or directory\n", cmd, args[0])
	return reconFile{}, fmt.Errorf("%s: %s: no such file", cmd, args[0])
}

func firstLines(content string, n int) string {
	if n <= 0 || content == "" {
		return ""
	}
	lines := splitContentLines(content)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "")
}

func lastLines(content string, n int) string {
	if n <= 0 || content == "" {
		return ""
	}
	lines := splitContentLines(content)
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "")
}

func splitContentLines(content string) []string {
	lines := strings.SplitAfter(content, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func knownReconCommandPaths() map[string]string {
	names := []string{
		"cat", "clear", "date", "df", "echo", "env", "exit", "free", "groups", "head", "history", "hostname", "id", "ifconfig", "ip", "last", "ls", "netstat", "ps", "pwd", "ss", "stat", "tail", "touch", "uname", "uptime", "w", "wc", "which", "who", "whoami",
	}
	paths := make(map[string]string, len(names)+1)
	for _, name := range names {
		prefix := "/usr/bin/"
		switch name {
		case "cat", "clear", "date", "df", "echo", "hostname", "ls", "pwd", "sh", "touch", "uname":
			prefix = "/bin/"
		}
		paths[name] = prefix + name
	}
	paths["sh"] = "/bin/sh"
	return paths
}
