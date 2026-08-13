//go:build !no_fakeshell && !plan9
// +build !no_fakeshell,!plan9

package fakeshell

import (
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/hugefiver/fakessh/modules/fakeshell/cmds"
	"github.com/spf13/afero"
)

const (
	MaxGlobMatches       = 64
	MaxSessionEnvEntries = 64
	MaxSessionEnvBytes   = 16 * 1024
)

type savedCommandEnv struct {
	key     string
	hadTemp bool
	value   cmds.EnvPair
}

func expandSimpleCommand(runner *cmds.CommandRunner, cmd simpleCommand, lastStatus int) (simpleCommand, func(), error) {
	if runner == nil {
		return simpleCommand{}, func() {}, fmt.Errorf("fakeshell: missing command runner")
	}
	if cmd.Name == "" {
		if err := executeAssignmentOnly(runner, cmd.EnvAssignments); err != nil {
			return simpleCommand{}, func() {}, err
		}
		return cmd, func() {}, nil
	}

	cleanup := applyCommandEnv(runner, cmd.EnvAssignments)
	expanded := simpleCommand{EnvAssignments: append([]string(nil), cmd.EnvAssignments...)}

	words := []syntaxWordValue{commandNameWord(cmd)}
	for i, arg := range cmd.Args {
		words = append(words, commandArgWord(cmd, i, arg))
	}
	expandedWords, err := expandCommandWords(runner, words, lastStatus)
	if err != nil {
		cleanup()
		return simpleCommand{}, func() {}, err
	}
	if len(expandedWords) > 0 {
		expanded.Name = expandedWords[0]
		expanded.Args = append(expanded.Args, expandedWords[1:]...)
	}

	for _, redir := range cmd.Redirects {
		if redir.Duplicate {
			expanded.Redirects = append(expanded.Redirects, redir)
			continue
		}
		target, err := expandRedirectTarget(runner, redirectTargetWord(redir), lastStatus)
		if err != nil {
			cleanup()
			return simpleCommand{}, func() {}, err
		}
		redir.Target = target
		expanded.Redirects = append(expanded.Redirects, redir)
	}
	if err := validateExpandedSimpleCommandBounds(expanded); err != nil {
		cleanup()
		return simpleCommand{}, func() {}, err
	}

	return expanded, cleanup, nil
}

type expandedWord struct {
	text         string
	globEligible []bool
}

func commandNameWord(cmd simpleCommand) syntaxWordValue {
	if len(cmd.NameWord.segments) != 0 {
		return cmd.NameWord
	}
	return literalUnquotedWord(cmd.Name)
}

func commandArgWord(cmd simpleCommand, index int, arg string) syntaxWordValue {
	if index < len(cmd.ArgWords) && len(cmd.ArgWords[index].segments) != 0 {
		return cmd.ArgWords[index]
	}
	return literalUnquotedWord(arg)
}

func redirectTargetWord(redir redirectSpec) syntaxWordValue {
	if len(redir.TargetWord.segments) != 0 {
		return redir.TargetWord
	}
	return literalUnquotedWord(redir.Target)
}

func literalUnquotedWord(text string) syntaxWordValue {
	return syntaxWordValue{text: text, segments: []wordSegment{{text: text, quote: unquoted}}}
}

func validateExpandedSimpleCommandBounds(cmd simpleCommand) error {
	if len(cmd.Name) > MaxInputTokenBytes {
		return newSyntaxLimitError("expanded command token too long")
	}
	if len(cmd.Args) > MaxInputArgs {
		return newSyntaxLimitError("too many expanded arguments")
	}
	for _, arg := range cmd.Args {
		if len(arg) > MaxInputTokenBytes {
			return newSyntaxLimitError("expanded argument token too long")
		}
	}
	if len(cmd.EnvAssignments) > MaxInputArgs {
		return newSyntaxLimitError("too many environment assignments")
	}
	for _, assignment := range cmd.EnvAssignments {
		key, value, ok := splitEnvAssignment(assignment)
		if !ok {
			return fmt.Errorf("fakeshell: invalid environment assignment")
		}
		if len(key) > MaxInputTokenBytes || len(value) > MaxInputTokenBytes || len(key)+1+len(value) > MaxInputTokenBytes {
			return newSyntaxLimitError("environment token too long")
		}
	}
	return nil
}

func applyCommandEnv(runner *cmds.CommandRunner, assignments []string) func() {
	if runner == nil || len(assignments) == 0 {
		return func() {}
	}

	saved := make([]savedCommandEnv, 0, len(assignments))
	for _, assignment := range assignments {
		key, value, ok := splitEnvAssignment(assignment)
		if !ok {
			continue
		}
		upper := strings.ToUpper(key)
		previous, hadTemp := runner.TempEnv.Envs.Load(upper)
		saved = append(saved, savedCommandEnv{key: key, hadTemp: hadTemp, value: previous})
		runner.SetEnv(key, value)
	}

	return func() {
		for i := len(saved) - 1; i >= 0; i-- {
			entry := saved[i]
			upper := strings.ToUpper(entry.key)
			if entry.hadTemp {
				runner.TempEnv.Envs.Store(upper, entry.value)
			} else {
				runner.UnsetEnv(entry.key)
			}
		}
	}
}

func executeAssignmentOnly(runner *cmds.CommandRunner, assignments []string) error {
	if runner == nil {
		return fmt.Errorf("fakeshell: missing command runner")
	}
	parsed, err := validateAssignmentOnlyEnv(runner, assignments)
	if err != nil {
		return err
	}
	for _, assignment := range parsed {
		runner.SetEnv(assignment.key, assignment.value)
	}
	return nil
}

type envAssignment struct {
	key   string
	value string
}

func validateAssignmentOnlyEnv(runner *cmds.CommandRunner, assignments []string) ([]envAssignment, error) {
	if len(assignments) > MaxInputArgs {
		return nil, newSyntaxLimitError("too many environment assignments")
	}

	parsed := make([]envAssignment, 0, len(assignments))
	newKeys := make(map[string]struct{})
	for _, assignment := range assignments {
		key, value, ok := splitEnvAssignment(assignment)
		if !ok {
			return nil, fmt.Errorf("fakeshell: invalid environment assignment")
		}
		if len(key) > MaxInputTokenBytes || len(value) > MaxInputTokenBytes || len(key)+1+len(value) > MaxInputTokenBytes {
			return nil, newSyntaxLimitError("environment token too long")
		}
		upper := strings.ToUpper(key)
		if _, exists := runner.TempEnv.Envs.Load(upper); !exists {
			newKeys[upper] = struct{}{}
		}
		parsed = append(parsed, envAssignment{key: key, value: value})
	}

	if runner.TempEnv.Envs.Size()+len(newKeys) > MaxSessionEnvEntries {
		return nil, newSyntaxLimitError("too many session environment entries")
	}

	merged := make(map[string]cmds.EnvPair, runner.TempEnv.Envs.Size()+len(parsed))
	runner.TempEnv.Envs.Range(func(key string, value cmds.EnvPair) bool {
		merged[key] = value
		return true
	})
	for _, assignment := range parsed {
		merged[strings.ToUpper(assignment.key)] = cmds.EnvPair{Key: assignment.key, Value: assignment.value}
	}

	total := 0
	for _, env := range merged {
		total += len(env.Key) + len(env.Value)
		if total > MaxSessionEnvBytes {
			return nil, newSyntaxLimitError("session environment too large")
		}
	}

	return parsed, nil
}

func expandCommandWords(runner *cmds.CommandRunner, words []syntaxWordValue, lastStatus int) ([]string, error) {
	expanded := make([]string, 0, len(words))
	for _, word := range words {
		withVars, err := expandWordSegments(runner, word, lastStatus)
		if err != nil {
			return nil, err
		}
		if err := validateExpandedTokenLen(withVars.text); err != nil {
			return nil, err
		}
		matches, err := expandGlobWord(runner, withVars)
		if err != nil {
			return nil, err
		}
		for _, match := range matches {
			if err := validateExpandedTokenLen(match); err != nil {
				return nil, err
			}
		}
		expanded = append(expanded, matches...)
	}
	return expanded, nil
}

func expandRedirectTarget(runner *cmds.CommandRunner, target syntaxWordValue, lastStatus int) (string, error) {
	withVars, err := expandWordSegments(runner, target, lastStatus)
	if err != nil {
		return "", err
	}
	if err := validateExpandedTokenLen(withVars.text); err != nil {
		return "", err
	}
	matches, err := expandGlobWord(runner, withVars)
	if err != nil {
		return "", err
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("fakeshell: ambiguous redirect: %s", target.text)
	}
	if err := validateExpandedTokenLen(matches[0]); err != nil {
		return "", err
	}
	return matches[0], nil
}

// expandWordSegments concatenates quote-aware word segments. Variable and glob
// processing operate only on unquoted segments; quotes and escapes stay literal.
func expandWordSegments(runner *cmds.CommandRunner, word syntaxWordValue, lastStatus int) (expandedWord, error) {
	var result expandedWord
	appendText := func(text string, globEligible bool) {
		result.text += text
		for i := 0; i < len(text); i++ {
			result.globEligible = append(result.globEligible, globEligible && (text[i] == '*' || text[i] == '?'))
		}
	}

	for _, segment := range word.segments {
		switch segment.quote {
		case singleQuoted, escaped:
			appendText(segment.text, false)
		case doubleQuoted:
			appendText(expandVariables(runner, segment.text, lastStatus), false)
		case unquoted:
			appendText(expandVariables(runner, segment.text, lastStatus), true)
		default:
			return expandedWord{}, newSyntaxError("unsupported word quote")
		}
	}
	if err := validateExpandedTokenLen(result.text); err != nil {
		return expandedWord{}, err
	}
	return result, nil
}

func expandVariables(runner *cmds.CommandRunner, word string, lastStatus int) string {
	var b strings.Builder
	for i := 0; i < len(word); i++ {
		if word[i] != '$' {
			b.WriteByte(word[i])
			continue
		}
		if i+1 >= len(word) {
			b.WriteByte('$')
			continue
		}
		next := word[i+1]
		if next == '?' {
			b.WriteString(strconv.Itoa(lastStatus))
			i++
			continue
		}
		if !isVariableNameStart(next) {
			b.WriteByte('$')
			continue
		}
		start := i + 1
		end := start + 1
		for end < len(word) && isVariableNameChar(word[end]) {
			end++
		}
		b.WriteString(runner.GetEnv(word[start:end]))
		i = end - 1
	}
	return b.String()
}

func expandGlobWord(runner *cmds.CommandRunner, word expandedWord) ([]string, error) {
	if !containsEligibleGlobMeta(word, 0, len(word.text)) {
		return []string{word.text}, nil
	}

	dirArg, prefix, pattern, patternStart := splitGlobPattern(word.text)
	if pattern == "" {
		return []string{word.text}, nil
	}
	if containsEligibleGlobMeta(word, 0, patternStart) {
		return nil, newSyntaxError("unsupported glob directory pattern")
	}
	pattern = globPattern(pattern, word.globEligible[patternStart:])

	resolvedDir, err := cmds.ResolvePath(currentPWD(runner), dirArg)
	if err != nil {
		return nil, err
	}

	nameSet := make(map[string]struct{})
	for _, name := range staticChildNames(runner, resolvedDir) {
		if globNameMatches(pattern, name) {
			nameSet[name] = struct{}{}
		}
	}
	for _, name := range dynamicChildNamesForGlob(runner, resolvedDir) {
		if globNameMatches(pattern, name) {
			nameSet[name] = struct{}{}
		}
	}

	if len(nameSet) == 0 {
		return []string{word.text}, nil
	}
	if len(nameSet) > MaxGlobMatches {
		return nil, newSyntaxLimitError("too many glob matches")
	}

	names := make([]string, 0, len(nameSet))
	for name := range nameSet {
		names = append(names, name)
	}
	sort.Strings(names)

	matches := make([]string, 0, len(names))
	for _, name := range names {
		matches = append(matches, prefix+name)
	}
	return matches, nil
}

func applyFakeRedirections(runner *cmds.CommandRunner, cmd simpleCommand, stdout io.Writer, stderr io.Writer) (out io.Writer, errw io.Writer, cleanup func(), err error) {
	if runner == nil {
		return nil, nil, func() {}, fmt.Errorf("fakeshell: missing command runner")
	}
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}

	out = stdout
	errw = stderr
	var records []*fakeRedirectionRecord
	if err := preflightOutputRedirectionTargets(runner, cmd.Redirects); err != nil {
		return nil, nil, func() {}, err
	}

	for _, redir := range cmd.Redirects {
		if redir.Duplicate {
			if redir.FD != 2 || redir.Operator != ">&" || redir.DuplicateFD != 1 {
				return nil, nil, func() {}, fmt.Errorf("fakeshell: unsupported redirection")
			}
			errw = out
			continue
		}

		switch redir.Operator {
		case ">", "2>":
			if redir.FD != 1 && redir.FD != 2 {
				return nil, nil, func() {}, fmt.Errorf("fakeshell: unsupported output descriptor %d", redir.FD)
			}
			resolved, err := validateFakeOutputRedirection(runner, redir.Target)
			if err != nil {
				return nil, nil, func() {}, err
			}
			writer := &boundedCountingDiscardWriter{cap: int64(cmds.MaxCommandOutputBytes)}
			records = append(records, &fakeRedirectionRecord{path: resolved, writer: writer})
			if redir.FD == 1 {
				out = writer
			} else {
				errw = writer
			}
		default:
			return nil, nil, func() {}, fmt.Errorf("fakeshell: unsupported redirection")
		}
	}

	return out, errw, func() {
		for _, record := range records {
			// validateFakeOutputRedirection already checked deterministic Record
			// constraints (non-nil Dynamic, path length, and store capacity), so a
			// failure here would be non-deterministic concurrency or a future store
			// validation change. Cleanup cannot report errors through its signature.
			_, _ = runner.Dynamic.Record(record.path, "file", record.writer.Count(), nil, "")
		}
	}, nil
}

func preflightOutputRedirectionTargets(runner *cmds.CommandRunner, redirects []redirectSpec) error {
	if runner == nil {
		return fmt.Errorf("fakeshell: missing command runner")
	}
	if runner.Dynamic == nil {
		for _, redir := range redirects {
			if redir.Duplicate {
				if redir.FD != 2 || redir.Operator != ">&" || redir.DuplicateFD != 1 {
					return fmt.Errorf("fakeshell: unsupported redirection")
				}
				continue
			}
			if redir.Operator != ">" && redir.Operator != "2>" {
				return fmt.Errorf("fakeshell: unsupported redirection")
			}
			return fmt.Errorf("fakeshell: dynamic store unavailable")
		}
		return nil
	}

	existing := make(map[string]struct{})
	for _, entry := range runner.Dynamic.Entries() {
		existing[entry.Path] = struct{}{}
	}

	newTargets := make(map[string]struct{})
	for _, redir := range redirects {
		if redir.Duplicate {
			if redir.FD != 2 || redir.Operator != ">&" || redir.DuplicateFD != 1 {
				return fmt.Errorf("fakeshell: unsupported redirection")
			}
			continue
		}
		switch redir.Operator {
		case ">", "2>":
			resolved, err := validateFakeOutputRedirection(runner, redir.Target)
			if err != nil {
				return err
			}
			if _, ok := existing[resolved]; !ok {
				newTargets[resolved] = struct{}{}
			}
		default:
			return fmt.Errorf("fakeshell: unsupported redirection")
		}
	}
	if len(existing)+len(newTargets) > cmds.MaxDynamicEntries {
		return fmt.Errorf("fakeshell: dynamic store full")
	}
	return nil
}

type fakeRedirectionRecord struct {
	path   string
	writer *boundedCountingDiscardWriter
}

type boundedCountingDiscardWriter struct {
	count int64
	cap   int64
}

func (w *boundedCountingDiscardWriter) Write(p []byte) (int, error) {
	if w.cap > 0 && w.count < w.cap {
		remaining := w.cap - w.count
		add := int64(len(p))
		if add > remaining {
			add = remaining
		}
		w.count += add
	}
	return len(p), nil
}

func (w *boundedCountingDiscardWriter) Count() int64 {
	return w.count
}

func validateFakeOutputRedirection(runner *cmds.CommandRunner, target string) (string, error) {
	resolved, err := cmds.ResolvePath(currentPWD(runner), target)
	if err != nil {
		return "", err
	}
	if len(resolved) > cmds.MaxDynamicPathLen {
		return "", newSyntaxLimitError("redirection path too long")
	}
	if runner.Dynamic == nil {
		return "", fmt.Errorf("fakeshell: dynamic store unavailable")
	}
	parent := path.Dir(resolved)
	if !fakeDirExists(runner, parent) {
		return "", fmt.Errorf("fakeshell: %s: No such file or directory", target)
	}
	if fakeDirExists(runner, resolved) {
		return "", fmt.Errorf("fakeshell: %s: Is a directory", target)
	}
	entries := runner.Dynamic.Entries()
	if !dynamicEntryExists(entries, resolved) && len(entries) >= cmds.MaxDynamicEntries {
		return "", fmt.Errorf("fakeshell: dynamic store full")
	}
	return resolved, nil
}

func validateExpandedTokenLen(token string) error {
	if len(token) > MaxInputTokenBytes {
		return newSyntaxLimitError("expanded token too long")
	}
	return nil
}

func splitEnvAssignment(assignment string) (string, string, bool) {
	if !isEnvAssignment(assignment) {
		return "", "", false
	}
	parts := strings.SplitN(assignment, "=", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func currentPWD(runner *cmds.CommandRunner) string {
	pwd := runner.GetEnv("PWD")
	if pwd == "" {
		return "/"
	}
	return pwd
}

func splitGlobPattern(word string) (dirArg string, prefix string, pattern string, patternStart int) {
	lastSlash := strings.LastIndexByte(word, '/')
	if lastSlash < 0 {
		return ".", "", word, 0
	}
	pattern = word[lastSlash+1:]
	prefix = word[:lastSlash+1]
	if lastSlash == 0 {
		return "/", prefix, pattern, lastSlash + 1
	}
	return word[:lastSlash], prefix, pattern, lastSlash + 1
}

func containsEligibleGlobMeta(word expandedWord, start, end int) bool {
	for i := start; i < end; i++ {
		if word.globEligible[i] {
			return true
		}
	}
	return false
}

func globPattern(text string, eligible []bool) string {
	var pattern strings.Builder
	for i := 0; i < len(text); i++ {
		if text[i] == '[' || text[i] == ']' || text[i] == '\\' || ((text[i] == '*' || text[i] == '?') && !eligible[i]) {
			pattern.WriteByte('\\')
		}
		pattern.WriteByte(text[i])
	}
	return pattern.String()
}

func globNameMatches(pattern, name string) bool {
	matched, err := path.Match(pattern, name)
	return err == nil && matched
}

func staticChildNames(runner *cmds.CommandRunner, dir string) []string {
	if runner.RootFS == nil {
		return nil
	}
	isDir, err := afero.IsDir(runner.RootFS, dir)
	if err != nil || !isDir {
		return nil
	}
	entries, err := afero.ReadDir(runner.RootFS, dir)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func dynamicChildNamesForGlob(runner *cmds.CommandRunner, dir string) []string {
	if runner.Dynamic == nil {
		return nil
	}
	var names []string
	for _, entry := range runner.Dynamic.Entries() {
		if path.Dir(entry.Path) == dir {
			names = append(names, path.Base(entry.Path))
		}
	}
	return names
}

func fakePathExists(runner *cmds.CommandRunner, resolved string) bool {
	if runner.RootFS != nil {
		exists, err := afero.Exists(runner.RootFS, resolved)
		if err == nil && exists {
			return true
		}
	}
	if runner.Dynamic != nil {
		for _, entry := range runner.Dynamic.Entries() {
			if entry.Path == resolved {
				return true
			}
		}
	}
	return false
}

func fakeDirExists(runner *cmds.CommandRunner, resolved string) bool {
	if resolved == "/" {
		return true
	}
	if runner.RootFS != nil {
		isDir, err := afero.IsDir(runner.RootFS, resolved)
		if err == nil && isDir {
			return true
		}
	}
	if runner.Dynamic != nil {
		for _, entry := range runner.Dynamic.Entries() {
			if entry.Path == resolved && entry.Kind == "dir" {
				return true
			}
		}
	}
	return false
}

func dynamicEntryExists(entries []cmds.DynamicEntry, resolved string) bool {
	for _, entry := range entries {
		if entry.Path == resolved {
			return true
		}
	}
	return false
}

func isTinyFakeAllowlistPath(resolved string) bool {
	switch resolved {
	case "/etc/hostname", "/etc/os-release", "/etc/passwd", "/proc/version", "/proc/uptime":
		return true
	default:
		return false
	}
}

func isVariableNameStart(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_'
}

func isVariableNameChar(c byte) bool {
	return isVariableNameStart(c) || (c >= '0' && c <= '9')
}
