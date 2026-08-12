//go:build !no_fakeshell && !plan9
// +build !no_fakeshell,!plan9

package fakeshell

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

const (
	MaxSyntaxTokens           = 128
	MaxSyntaxOperators        = 64
	MaxRedirectionsPerCommand = 8
)

var (
	errSyntaxParse = errors.New("syntax parse error")
	errSyntaxLimit = errors.New("syntax limit exceeded")
)

type shellLine struct {
	Pipelines []pipeline
	Operators []string
}

type pipeline struct {
	Parts     []pipelinePart
	Operators []string
}

type pipelinePart struct {
	Command simpleCommand
}

type simpleCommand struct {
	EnvAssignments []string
	Name           string
	NameSingle     bool
	Args           []string
	ArgSingle      []bool
	Redirects      []redirectSpec
}

type redirectSpec struct {
	FD           int
	Operator     string
	Target       string
	TargetSingle bool
	Duplicate    bool
	DuplicateFD  int
}

type syntaxTokenKind int

const (
	syntaxWord syntaxTokenKind = iota
	syntaxAnd
	syntaxOr
	syntaxPipe
	syntaxRedirect
)

type syntaxToken struct {
	kind   syntaxTokenKind
	text   string
	single bool
}

func parseShellLine(segment []byte) (shellLine, error) {
	tokens, err := tokenizeShellSegment(segment)
	if err != nil {
		return shellLine{}, err
	}
	if len(tokens) == 0 {
		return shellLine{}, nil
	}

	var line shellLine
	for pos := 0; pos < len(tokens); {
		part, next, err := parsePipelineTokens(tokens, pos)
		if err != nil {
			return shellLine{}, err
		}
		line.Pipelines = append(line.Pipelines, part)
		pos = next
		if pos >= len(tokens) {
			break
		}
		if tokens[pos].kind != syntaxAnd && tokens[pos].kind != syntaxOr {
			return shellLine{}, newSyntaxError("expected logical operator")
		}
		line.Operators = append(line.Operators, tokens[pos].text)
		pos++
		if pos >= len(tokens) {
			return shellLine{}, newSyntaxError("missing command after logical operator")
		}
	}

	return line, nil
}

func syntaxErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	return "fakeshell: syntax error"
}

func isSyntaxLimitError(err error) bool {
	return errors.Is(err, errSyntaxLimit)
}

func tokenizeShellSegment(segment []byte) ([]syntaxToken, error) {
	input := trimShellSegment(segment)
	var tokens []syntaxToken
	operators := 0

	appendToken := func(tok syntaxToken) error {
		tokens = append(tokens, tok)
		if len(tokens) > MaxSyntaxTokens {
			return newSyntaxLimitError("too many syntax tokens")
		}
		if tok.kind == syntaxAnd || tok.kind == syntaxOr || tok.kind == syntaxPipe {
			operators++
			if operators > MaxSyntaxOperators {
				return newSyntaxLimitError("too many syntax operators")
			}
		}
		return nil
	}

	for i := 0; i < len(input); {
		c := input[i]
		if isShellSpace(c) {
			i++
			continue
		}
		if c == '#' {
			break
		}
		if c == ';' || c == '\n' {
			if onlyShellSpace(input[i+1:]) {
				break
			}
			return nil, newSyntaxError("unexpected command separator")
		}

		switch c {
		case '&':
			if hasPrefixAt(input, i, "&&") {
				if err := appendToken(syntaxToken{kind: syntaxAnd, text: "&&"}); err != nil {
					return nil, err
				}
				i += 2
				continue
			}
			return nil, newSyntaxError("unsupported background operator")
		case '|':
			if hasPrefixAt(input, i, "||") {
				if err := appendToken(syntaxToken{kind: syntaxOr, text: "||"}); err != nil {
					return nil, err
				}
				i += 2
				continue
			}
			if err := appendToken(syntaxToken{kind: syntaxPipe, text: "|"}); err != nil {
				return nil, err
			}
			i++
			continue
		case '<':
			if hasPrefixAt(input, i, "<<") {
				return nil, newSyntaxError("unsupported heredoc")
			}
			if hasPrefixAt(input, i, "<(") {
				return nil, newSyntaxError("unsupported process substitution")
			}
			if err := appendToken(syntaxToken{kind: syntaxRedirect, text: "<"}); err != nil {
				return nil, err
			}
			i++
			continue
		case '>':
			if hasPrefixAt(input, i, ">(") {
				return nil, newSyntaxError("unsupported process substitution")
			}
			text := ">"
			if hasPrefixAt(input, i, ">>") {
				text = ">>"
			}
			if err := appendToken(syntaxToken{kind: syntaxRedirect, text: text}); err != nil {
				return nil, err
			}
			i += len(text)
			continue
		}

		if hasPrefixAt(input, i, "2>&1") && isTokenBoundary(input, i+4) {
			if err := appendToken(syntaxToken{kind: syntaxRedirect, text: "2>&1"}); err != nil {
				return nil, err
			}
			i += 4
			continue
		}
		if hasPrefixAt(input, i, "2>>") {
			if err := appendToken(syntaxToken{kind: syntaxRedirect, text: "2>>"}); err != nil {
				return nil, err
			}
			i += 3
			continue
		}
		if hasPrefixAt(input, i, "2>") {
			if err := appendToken(syntaxToken{kind: syntaxRedirect, text: "2>"}); err != nil {
				return nil, err
			}
			i += 2
			continue
		}
		if isDigit(input[i]) {
			j := i + 1
			for j < len(input) && isDigit(input[j]) {
				j++
			}
			if j < len(input) && (input[j] == '>' || input[j] == '<') {
				return nil, newSyntaxError("unsupported redirection descriptor")
			}
		}

		word, singleQuoted, next, err := scanSyntaxWord(input, i)
		if err != nil {
			return nil, err
		}
		if word == "" {
			return nil, newSyntaxError("empty token")
		}
		if err := validateSyntaxWord(word, singleQuoted); err != nil {
			return nil, err
		}
		if err := appendToken(syntaxToken{kind: syntaxWord, text: word, single: singleQuoted}); err != nil {
			return nil, err
		}
		i = next
	}

	return tokens, nil
}

func parsePipelineTokens(tokens []syntaxToken, start int) (pipeline, int, error) {
	var pipe pipeline
	pos := start
	for {
		if pos >= len(tokens) || tokens[pos].kind == syntaxAnd || tokens[pos].kind == syntaxOr || tokens[pos].kind == syntaxPipe {
			return pipeline{}, 0, newSyntaxError("missing command")
		}
		cmd, next, err := parseSimpleCommandTokens(tokens, pos)
		if err != nil {
			return pipeline{}, 0, err
		}
		pipe.Parts = append(pipe.Parts, pipelinePart{Command: cmd})
		pos = next
		if pos >= len(tokens) || tokens[pos].kind == syntaxAnd || tokens[pos].kind == syntaxOr {
			return pipe, pos, nil
		}
		if tokens[pos].kind != syntaxPipe {
			return pipeline{}, 0, newSyntaxError("unexpected token")
		}
		pipe.Operators = append(pipe.Operators, tokens[pos].text)
		pos++
	}
}

func parseSimpleCommandTokens(tokens []syntaxToken, start int) (simpleCommand, int, error) {
	var cmd simpleCommand
	var words []syntaxToken
	pos := start

	for pos < len(tokens) {
		tok := tokens[pos]
		if tok.kind == syntaxAnd || tok.kind == syntaxOr || tok.kind == syntaxPipe {
			break
		}
		if tok.kind == syntaxRedirect {
			if len(cmd.Redirects) >= MaxRedirectionsPerCommand {
				return simpleCommand{}, 0, newSyntaxLimitError("too many redirections")
			}
			redir, next, err := parseRedirect(tokens, pos)
			if err != nil {
				return simpleCommand{}, 0, err
			}
			cmd.Redirects = append(cmd.Redirects, redir)
			pos = next
			continue
		}
		if tok.kind != syntaxWord {
			return simpleCommand{}, 0, newSyntaxError("unexpected token")
		}
		words = append(words, tok)
		pos++
	}

	for len(words) > 0 && isEnvAssignment(words[0].text) {
		cmd.EnvAssignments = append(cmd.EnvAssignments, words[0].text)
		words = words[1:]
	}
	if len(words) > 0 {
		cmd.Name = words[0].text
		cmd.NameSingle = words[0].single
		for _, word := range words[1:] {
			cmd.Args = append(cmd.Args, word.text)
			cmd.ArgSingle = append(cmd.ArgSingle, word.single)
		}
	}
	if cmd.Name == "" && len(cmd.EnvAssignments) == 0 && len(cmd.Redirects) > 0 {
		return simpleCommand{}, 0, newSyntaxError("redirection without command")
	}

	return cmd, pos, nil
}

func parseRedirect(tokens []syntaxToken, pos int) (redirectSpec, int, error) {
	tok := tokens[pos]
	if tok.text == "2>&1" {
		return redirectSpec{FD: 2, Operator: ">&", Duplicate: true, DuplicateFD: 1}, pos + 1, nil
	}

	redir := redirectSpec{Operator: tok.text}
	switch tok.text {
	case "<":
		redir.FD = 0
	case ">", ">>":
		redir.FD = 1
	case "2>", "2>>":
		redir.FD = 2
	default:
		return redirectSpec{}, 0, newSyntaxError("unsupported redirection")
	}

	if pos+1 >= len(tokens) || tokens[pos+1].kind != syntaxWord {
		return redirectSpec{}, 0, newSyntaxError("missing redirection target")
	}
	redir.Target = tokens[pos+1].text
	redir.TargetSingle = tokens[pos+1].single
	if redir.Target == "" {
		return redirectSpec{}, 0, newSyntaxError("missing redirection target")
	}
	return redir, pos + 2, nil
}

func scanSyntaxWord(input []byte, start int) (string, bool, int, error) {
	var b strings.Builder
	hasSingleQuotedPart := false
	hasNonSingleQuotedPart := false
	for i := start; i < len(input); i++ {
		c := input[i]
		if isShellSpace(c) || c == ';' || c == '\n' || c == '#' || isSyntaxOperatorStart(c) {
			return b.String(), hasSingleQuotedPart && !hasNonSingleQuotedPart, i, nil
		}

		switch c {
		case '\'':
			next := bytes.IndexByte(input[i+1:], '\'')
			if next < 0 {
				return "", false, 0, newSyntaxError("unterminated quote")
			}
			hasSingleQuotedPart = true
			b.Write(input[i+1 : i+1+next])
			i += next + 1
		case '"':
			hasNonSingleQuotedPart = true
			next, err := scanDoubleQuotedWord(input, i+1, &b)
			if err != nil {
				return "", false, 0, err
			}
			i = next
		case '\\':
			hasNonSingleQuotedPart = true
			if i+1 >= len(input) {
				b.WriteByte(c)
				continue
			}
			i++
			b.WriteByte(input[i])
		default:
			hasNonSingleQuotedPart = true
			b.WriteByte(c)
		}
	}
	return b.String(), hasSingleQuotedPart && !hasNonSingleQuotedPart, len(input), nil
}

func scanDoubleQuotedWord(input []byte, start int, b *strings.Builder) (int, error) {
	for i := start; i < len(input); i++ {
		c := input[i]
		if c == '"' {
			return i, nil
		}
		if c == '\\' && i+1 < len(input) {
			i++
			b.WriteByte(input[i])
			continue
		}
		b.WriteByte(c)
	}
	return 0, newSyntaxError("unterminated quote")
}

func validateSyntaxWord(word string, singleQuoted bool) error {
	if singleQuoted {
		return nil
	}
	if strings.Contains(word, "$(") || strings.ContainsRune(word, '`') {
		return newSyntaxError("unsupported command substitution")
	}
	if strings.Contains(word, "<(") || strings.Contains(word, ">(") {
		return newSyntaxError("unsupported process substitution")
	}
	if strings.ContainsAny(word, "(){}") {
		return newSyntaxError("unsupported grouping")
	}
	if strings.ContainsRune(word, '&') {
		return newSyntaxError("unsupported background operator")
	}
	return nil
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func trimShellSegment(segment []byte) []byte {
	trimmed := bytes.TrimSpace(segment)
	for len(trimmed) > 0 {
		last := trimmed[len(trimmed)-1]
		if last != '\n' && last != ';' {
			break
		}
		trimmed = bytes.TrimSpace(trimmed[:len(trimmed)-1])
	}
	return trimmed
}

func isEnvAssignment(word string) bool {
	eq := strings.IndexByte(word, '=')
	if eq <= 0 {
		return false
	}
	for i := 0; i < eq; i++ {
		c := word[i]
		if i == 0 {
			if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_') {
				return false
			}
			continue
		}
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

func isShellSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v'
}

func onlyShellSpace(s []byte) bool {
	for _, c := range s {
		if !isShellSpace(c) {
			return false
		}
	}
	return true
}

func isSyntaxOperatorStart(c byte) bool {
	return c == '&' || c == '|' || c == '<' || c == '>'
}

func isTokenBoundary(input []byte, pos int) bool {
	if pos >= len(input) {
		return true
	}
	c := input[pos]
	return isShellSpace(c) || c == ';' || c == '\n' || c == '#' || isSyntaxOperatorStart(c)
}

func hasPrefixAt(input []byte, pos int, prefix string) bool {
	return len(input) >= pos+len(prefix) && string(input[pos:pos+len(prefix)]) == prefix
}

func newSyntaxError(reason string) error {
	return fmt.Errorf("%w: %s", errSyntaxParse, reason)
}

func newSyntaxLimitError(reason string) error {
	return fmt.Errorf("%w: %w: %s", errSyntaxParse, errSyntaxLimit, reason)
}
