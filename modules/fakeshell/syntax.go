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
	NameWord       syntaxWordValue
	Args           []string
	ArgWords       []syntaxWordValue
	Redirects      []redirectSpec
}

type redirectSpec struct {
	FD          int
	Operator    string
	Target      string
	TargetWord  syntaxWordValue
	Duplicate   bool
	DuplicateFD int
}

type wordQuote uint8

const (
	unquoted wordQuote = iota
	singleQuoted
	doubleQuoted
	escaped
)

type wordSegment struct {
	text  string
	quote wordQuote
}

type syntaxWordValue struct {
	text     string
	segments []wordSegment
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
	kind syntaxTokenKind
	text string
	word syntaxWordValue
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
			return nil, newSyntaxError("unsupported redirection")
		case '>':
			if hasPrefixAt(input, i, ">(") {
				return nil, newSyntaxError("unsupported process substitution")
			}
			if hasPrefixAt(input, i, ">>") {
				return nil, newSyntaxError("unsupported redirection")
			}
			if err := appendToken(syntaxToken{kind: syntaxRedirect, text: ">"}); err != nil {
				return nil, err
			}
			i++
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
			return nil, newSyntaxError("unsupported redirection")
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

		word, next, err := scanSyntaxWord(input, i)
		if err != nil {
			return nil, err
		}
		if err := validateSyntaxWord(word); err != nil {
			return nil, err
		}
		if err := validateLiteralEnvAssignment(word); err != nil {
			return nil, err
		}
		if err := appendToken(syntaxToken{kind: syntaxWord, text: word.text, word: word}); err != nil {
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
		cmd.NameWord = words[0].word
		for _, word := range words[1:] {
			cmd.Args = append(cmd.Args, word.text)
			cmd.ArgWords = append(cmd.ArgWords, word.word)
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
	case ">":
		redir.FD = 1
	case "2>":
		redir.FD = 2
	default:
		return redirectSpec{}, 0, newSyntaxError("unsupported redirection")
	}

	if pos+1 >= len(tokens) || tokens[pos+1].kind != syntaxWord {
		return redirectSpec{}, 0, newSyntaxError("missing redirection target")
	}
	redir.Target = tokens[pos+1].text
	redir.TargetWord = tokens[pos+1].word
	if redir.Target == "" {
		return redirectSpec{}, 0, newSyntaxError("missing redirection target")
	}
	return redir, pos + 2, nil
}

func scanSyntaxWord(input []byte, start int) (syntaxWordValue, int, error) {
	var word syntaxWordValue
	appendSegment := func(text string, quote wordQuote) {
		if len(word.segments) > 0 && word.segments[len(word.segments)-1].quote == quote {
			word.segments[len(word.segments)-1].text += text
		} else {
			word.segments = append(word.segments, wordSegment{text: text, quote: quote})
		}
		word.text += text
	}

	for i := start; i < len(input); i++ {
		c := input[i]
		if isShellSpace(c) || c == ';' || c == '\n' || isSyntaxOperatorStart(c) {
			return word, i, nil
		}

		switch c {
		case '\'':
			next := bytes.IndexByte(input[i+1:], '\'')
			if next < 0 {
				return syntaxWordValue{}, 0, newSyntaxError("unterminated quote")
			}
			appendSegment(string(input[i+1:i+1+next]), singleQuoted)
			i += next + 1
		case '"':
			for i++; i < len(input); i++ {
				if input[i] == '"' {
					break
				}
				if input[i] == '\\' && i+1 < len(input) {
					i++
					appendSegment(string(input[i]), escaped)
					continue
				}
				appendSegment(string(input[i]), doubleQuoted)
			}
			if i >= len(input) {
				return syntaxWordValue{}, 0, newSyntaxError("unterminated quote")
			}
		case '\\':
			if i+1 >= len(input) {
				appendSegment(string(c), escaped)
				continue
			}
			i++
			appendSegment(string(input[i]), escaped)
		default:
			appendSegment(string(c), unquoted)
		}
	}
	return word, len(input), nil
}

// scanSyntaxWord preserves quote context for every segment. An unquoted
// backslash makes its next byte literal; unescaped mid-word # remains literal.
// validateSyntaxWord checks only unquoted and double-quoted segments. Single
// quotes and backslash escapes make their contents literal in this parser.
func validateSyntaxWord(word syntaxWordValue) error {
	for _, segment := range word.segments {
		if segment.quote == singleQuoted || segment.quote == escaped {
			continue
		}
		if strings.Contains(segment.text, "$(") || strings.ContainsRune(segment.text, '`') {
			return newSyntaxError("unsupported command substitution")
		}
		if strings.Contains(segment.text, "<(") || strings.Contains(segment.text, ">(") {
			return newSyntaxError("unsupported process substitution")
		}
		if strings.ContainsAny(segment.text, "(){}") {
			return newSyntaxError("unsupported grouping")
		}
		if strings.ContainsRune(segment.text, '&') {
			return newSyntaxError("unsupported background operator")
		}
	}
	for _, segment := range word.segments {
		if segment.text != "" {
			if segment.quote == unquoted && segment.text[0] == '~' {
				return newSyntaxError("unsupported tilde expansion")
			}
			break
		}
	}
	return nil
}

func validateLiteralEnvAssignment(word syntaxWordValue) error {
	if !isEnvAssignment(word.text) {
		return nil
	}
	for _, segment := range word.segments {
		if segment.quote != unquoted {
			return newSyntaxError("unsupported environment assignment")
		}
	}
	value := word.text[strings.IndexByte(word.text, '=')+1:]
	if strings.ContainsAny(value, "$*?~") {
		return newSyntaxError("unsupported environment assignment")
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
	return isShellSpace(c) || c == ';' || c == '\n' || isSyntaxOperatorStart(c)
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
