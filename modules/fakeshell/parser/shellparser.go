package parser

import (
	"bytes"
	"fmt"
)

const zero byte = byte(0)

type Command struct {
	Name string
	Args []string

	Opt CommandOpt
}

type CommandOpt struct {
	Envs    []EnvPair
	Outputs []string
}

type EnvPair struct {
	Key   string
	Value string
}

// type PipeChain struct {
// 	Commands []Command
// }

type parseCuror int

const (
	envCur parseCuror = iota
	cmdCur
	argCur
)

func ParseCmd(buf []byte, idx int) (*Command, int, error) {
	parts := [][]byte{}
	b := bytes.NewBuffer(nil)

	quote := zero

	i := idx
loop:
	for ; i < len(buf); i++ {
		c := buf[i]
		switch c {
		case ' ':
			if quote == zero {
				if b.Len() > 0 {
					parts = append(parts, bytes.Clone(b.Bytes()))
					b.Reset()
				}
				continue loop
			}
			fallthrough
		case '"', '\'':
			if quote == zero {
				quote = c
				continue loop
			} else if c == quote {
				quote = zero
				parts = append(parts, bytes.Clone(b.Bytes()))
				b.Reset()
				continue loop
			}
			fallthrough
		case '\n', ';':
			if quote == zero {
				idx = i + 1
				break loop
			}
		case '\\':
			if quote == '"' {
				if i+1 < len(buf) {
					next := buf[i+1]
					switch next {
					case 'n':
						next = '\n'
					case 't':
						next = '\t'
					case 'r':
						next = '\r'
					case 'a':
						next = '\a'
					case 'b':
						next = '\b'
					case 'f':
						next = '\f'
					}
					c = next
					i++
				}
			}
		}
		b.WriteByte(c)
	}
	if quote != zero {
		return nil, idx, fmt.Errorf("unclosed quote")
	}
	idx = i

	if b.Len() > 0 {
		parts = append(parts, bytes.Clone(b.Bytes()))
	}

	curr := envCur
	ret := &Command{}
	fmt.Printf("parts: %s\n", parts)

	for i := 0; i < len(parts); {
		p := parts[i]
		switch curr {
		case envCur:
			if i := bytes.IndexByte(p, '='); i < 0 {
				curr = cmdCur
				continue
			} else {
				ret.Opt.Envs = append(ret.Opt.Envs, EnvPair{
					Key:   string(p[:i]),
					Value: string(p[i+1:]),
				})
			}
		case cmdCur:
			ret.Name = string(p)
			curr = argCur
		case argCur:
			ret.Args = append(ret.Args, string(p))
		}

		i++
	}

	return ret, idx, nil
}
