package main

import (
	"fmt"
	"strings"
)

type KeyOption struct {
	Type   string
	Option string
}

func (k KeyOption) String() string {
	return fmt.Sprintf("KeyOption[type: %s option: %s]", k.Type, k.Option)
}

func GetKeyOptionPairs(s string) (ps []*KeyOption) {
	ts := strings.Split(s, ",")

	for _, t := range ts {
		p := &KeyOption{}
		if strings.Contains(t, ";") {
			pars := strings.SplitN(t, ";", 2)
			p.Type, p.Option = pars[0], pars[1]
		} else {
			p.Type = t
		}
		ps = append(ps, p)
	}
	return
}
