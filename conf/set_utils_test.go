package conf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStringSet(t *testing.T) {
	ass := assert.New(t)

	// `NewStringSet`, `ss.Equal`
	ss := NewStringSet("a", "b", "c")
	ss2 := NewStringSet("a", "b", "c")
	ass.Equal(ss2, ss)

	// `ss.Equal`, `ss.Add`, `ss.Remove`
	ss3 := NewStringSet("a", "b", "c", "d")
	ass.NotEqual(ss3, ss)
	ss.Add("d")
	ass.NotEqual(ss2, ss)
	ass.Equal(ss3, ss)
	ss.Add("b")
	ass.Equal(ss3, ss)
	ss.Remove("d")
	ass.Equal(ss, ss2)
	ss.Remove("d")
	ass.Equal(ss, ss2)

	// `ss.Contains`
	ass.True(ss.Contains("a"))
	ass.False(ss.Contains("d"))
	ass.False(ss.Contains("e"))

	// `ss.ContainsOne`, `ss.ContainsAll`
	ass.True(ss.ContainsOne("a", "b"))
	ass.True(ss.ContainsOne("a", "e", "f"))
	ass.False(ss.ContainsOne("d", "e", "f"))
	ass.True(ss.ContainsOne())
	ass.True(ss.ContainsAll("a", "b", "c"))
	ass.False(ss.ContainsAll("a", "b", "c", "d"))
	ass.False(ss.ContainsAll("d", "e", "f"))
	ass.True(ss.ContainsAll())

	// `ss.Clone`
	ss4 := ss.Clone()
	ass.Equal(ss4, ss)
	ss4.Add("d")
	ass.NotEqual(ss4, ss)
	ss4.Remove("d")
	ass.Equal(ss4, ss)

	// `ss.Keys`, `ss.Len`
	ass.Equal(ss.Keys(), []string{"a", "b", "c"})
	ass.Equal(ss.Len(), 3)
}
