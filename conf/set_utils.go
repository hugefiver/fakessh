package conf

const (
	FlagLogFile   = "log"
	FlagLogLevel  = "level"
	FlagLogFormat = "format"
	FlagLogPasswd = "passwd"

	FlagKeyPaths = "key"
	FlagKeyType  = "type"

	FlagBind       = "bind"
	FlagSSHVersion = "version"

	FlagDelay     = "delay"
	FlagDeviation = "devia"

	FlagMaxTry = "try"

	FlagEnableAntiScan  = "a"
	FlagDisableAntiScan = "A"

	FlagSuccessRatio = "r"
	FlagSuccessSeed  = "seed"
)

var Commands = NewStringSet(
	FlagLogFile,
	FlagLogLevel,
	FlagLogFormat,
	FlagLogPasswd,
	FlagKeyPaths,
	FlagKeyType,
	FlagBind,
	FlagSSHVersion,
	FlagDelay,
	FlagDeviation,
	FlagMaxTry,
	FlagEnableAntiScan,
	FlagDisableAntiScan,
	FlagSuccessRatio,
	FlagSuccessSeed,
)

type StringSet map[string]struct{}

func NewStringSet(xs ...string) StringSet {
	s := make(StringSet, len(xs))
	for _, v := range xs {
		s[v] = struct{}{}
	}
	return s
}

func (s StringSet) Add(str string) {
	s[str] = struct{}{}
}

func (s StringSet) Remove(str string) {
	delete(s, str)
}

func (s StringSet) Contains(x string) bool {
	_, ok := s[x]
	return ok
}

func (s StringSet) ContainsOne(xs ...string) bool {
	if len(xs) == 0 {
		return true
	}
	for _, x := range xs {
		if s.Contains(x) {
			return true
		}
	}
	return false
}

func (s StringSet) ContainsAll(xs ...string) bool {
	for _, x := range xs {
		if !s.Contains(x) {
			return false
		}
	}
	return true
}

func (s StringSet) Equals(other StringSet) bool {
	if len(s) != len(other) {
		return false
	} else if len(s) == 0 {
		return true
	}
	return s.ContainsAll(other.Keys()...)
}

func (s StringSet) ForEach(fn func(string) error) error {
	for v := range s {
		if err := fn(v); err != nil {
			return err
		}
	}
	return nil
}

func (s StringSet) Len() int {
	return len(s)
}

func (s StringSet) Keys() []string {
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	return keys
}

func (s StringSet) Clone() StringSet {
	return NewStringSet(s.Keys()...)
}
