package cmds

import (
	"io"
	"strings"

	"github.com/hugefiver/fakessh/modules/fakeshell/conf"
	"github.com/hugefiver/fakessh/modules/fakeshell/parser"
	"github.com/puzpuzpuz/xsync/v2"
	"github.com/samber/lo"
	"github.com/spf13/afero"
)

type EnvPair struct {
	Key   string
	Value string
}

type EnvMap struct {
	Envs xsync.MapOf[string, EnvPair]
}

func NewEnvMap(m map[string]string) *EnvMap {
	e := &EnvMap{
		Envs: *xsync.NewMapOfPresized[EnvPair](len(m)),
	}
	for k, v := range m {
		e.Envs.Store(strings.ToUpper(k), EnvPair{
			Key:   k,
			Value: v,
		})
	}
	return e
}

func (e *EnvMap) Get(key string) string {
	if v, ok := e.Envs.Load(strings.ToUpper(key)); ok {
		return v.Value
	}
	return ""
}

type CommandRunner struct {
	C *conf.FakeshellConfig

	Env     *EnvMap
	TempEnv *EnvMap
	RootFS  afero.Fs

	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

func NewCommandRunner(c *conf.FakeshellConfig) *CommandRunner {
	return &CommandRunner{
		C: c,

		Env:    NewEnvMap(c.EnvConfig.Envs),
		RootFS: afero.NewMemMapFs(),
	}
}

func (r *CommandRunner) GetEnv(key string) string {
	key = strings.ToUpper(key)
	if v, ok := r.TempEnv.Envs.Load(key); ok {
		return v.Value
	}

	if v, ok := r.Env.Envs.Load(key); ok {
		return v.Value
	}
	return ""
}

func (r *CommandRunner) SetEnv(key, value string) {
	r.TempEnv.Envs.Store(strings.ToUpper(key), EnvPair{
		Key:   key,
		Value: value,
	})
}

func (r *CommandRunner) UnsetEnv(key string) {
	r.TempEnv.Envs.Delete(strings.ToUpper(key))
}

func (r *CommandRunner) GetEnvs() []EnvPair {
	envs := make(map[string]EnvPair, r.TempEnv.Envs.Size()+r.Env.Envs.Size())

	r.Env.Envs.Range(func(k string, v EnvPair) bool {
		envs[k] = v
		return true
	})
	r.TempEnv.Envs.Range(func(k string, v EnvPair) bool {
		envs[k] = v
		return true
	})
	return lo.MapToSlice(envs, func(k string, v EnvPair) EnvPair {
		return v
	})
}

func (r *CommandRunner) Run(cmdPar *parser.Command, cmdOp Command) error {
	return cmdOp.Run(r, cmdPar.Args...)
}

type Command interface {
	Run(runner *CommandRunner, args ...string) error
}
