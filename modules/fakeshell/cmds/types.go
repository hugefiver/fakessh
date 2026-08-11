package cmds

import (
	"io"
	"strings"
	"sync"

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

// CommandRunner holds the per-session state shared by all built-in commands.
//
// mu guards mutable runner state (RootFS and the PWD temp env). Built-ins that
// inspect or mutate cwd/rootfs must hold mu for the duration of their read- or
// write-back so concurrent commands on the same runner cannot observe a
// half-updated state. The Env/TempEnv maps are backed by xsync and are already
// goroutine-safe, so fine-grained env reads/writes do not need mu.
//
// Dynamic is the per-session metadata-only store backing touch and other
// dynamic commands. It is created in NewCommandRunner and is never shared
// across runners, which is the primary cross-session isolation boundary. The
// store has its own internal mutex, so built-ins do not need to hold the
// runner mu to call Dynamic.Record / Dynamic.Entries; however a built-in that
// needs a consistent snapshot of BOTH RootFS and Dynamic (e.g. ls merging the
// two) must hold the runner mu for the whole read so a concurrent touch cannot
// insert a dynamic entry mid-list.
type CommandRunner struct {
	mu sync.Mutex

	C *conf.FakeshellConfig

	Env     *EnvMap
	TempEnv *EnvMap
	RootFS  afero.Fs

	// Dynamic records per-session metadata for paths the session has touched
	// or otherwise mutated. nil is treated as "no dynamic state"; built-ins
	// that touch it must nil-check first (NewCommandRunner always sets it).
	Dynamic *DynamicStore

	// Logger optionally records bounded session activity. nil means "no
	// logging"; RunLoop nil-checks before emitting events so a runner
	// constructed without a logger never panics. When non-nil it is always a
	// per-session logger (never shared across runners), matching the
	// per-session isolation posture of Dynamic.
	Logger EventLogger

	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

func NewCommandRunner(c *conf.FakeshellConfig) *CommandRunner {
	return &CommandRunner{
		C: c,

		Env:     NewEnvMap(c.EnvConfig.Envs),
		TempEnv: NewEnvMap(nil),
		RootFS:  afero.NewMemMapFs(),
		Dynamic: NewDynamicStore(),
	}
}

// SetRootFS installs a per-session root filesystem on the runner. It is called
// once during shell startup with the afero.Fs produced by LoadRootFS. Passing
// nil is allowed and leaves the runner with a safe empty in-memory filesystem
// so that a nil rootfs can never cause a nil-pointer dereference inside a
// built-in; the shell startup code is still responsible for refusing to run if
// LoadRootFS returned an error (there is no empty-fs fallback at startup).
func (r *CommandRunner) SetRootFS(fs afero.Fs) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if fs == nil {
		fs = afero.NewMemMapFs()
	}
	r.RootFS = fs
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
