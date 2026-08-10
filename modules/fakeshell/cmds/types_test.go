package cmds

import (
	"testing"

	fsconf "github.com/hugefiver/fakessh/modules/fakeshell/conf"
)

func TestNewCommandRunnerInitializesTempEnv(t *testing.T) {
	t.Parallel()

	runner := NewCommandRunner(&fsconf.FakeshellConfig{})
	runner.SetEnv("PWD", "/tmp")

	if got := runner.GetEnv("PWD"); got != "/tmp" {
		t.Fatalf("GetEnv(PWD) = %q, want /tmp", got)
	}
}
