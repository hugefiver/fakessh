package conf

import "testing"

func TestMergeOptionInitializesEnvMap(t *testing.T) {
	t.Parallel()

	c := &EnvConfig{}
	c.mergeOption("env", "FOO=bar")

	if got := c.Envs["FOO"]; got != "bar" {
		t.Fatalf("expected env option to initialize and set map, got %q", got)
	}
}

func TestCheckAndFillGeneratesDefaultEnv(t *testing.T) {
	t.Parallel()

	c := &EnvConfig{User: "alice", Home: "/home/alice", GenerateEnv: true}
	if err := c.CheckAndFill(); err != nil {
		t.Fatalf("CheckAndFill() error = %v", err)
	}

	if c.Envs["USER"] != "alice" {
		t.Fatalf("USER = %q, want alice", c.Envs["USER"])
	}
	if c.Envs["PWD"] != "/home/alice" {
		t.Fatalf("PWD = %q, want /home/alice", c.Envs["PWD"])
	}
}
