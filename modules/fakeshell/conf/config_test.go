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

func TestCheckAndFillDerivesHomeAfterUserOverride(t *testing.T) {
	t.Parallel()

	c := &EnvConfig{}
	c.FillDefault()
	c.mergeOption("user", "alice")
	if err := c.CheckAndFill(); err != nil {
		t.Fatalf("CheckAndFill() error = %v", err)
	}

	if c.Home != "/home/alice" {
		t.Fatalf("Home = %q, want /home/alice", c.Home)
	}
	if c.Envs["HOME"] != "/home/alice" || c.Envs["PWD"] != "/home/alice" {
		t.Fatalf("HOME/PWD = %q/%q, want /home/alice", c.Envs["HOME"], c.Envs["PWD"])
	}
}

func TestCheckAndFillPreservesExplicitHome(t *testing.T) {
	t.Parallel()

	c := &EnvConfig{}
	c.FillDefault()
	c.mergeOption("user", "alice")
	c.mergeOption("home", "/srv/alice")
	if err := c.CheckAndFill(); err != nil {
		t.Fatalf("CheckAndFill() error = %v", err)
	}

	if c.Home != "/srv/alice" {
		t.Fatalf("Home = %q, want /srv/alice", c.Home)
	}
	if c.Envs["HOME"] != "/srv/alice" || c.Envs["PWD"] != "/srv/alice" {
		t.Fatalf("HOME/PWD = %q/%q, want /srv/alice", c.Envs["HOME"], c.Envs["PWD"])
	}
}
