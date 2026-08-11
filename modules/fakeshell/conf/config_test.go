package conf

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

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

// ---------------------------------------------------------------------------
// RootFS config validation
// ---------------------------------------------------------------------------

func TestCheckAndFillConfig_EmptyRootFSIsValid(t *testing.T) {
	t.Parallel()

	c := &FakeshellConfig{RootFS: ""}
	if err := CheckAndFillConfig(c); err != nil {
		t.Fatalf("CheckAndFillConfig(empty rootfs) error = %v", err)
	}
}

func TestCheckAndFillConfig_MissingRootFSErrors(t *testing.T) {
	t.Parallel()

	c := &FakeshellConfig{RootFS: filepath.Join(t.TempDir(), "nope")}
	err := CheckAndFillConfig(c)
	if err == nil {
		t.Fatal("expected error for missing rootfs, got nil")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "rootfs") {
		t.Errorf("error should mention rootfs, got: %v", err)
	}
}

func TestCheckAndFillConfig_ExistingDirectorySucceeds(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	c := &FakeshellConfig{RootFS: dir}
	if err := CheckAndFillConfig(c); err != nil {
		t.Fatalf("CheckAndFillConfig(existing dir) error = %v", err)
	}
}

func TestCheckAndFillConfig_SupportedArchiveSucceeds(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, name := range []string{"root.tar", "root.tar.gz", "root.tgz", "root.zip"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		c := &FakeshellConfig{RootFS: p}
		if err := CheckAndFillConfig(c); err != nil {
			t.Errorf("CheckAndFillConfig(%s) error = %v", name, err)
		}
	}
}

func TestCheckAndFillConfig_UnsupportedExtensionErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := filepath.Join(dir, "root.txt")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	c := &FakeshellConfig{RootFS: p}
	if err := CheckAndFillConfig(c); err == nil {
		t.Fatal("expected error for unsupported extension, got nil")
	}
}

func TestCheckAndFillConfig_ControlCharRootFSErrors(t *testing.T) {
	t.Parallel()

	c := &FakeshellConfig{RootFS: "bad\x00path"}
	if err := CheckAndFillConfig(c); err == nil {
		t.Fatal("expected error for control char in rootfs, got nil")
	}
}

func TestCheckAndFillConfig_NilConfigNoOp(t *testing.T) {
	t.Parallel()

	if err := CheckAndFillConfig(nil); err != nil {
		t.Fatalf("CheckAndFillConfig(nil) error = %v", err)
	}
}

func TestCheckAndFillConfig_SymlinkRootRejected(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "realdir")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("cannot create symlink on windows: %v", err)
		}
		t.Fatalf("symlink: %v", err)
	}

	c := &FakeshellConfig{RootFS: link}
	if err := CheckAndFillConfig(c); err == nil {
		t.Fatal("expected error for symlink rootfs, got nil")
	}
}

func TestIsSupportedArchiveExt(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want bool
	}{
		{"root.tar", true},
		{"root.TAR", true},
		{"root.tar.gz", true},
		{"root.TAR.GZ", true},
		{"root.tgz", true},
		{"root.TGZ", true},
		{"root.zip", true},
		{"root.ZIP", true},
		{"root.txt", false},
		{"root", false},
		{"root.gz", false}, // bare .gz is not a supported archive type
		{"root.iso", false},
	}
	for _, tc := range cases {
		if got := isSupportedArchiveExt(tc.in); got != tc.want {
			t.Errorf("isSupportedArchiveExt(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// LogConfig validation
// ---------------------------------------------------------------------------

// TestLogConfig_DisabledAcceptsAnything verifies that when logging is
// disabled, any compress value and a non-existent path are accepted (the path
// is still defaulted to DefaultLogPath). The path need not exist because no
// logger is created.
func TestLogConfig_DisabledAcceptsAnything(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		compress string
		path     string
	}{
		{"empty compress", "", ""},
		{"unknown compress", "xz", ""},
		{"zstd compress", "zstd", ""},
		{"nonexistent path", "", "/definitely/does/not/exist/for/logging"},
		{"unknown compress and nonexistent path", "xz", "/nope/nope/nope"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := &FakeshellConfig{
				LogConfig: LogConfig{
					Enable:   false,
					Compress: tc.compress,
					Path:     tc.path,
				},
			}
			if err := CheckAndFillConfig(c); err != nil {
				t.Fatalf("CheckAndFillConfig (disabled) error = %v", err)
			}
			// Default path is always filled, even when disabled.
			if c.LogConfig.Path == "" {
				t.Errorf("disabled log path stayed empty; want default %q", DefaultLogPath)
			}
		})
	}
}

// TestLogConfig_DisabledFillsDefaultPath verifies that a disabled config with
// an empty path gets the default path filled in.
func TestLogConfig_DisabledFillsDefaultPath(t *testing.T) {
	t.Parallel()

	c := &FakeshellConfig{LogConfig: LogConfig{Enable: false, Path: ""}}
	if err := CheckAndFillConfig(c); err != nil {
		t.Fatalf("CheckAndFillConfig: %v", err)
	}
	if c.LogConfig.Path != DefaultLogPath {
		t.Errorf("disabled path = %q, want default %q", c.LogConfig.Path, DefaultLogPath)
	}
}

// TestLogConfig_EnabledFillsDefaultPath verifies that an enabled config with
// an empty path gets the default path filled in.
func TestLogConfig_EnabledFillsDefaultPath(t *testing.T) {
	t.Parallel()

	c := &FakeshellConfig{LogConfig: LogConfig{Enable: true, Path: ""}}
	if err := CheckAndFillConfig(c); err != nil {
		t.Fatalf("CheckAndFillConfig: %v", err)
	}
	if c.LogConfig.Path != DefaultLogPath {
		t.Errorf("enabled path = %q, want default %q", c.LogConfig.Path, DefaultLogPath)
	}
}

// TestLogConfig_EnabledAcceptsGzipAndEmpty verifies that an enabled config
// accepts "" and "gzip" compress values (case-insensitive for gzip).
func TestLogConfig_EnabledAcceptsGzipAndEmpty(t *testing.T) {
	t.Parallel()

	for _, compress := range []string{"", "gzip", "GZIP", "Gzip"} {
		c := &FakeshellConfig{
			LogConfig: LogConfig{
				Enable:   true,
				Compress: compress,
				Path:     t.TempDir(),
			},
		}
		if err := CheckAndFillConfig(c); err != nil {
			t.Errorf("enabled compress=%q error = %v", compress, err)
		}
	}
}

// TestLogConfig_EnabledRejectsUnknownCompress verifies that an enabled config
// rejects xz/zstd/unknown compress values.
func TestLogConfig_EnabledRejectsUnknownCompress(t *testing.T) {
	t.Parallel()

	for _, compress := range []string{"xz", "zstd", "bzip2", "lz4", "snappy"} {
		c := &FakeshellConfig{
			LogConfig: LogConfig{
				Enable:   true,
				Compress: compress,
				Path:     t.TempDir(),
			},
		}
		err := CheckAndFillConfig(c)
		if err == nil {
			t.Errorf("enabled compress=%q accepted, want rejection", compress)
			continue
		}
		if !strings.Contains(err.Error(), "compress") {
			t.Errorf("enabled compress=%q error = %v, want substring 'compress'", compress, err)
		}
	}
}

// TestLogConfig_EnabledRejectsControlCharPath verifies that an enabled config
// rejects a path containing NUL or control characters.
func TestLogConfig_EnabledRejectsControlCharPath(t *testing.T) {
	t.Parallel()

	c := &FakeshellConfig{
		LogConfig: LogConfig{
			Enable: true,
			Path:   "bad\x00path",
		},
	}
	if err := CheckAndFillConfig(c); err == nil {
		t.Fatal("expected error for control char in enabled log path, got nil")
	}
}

// TestLogConfig_NilConfigNoOp verifies that validateLogConfig handles nil.
func TestLogConfig_NilConfigNoOp(t *testing.T) {
	t.Parallel()

	if err := validateLogConfig(nil); err != nil {
		t.Fatalf("validateLogConfig(nil) error = %v", err)
	}
}
