package main

import (
	"os"
	"runtime"
	"testing"
)

func TestNewLoggerCreatesPrivateLogFile(t *testing.T) {
	tmp, err := os.CreateTemp("", "fakessh-*.log")
	if err != nil {
		t.Fatalf("create temp log path: %v", err)
	}
	path := tmp.Name()
	if err := tmp.Close(); err != nil {
		t.Fatalf("close temp log file: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove temp log file before NewLogger: %v", err)
	}
	if runtime.GOOS != "windows" {
		t.Cleanup(func() {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				t.Errorf("remove log file: %v", err)
			}
		})
	}

	logger, err := NewLogger(path, "info", "plain")
	if err != nil {
		t.Fatalf("NewLogger() error = %v", err)
	}
	defer logger.Sync()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat log file: %v", err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("log file mode = %v, want %v", got, os.FileMode(0o600))
	}
}
