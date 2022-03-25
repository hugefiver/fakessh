package utils

import (
	"os"
	"path/filepath"
	"strings"
)

func ParsePath(path string) string {
	if path == "" {
		return ""
	}
	if strings.HasPrefix(path, "~") {
		path = filepath.Join(os.Getenv("HOME"), path[1:])
	} else if !strings.HasPrefix(path, "/") {
		path = filepath.Join(os.Getenv("PWD"), path)
	}

	return path
}
