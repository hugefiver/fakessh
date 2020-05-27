package main

// +build none

import (
	"strings"

	"go.uber.org/zap"
)

// NewLogger : new a `zap loger` with some options
func NewLogger(file string, level string, fmt string) (*zap.Logger, error) {
	level = strings.ToLower(level)
	fmt = strings.ToLower(fmt)

	/*var zapLevel zapcore.Level
	switch level {
	case "info":
		zapLevel = zapcore.InfoLevel
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "warning":
		zapLevel = zapcore.WarnLevel
	default:
		return nil, errors.New("unsupported log level")
	}*/

	return nil, nil
}
