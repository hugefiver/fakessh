package main

import (
	"errors"
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// NewLogger : new a `zap loger` with some options
func NewLogger(filepath string, level string, fmt string) (logger *zap.Logger, err error) {
	level = strings.ToLower(level)
	fmt = strings.ToLower(fmt)

	var zapLevel zapcore.Level
	switch level {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "info":
		zapLevel = zapcore.InfoLevel
	case "warning":
		zapLevel = zapcore.WarnLevel
	default:
		return nil, errors.New("unsupported log level: " + level)
	}

	var zapEncoder zapcore.Encoder
	encConfig := getEncoderConfig()
	switch fmt {
	case "plain":
		zapEncoder = zapcore.NewConsoleEncoder(encConfig)
	case "json":
		zapEncoder = zapcore.NewJSONEncoder(encConfig)
	default:
		return nil, errors.New("unsupported log format: " + fmt)
	}

	file, err := os.OpenFile(filepath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	fileSync := zapcore.AddSync(file)

	core := zapcore.NewCore(zapEncoder, fileSync, zapLevel)
	logger = zap.New(core)
	return logger, nil
}

func getEncoderConfig() zapcore.EncoderConfig {
	e := zap.NewProductionEncoderConfig()

	e.EncodeLevel = zapcore.CapitalLevelEncoder
	e.EncodeTime = zapcore.ISO8601TimeEncoder
	return e
}
