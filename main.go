package main

import (
	"os"

	"go.uber.org/zap"
)

var log *zap.SugaredLogger

func main() {
	args, helpF := GetArg()
	initArgs(args, helpF)

}

func initArgs(a ArgsStruct, helpF func()) {
	if a.Help {
		helpF()
		os.Exit(0)
	}

	l, err := NewLogger(a.LogFile, a.LogLevel, a.LogFormat)
	if err != nil {
		panic(err)
	}
	log = l.Sugar()
}
