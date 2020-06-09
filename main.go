package main

import (
	"fmt"
	"os"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

var log *zap.SugaredLogger
var cl ArgsStruct

func main() {
	args, helpF := GetArg()
	cl = args
	initArgs(args, helpF)

	var signer ssh.Signer
	// Generate private key or read it from file
	if args.GenKeyFile == false && args.KeyFile == "" {
		b, err　:= 
	} else {
		key, err := createKey()
		if err != nil {
			fmt.Errorf("Get an error when generate key: %v")
		}
	}
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
