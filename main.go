package main

import (
	"fmt"
	"io/ioutil"
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
	if args.GenKeyFile == false && args.KeyFile != "" {
		b, err := ioutil.ReadFile(args.KeyFile)
		if err != nil {
			fmt.Errorf("Reading %s error: %v ", args.KeyFile, err)
			return
		}
		signer, err = parseKey(b)
		if err != nil {
			fmt.Errorf("Parsing private key error: %v ", err)
			return
		}
	} else {
		key, err := createKey()
		if err != nil {
			fmt.Errorf("Error when generating key: %v ", err)
			return
		}

		if args.GenKeyFile {
			// Marshal key
			b, err := marshalPriKey(key)
			if err != nil {
				fmt.Errorf("Marshaling key error: %v ", err)
				return
			}
			file := args.KeyFile
			if file == "" {
				// Output to stdout
				fmt.Println("Here is your private key:")
				fmt.Println(string(b))
			} else {
				// Output to file
				err := ioutil.WriteFile(file, b, 0600)
				if err != nil {
					fmt.Errorf("Write file %s error: %v ", file, err)
				} else {
					fmt.Printf("Private key has writen to %s .", file)
				}
			}
			return
		} else {
			signer, err = getSigner(key)
			if err != nil {
				fmt.Errorf("Get signer from private key error: %v ", err)
				return
			}
		}

	}

	serverConfig := ssh.ServerConfig{}
	serverConfig.AddHostKey(signer)
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
