package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	golog "log"
	"os"
	"strings"
	"sync"
	"time"

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
	if !args.GenKeyFile && args.KeyFile != "" {
		b, err := ioutil.ReadFile(args.KeyFile)
		if err != nil {
			golog.Fatalf("Reading %s error: %v ", args.KeyFile, err)

		}
		signer, err = parseKey(b)
		if err != nil {
			golog.Fatalf("Parsing private key error: %v ", err)

		}
	} else {
		key, err := createKey()
		if err != nil {
			golog.Fatalf("Error when generating key: %v ", err)
		}

		if args.GenKeyFile {
			// Marshal key
			b, err := marshalPriKey(key)
			if err != nil {
				golog.Fatalf("Marshaling key error: %v ", err)

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
					golog.Fatalf("Write file %s error: %v ", file, err)
				} else {
					fmt.Printf("Private key has writen to %s .", file)
				}
			}
			return
		}
		signer, err = getSigner(key)
		if err != nil {
			golog.Fatalf("Get signer from private key error: %v ", err)
			return
		}
	}

	serverConfig := ssh.ServerConfig{
		Config:            ssh.Config{},
		NoClientAuth:      false,
		MaxAuthTries:      3,
		PasswordCallback:  rejectAll,
		PublicKeyCallback: nil,
		AuthLogCallback:   nil,
		ServerVersion:     args.Version,
		BannerCallback:    nil,
	}
	serverConfig.AddHostKey(signer)
	log.Warnf("[Server] Using host key: %s %s",
		signer.PublicKey().Type(),
		strings.ToUpper(hex.EncodeToString(
			sha256Sum(signer.PublicKey().Marshal())[:8],
		)),
	)

	// Wait goroutines
	wg := sync.WaitGroup{}

	// Run server
	wg.Add(1)
	go func() {
		StartSSHServer(&serverConfig)
		wg.Done()
	}()

	wg.Wait()
}

func sha256Sum(bytes []byte) (sum []byte) {
	h := sha256.Sum256(bytes)
	sum = h[:]
	return
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

var authError = errors.New("Auth failed")

func rejectAll(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	log.Infof("[login] Connection from %v using user %s password %s",
		conn.RemoteAddr(), conn.User(), string(password))
	time.Sleep(time.Second * 5)
	return nil, authError
}
