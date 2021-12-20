package main

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	golog "log"
	"math/rand"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/hugefiver/fakessh/third/ssh"

	"go.uber.org/zap"
)

var log *zap.SugaredLogger
var cl ArgsStruct

func main() {
	args, helpF := GetArg()
	cl = args
	initArgs(args, helpF)

	var signers []ssh.Signer
	// Generate private key or read it from file
	if !args.GenKeyFile && len(args.KeyFiles) > 0 {
		for _, f := range args.KeyFiles {
			b, err := ioutil.ReadFile(f)
			if err != nil {
				golog.Fatalf("Reading %s error: %v ", args.KeyFiles, err)

			}
			signer, err := parseKey(b)
			if err != nil {
				golog.Fatalf("Parsing private key error: %v ", err)
			}
			signers = append(signers, signer)
		}

	} else {
		pairs := GetKeyOptionPairs(args.KeyType)

		// only generate the first key option
		if args.GenKeyFile {
			// Marshal key
			k := &KeyOption{}
			if len(pairs) > 0 {
				k = pairs[0]
			}
			key, err := createPriKey(k.Type, k.Option)
			if err != nil {
				golog.Fatalf("Error when generating key: %v, option: %v ", err, k)
			}

			b, err := marshalPriKey(key)
			if err != nil {
				golog.Fatalf("Marshaling key error: %v ", err)

			}
			file := ""
			if len(args.KeyFiles) > 0 {
				file = args.KeyFiles[0]
			}
			if file == "" {
				// Output to stdout
				fmt.Fprintln(os.Stderr, "Your private key output to stdout.")
				fmt.Println(string(b))
			} else {
				// Output to file
				err := ioutil.WriteFile(file, b, 0600)
				if err != nil {
					golog.Fatalf("Write file %s error: %v ", file, err)
				} else {
					fmt.Printf("Private key has writen to %s \n", file)
				}
			}
			return
		}

		var keys []crypto.Signer
		if len(pairs) > 0 {
			for _, k := range pairs {
				key, err := createPriKey(k.Type, k.Option)
				if err != nil {
					golog.Fatalf("Error when generating key: %v, option: %v ", err, k)
				}
				keys = append(keys, key)
			}
		} else {
			key, err := createEd25519Key()
			if err != nil {
				golog.Fatalf("Error when generating key: %v ", err)
			}
			keys = append(keys, key)
		}

		for _, key := range keys {
			signer, err := getSigner(key)
			if err != nil {
				golog.Fatalf("Get signer from private key error: %v ", err)
				return
			}
			signers = append(signers, signer)
		}
	}

	var checkVersionFunc func([]byte) bool
	if args.AntiScan {
		patt := regexp.MustCompile(`^SSH-\d\.\d(-.+)(\d+(\.\d+)*)?(\s*.*)$`)

		checkVersionFunc = func(version []byte) bool {
			ok := patt.Match(version)
			log.Debugf("[client] version: %s, ok: %t", version, ok)
			return ok
		}
	}

	maxTry := 3
	if args.MaxTry > 0 {
		maxTry = int(args.MaxTry)
	}
	serverConfig := ssh.ServerConfig{
		Config:             ssh.Config{},
		NoClientAuth:       false,
		MaxAuthTries:       maxTry,
		PasswordCallback:   rejectAll,
		PublicKeyCallback:  nil,
		AuthLogCallback:    nil,
		ServerVersion:      "SSH-2.0-" + args.Version,
		BannerCallback:     nil,
		AsOpenSSH:          args.AntiScan,
		CheckClientVersion: checkVersionFunc,
	}

	for _, signer := range signers {
		serverConfig.AddHostKey(signer)
		log.Warnf("[Server] Using host key: %s %s",
			signer.PublicKey().Type(),
			strings.ToUpper(hex.EncodeToString(
				sha256Sum(signer.PublicKey().Marshal())[:8],
			)),
		)
	}

	// Wait goroutines
	wg := sync.WaitGroup{}

	// Run server
	wg.Add(1)
	go func() {
		if !args.AntiScan {
			log.Warn("[Sever] Anti honeypot scan DISABLED")
		}
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

var errAuth = errors.New("auth failed")

func rejectAll(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	delay := cl.Delay

	p := "*"
	if cl.Passwd {
		p = string(password)
	}

	log.Infof("[login] Connection from %v using user %s password %s",
		conn.RemoteAddr(), conn.User(), p)

	if delay > 0 {
		m := cl.Deviation
		if m <= 0 {
			time.Sleep(time.Microsecond * 5)
		} else {
			start := delay - m
			end := delay + m
			if start < 0 {
				start = 0
			}
			time.Sleep(time.Microsecond * time.Duration(start+rand.Intn(end-start)))
		}

	}

	return nil, errAuth
}
