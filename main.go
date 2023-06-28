package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	golog "log"
	"math"
	"math/rand"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/hugefiver/fakessh/conf"
	"github.com/hugefiver/fakessh/third/ssh"

	"go.uber.org/zap"
)

var log *zap.SugaredLogger
var cl *conf.FlagArgsStruct
var sc *conf.AppConfig

const seedSize = 32 // 256 bits
var seed []byte

func init() {
	rand.Seed(time.Now().UnixNano())
	byteBuf := bytes.NewBuffer(make([]byte, 0, seedSize))
	for i := 0; i < seedSize/8; i++ {
		binary.Write(byteBuf, binary.BigEndian, rand.Uint64())
	}
	seed = byteBuf.Bytes()
}

func main() {
	args, used, helpF := conf.GetArg()
	cl = args
	initArgs(args, used, helpF)

	var signers []ssh.Signer
	// Generate private key or read it from file
	if !args.GenKeyFile && len(sc.Key.KeyFiles) > 0 {
		for _, f := range args.KeyFiles {
			b, err := os.ReadFile(f)
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
		var pairs []*KeyOption
		if used.Contains(conf.FlagKeyType) || args.GenKeyFile {
			pairs = GetKeyOptionPairs(args.KeyType)
		} else {
			pairs = GetKeyOptionPairs(sc.Key.KeyType)
		}

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
				err := os.WriteFile(file, b, 0600)
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

	if sc.Server.SuccessSeed != nil {
		seed = sha256Sum(sc.Server.SuccessSeed)
	}

	var checkVersionFunc func([]byte) bool
	if sc.Server.AntiScan {
		patt := regexp.MustCompile(`^SSH-\d\.\d(?:-[^\s]+)(?:\s*.*)$`)

		checkVersionFunc = func(version []byte) bool {
			ok := patt.Match(version)
			log.Debugf("[client] version: %s, ok: %t", version, ok)
			return ok
		}
	}

	serverConfig := ssh.ServerConfig{
		Config:             ssh.Config{},
		NoClientAuth:       false,
		MaxAuthTries:       sc.Server.MaxTry,
		PasswordCallback:   authCallback,
		PublicKeyCallback:  nil,
		AuthLogCallback:    authLogCallback,
		ServerVersion:      "SSH-2.0-" + sc.Server.SSHVersion,
		BannerCallback:     nil,
		AsOpenSSH:          sc.Server.AntiScan,
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
		if !sc.Server.AntiScan {
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

func initArgs(a *conf.FlagArgsStruct, used conf.StringSet, helpF func()) {
	if a.Help {
		helpF()
		os.Exit(0)
	}

	if a.AppVersion {
		showVersion()
		os.Exit(0)
	}

	var c *conf.AppConfig
	if a.ConfigPath != "" {
		var err error
		c, err = conf.LoadFromFile(a.ConfigPath)
		if err != nil {
			golog.Fatalf("load config file failed: %v", err)
		}
	} else {
		c = conf.NewDefaultAppConfig()
	}
	if err := conf.MergeConfig(c, a, used); err != nil {
		golog.Fatalf("merge config failed: %v", err)
	}

	err := c.CheckConfig()
	if err != nil {
		panic(err)
	}
	sc = c

	l, err := NewLogger(a.LogFile, a.LogLevel, a.LogFormat)
	if err != nil {
		panic(err)
	}
	log = l.Sugar()
}

var errAuth = errors.New("auth failed")

func checkCouldSuccess(user, pass []byte) bool {
	ratio := sc.Server.SuccessRatio / 100
	if ratio == 0. {
		return false
	} else if ratio >= 1-math.Pow10(-8) {
		return true
	}

	sep := make([]byte, len(seed)+2)
	i := copy(sep[1:], seed)
	if i != len(seed) {
		log.Warnf("build sep bytes, should copy %d, copied %d", len(seed), i)
	}

	pair := bytes.Join([][]byte{user, pass}, sep)
	hasher := fnv.New64()
	_, err := hasher.Write(pair)
	if err != nil {
		log.Errorf("hash error: %v", err)
		return false
	}

	hashed := hasher.Sum64()
	return hashed <= uint64(ratio*math.MaxUint64)
}

func authCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	delay := cl.Delay

	p := "*"
	if cl.IsLogPasswd {
		p = string(password)
	}

	succLogin := checkCouldSuccess([]byte(conn.User()), password)
	log.Infof("[login] Connection from %v using user %s password %s, login: %t",
		conn.RemoteAddr(), conn.User(), p, succLogin)

	if succLogin {
		return nil, nil
	}

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

func authLogCallback(conn ssh.ConnMetadata, method string, err error) {
	if method == "password" {
		return
	}
	log.Infof("[unknow_method] Connection from %v version (%s) using %s method",
		conn.RemoteAddr(), conn.ClientVersion(), method)
}
