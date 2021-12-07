package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strconv"
	"strings"

	"github.com/hugefiver/fakessh/third/ssh"
)

const DefaultKeyType = "ED25519"
const RsaDefaultBits = 4096

func createPriKey(t, option string) (key crypto.Signer, err error) {
	t = strings.ToUpper(t)
	switch t {
	case "RSA":
		bits := RsaDefaultBits
		if option != "" {
			bits, err = strconv.Atoi(option)
			if err != nil {
				return
			}
		}
		return createRSAKey(bits)
	case "ECDSA":
		c := getCurve(strings.ToUpper(option))
		if c == nil {
			return nil, errors.New("invalid curve type")
		}
		return createEcdsa(c)
	case "ED25519", "":
		return createEd25519Key()
	default:
		return nil, errors.New("unsupport private key type")
	}
}

func getCurve(c string) elliptic.Curve {
	switch c {
	case "P256":
		return elliptic.P256()
	case "P384", "":
		return elliptic.P384()
	case "P521":
		return elliptic.P521()
	default:
		return nil
	}
}

func parseKey(bytes []byte) (signer ssh.Signer, err error) {
	signer, err = ssh.ParsePrivateKey(bytes)
	return
}

func getSigner(key crypto.Signer) (ssh.Signer, error) {
	return ssh.NewSignerFromKey(key)
}

func createEd25519Key() (ed25519.PrivateKey, error) {
	_, pri, err := ed25519.GenerateKey(nil)
	return pri, err
}

func createRSAKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

func createEcdsa(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(curve, rand.Reader)
}

func marshalPriKey(key crypto.PrivateKey) ([]byte, error) {
	var block *pem.Block
	switch v := key.(type) {
	case *rsa.PrivateKey:
		cur := x509.MarshalPKCS1PrivateKey(v)
		block = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: cur,
		}
	case *ecdsa.PrivateKey:
		cur, err := x509.MarshalECPrivateKey(v)
		if err != nil {
			return nil, err
		}
		block = &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: cur,
		}
	default:
		// for ed25519
		cur, err := x509.MarshalPKCS8PrivateKey(v)
		if err != nil {
			return nil, err
		}
		block = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: cur,
		}
	}

	bytes := pem.EncodeToMemory(block)
	return bytes, nil
}
