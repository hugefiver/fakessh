package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"

	"golang.org/x/crypto/ssh"
)

func parseKey(bytes []byte) (signer ssh.Signer, err error) {
	signer, err = ssh.ParsePrivateKey(bytes)
	return
}

func createKey() (ed25519.PrivateKey, error) {
	_, pri, err := ed25519.GenerateKey(nil)
	return pri, err
}

func marshalPriKey(key ed25519.PrivateKey) ([]byte, error) {
	cur, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: cur,
	}
	bytes := pem.EncodeToMemory(block)
	return bytes, nil
}
