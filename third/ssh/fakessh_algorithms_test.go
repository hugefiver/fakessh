// Copyright 2025 The Fakessh Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"testing"
)

// TestFakesshNegotiatesDH18AndHMACSHA1ETM verifies that the OpenSSH 9.3
// residual algorithms registered in fakessh_algorithms.go (group18-sha512 and
// hmac-sha1-etm@openssh.com) negotiate end-to-end and complete password
// authentication, with the negotiated MAC agreeing in both directions.
func TestFakesshNegotiatesDH18AndHMACSHA1ETM(t *testing.T) {
	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}
	defer c1.Close()
	defer c2.Close()

	var serverAlgorithms NegotiatedAlgorithms

	serverConfig := &ServerConfig{
		Config: Config{
			KeyExchanges: []string{KeyExchangeDH18SHA512},
			Ciphers:      []string{CipherAES128CTR},
			MACs:         []string{HMACSHA1ETM},
		},
		PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
			if algorithmConn, ok := conn.(AlgorithmsConnMetadata); ok {
				serverAlgorithms = algorithmConn.Algorithms()
				return &Permissions{}, nil
			}
			return nil, nil
		},
	}
	serverConfig.AddHostKey(testSigners["rsa"])

	srvErrCh := make(chan error, 1)
	go func() {
		_, _, _, err := NewServerConn(c1, serverConfig)
		srvErrCh <- err
	}()

	clientConfig := &ClientConfig{
		Config: Config{
			KeyExchanges: []string{KeyExchangeDH18SHA512},
			Ciphers:      []string{CipherAES128CTR},
			MACs:         []string{HMACSHA1ETM},
		},
		User:            "user",
		Auth:            []AuthMethod{Password("password")},
		HostKeyCallback: FixedHostKey(testSigners["rsa"].PublicKey()),
	}

	conn, _, _, err := NewClientConn(c2, "", clientConfig)
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}
	defer conn.Close()

	if err := <-srvErrCh; err != nil {
		t.Fatalf("NewServerConn: %v", err)
	}

	clientAlgorithms := conn.(AlgorithmsConnMetadata).Algorithms()

	if clientAlgorithms.KeyExchange != KeyExchangeDH18SHA512 {
		t.Fatalf("client negotiated KEX = %q, want %q", clientAlgorithms.KeyExchange, KeyExchangeDH18SHA512)
	}
	if serverAlgorithms.KeyExchange != KeyExchangeDH18SHA512 {
		t.Fatalf("server negotiated KEX = %q, want %q", serverAlgorithms.KeyExchange, KeyExchangeDH18SHA512)
	}

	if clientAlgorithms.Read.MAC != HMACSHA1ETM {
		t.Fatalf("client read MAC = %q, want %q", clientAlgorithms.Read.MAC, HMACSHA1ETM)
	}
	if clientAlgorithms.Write.MAC != HMACSHA1ETM {
		t.Fatalf("client write MAC = %q, want %q", clientAlgorithms.Write.MAC, HMACSHA1ETM)
	}
	if serverAlgorithms.Read.MAC != HMACSHA1ETM {
		t.Fatalf("server read MAC = %q, want %q", serverAlgorithms.Read.MAC, HMACSHA1ETM)
	}
	if serverAlgorithms.Write.MAC != HMACSHA1ETM {
		t.Fatalf("server write MAC = %q, want %q", serverAlgorithms.Write.MAC, HMACSHA1ETM)
	}

	if clientAlgorithms.Read.Cipher != CipherAES128CTR || clientAlgorithms.Write.Cipher != CipherAES128CTR {
		t.Fatalf("client cipher read=%q write=%q, want %q", clientAlgorithms.Read.Cipher, clientAlgorithms.Write.Cipher, CipherAES128CTR)
	}
	if serverAlgorithms.Read.Cipher != CipherAES128CTR || serverAlgorithms.Write.Cipher != CipherAES128CTR {
		t.Fatalf("server cipher read=%q write=%q, want %q", serverAlgorithms.Read.Cipher, serverAlgorithms.Write.Cipher, CipherAES128CTR)
	}
}
