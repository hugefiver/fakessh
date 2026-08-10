// Copyright 2025 The Fakessh Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/binary"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/hugefiver/fakessh/third/ssh/internal/poly1305"
	"golang.org/x/crypto/chacha20"
)

// bufConn wraps a bytes.Buffer as an io.ReadWriteCloser for transport tests.
type bufConn struct {
	r bytes.Buffer
}

func (c *bufConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *bufConn) Write(p []byte) (int, error) { return c.r.Write(p) }
func (c *bufConn) Close() error                { return nil }
func (c *bufConn) Bytes() []byte               { return c.r.Bytes() }

// constantReader is an io.Reader that always fills p with the same byte,
// used as a deterministic non-zero rand source for padding tests.
type constantReader byte

func (c constantReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(c)
	}
	return len(p), nil
}

// fakeCipher is a test-only packetCipher that records the last written packet
// and always returns errPacketCorrupt on read. Because it is not a
// *streamPacketCipher, connectionState.isPlaintext returns false for it,
// simulating a post-KEX (encrypted) state.
type fakeCipher struct {
	written []byte
}

func (f *fakeCipher) writeCipherPacket(seqNum uint32, w io.Writer, r io.Reader, packet []byte) error {
	f.written = append(f.written[:0], packet...)
	_, err := w.Write(packet)
	return err
}

func (f *fakeCipher) readCipherPacket(seqNum uint32, r io.Reader) ([]byte, error) {
	return nil, errPacketCorrupt
}

// extractPlaintextPadding parses a plaintext SSH packet wire (noneCipher, no
// MAC) and returns just the padding bytes.
func extractPlaintextPadding(wire []byte) []byte {
	if len(wire) < 6 {
		return nil
	}
	length := binary.BigEndian.Uint32(wire[:4])
	paddingLength := int(wire[4])
	packetLen := int(length) - 1 - paddingLength
	if packetLen < 0 {
		return nil
	}
	paddingStart := 5 + packetLen
	paddingEnd := paddingStart + paddingLength
	if paddingEnd > len(wire) || paddingStart > paddingEnd {
		return nil
	}
	return wire[paddingStart:paddingEnd]
}

// TestFakesshOpenSSHCompatNullPaddingIsOptIn proves that pre-KEX plaintext
// padding is non-zero by default (random) and zero when OpenSSH-compat is
// enabled, using a deterministic non-zero rand source (0xAA).
func TestFakesshOpenSSHCompatNullPaddingIsOptIn(t *testing.T) {
	packet := []byte("test")

	// --- Default: compat disabled ---
	rwc1 := &bufConn{}
	tr1 := newTransport(rwc1, constantReader(0xAA), false)
	if err := tr1.writePacket(packet); err != nil {
		t.Fatalf("default writePacket: %v", err)
	}
	wire1 := rwc1.Bytes()
	padding1 := extractPlaintextPadding(wire1)
	if len(padding1) == 0 {
		t.Fatalf("default: could not extract padding from %d-byte wire", len(wire1))
	}
	for _, b := range padding1 {
		if b != 0xAA {
			t.Errorf("default padding = %#x, want 0xAA (random nonzero)", b)
		}
	}

	// --- Compat enabled ---
	rwc2 := &bufConn{}
	tr2 := newTransport(rwc2, constantReader(0xAA), false)
	tr2.enableOpenSSHCompat(true)
	if err := tr2.writePacket(packet); err != nil {
		t.Fatalf("compat writePacket: %v", err)
	}
	wire2 := rwc2.Bytes()
	padding2 := extractPlaintextPadding(wire2)
	if len(padding2) == 0 {
		t.Fatalf("compat: could not extract padding from %d-byte wire", len(wire2))
	}
	for _, b := range padding2 {
		if b != 0x00 {
			t.Errorf("compat padding = %#x, want 0x00 (NULL)", b)
		}
	}
}

// TestFakesshCorruptPacketPlaintextBeforeKEX proves that when compat is
// enabled and a malformed plaintext packet is read (triggering a corrupt
// error), the transport writes bare "Packet corrupt\x00" to the raw
// connection.
func TestFakesshCorruptPacketPlaintextBeforeKEX(t *testing.T) {
	rwc := &bufConn{}
	// length=0, paddingLength=0 -> "ssh: invalid packet length, packet too small"
	rwc.Write([]byte{0, 0, 0, 0, 0})

	tr := newTransport(rwc, rand.Reader, false)
	tr.enableOpenSSHCompat(true)

	_, err := tr.readPacket()
	if err == nil {
		t.Fatalf("readPacket: expected error, got nil")
	}

	result := rwc.Bytes()
	want := []byte("Packet corrupt\x00")
	if !bytes.Contains(result, want) {
		t.Errorf("raw conn = %q, want it to contain %q", result, want)
	}
}

func TestFakesshPlaintextBadPadlenBeforeKEXWritesGenericCorrupt(t *testing.T) {
	rwc := &bufConn{}
	var prefix [5]byte
	binary.BigEndian.PutUint32(prefix[:4], 8)
	prefix[4] = 1
	rwc.Write(prefix[:])
	rwc.Write([]byte("badpad"))
	rwc.Write([]byte{0x42})

	tr := newTransport(rwc, rand.Reader, false)
	tr.enableOpenSSHCompat(true)

	_, err := tr.readPacket()
	if err == nil {
		t.Fatalf("readPacket: expected error, got nil")
	}

	result := rwc.Bytes()
	if !bytes.Contains(result, []byte("Packet corrupt\x00")) {
		t.Fatalf("raw conn = %q, want Packet corrupt", result)
	}
	if bytes.Contains(result, []byte("Corrupted padlen")) {
		t.Fatalf("raw conn = %q, must not contain padlen-specific disconnect", result)
	}
}

// TestFakesshCorruptPacketDisconnectAfterKEX proves that when compat is
// enabled and the writer is not plaintext (post-KEX), a corrupt read error
// triggers a framed SSH_MSG_DISCONNECT with reason 2 and message
// "Packet corrupt", not bare plaintext.
func TestFakesshCorruptPacketDisconnectAfterKEX(t *testing.T) {
	rwc := &bufConn{}
	tr := newTransport(rwc, rand.Reader, false)
	tr.enableOpenSSHCompat(true)

	// Replace both reader and writer with a fake non-plaintext cipher.
	// fakeCipher is not *streamPacketCipher, so isPlaintext() returns false.
	fake := &fakeCipher{}
	tr.reader.packetCipher = fake
	tr.writer.packetCipher = fake

	_, err := tr.readPacket()
	if err == nil {
		t.Fatalf("readPacket: expected error, got nil")
	}

	result := rwc.Bytes()
	// The bare plaintext response is exactly "Packet corrupt\x00" (16 bytes).
	// A framed disconnect starts with msgDisconnect (0x01). The fake cipher
	// passes the marshaled packet through unencrypted, so we should see the
	// framed message, not the bare plaintext.
	bareCorrupt := []byte("Packet corrupt\x00")
	if bytes.Equal(result, bareCorrupt) || bytes.HasPrefix(result, bareCorrupt) {
		t.Errorf("raw conn got bare plaintext corrupt: %q", result)
	}
	if len(result) == 0 || result[0] != msgDisconnect {
		t.Errorf("raw conn first byte = %#x, want msgDisconnect (%#x)", result, msgDisconnect)
	}

	var msg disconnectMsg
	if err := Unmarshal(result, &msg); err != nil {
		t.Fatalf("Unmarshal(raw conn): %v (bytes: %v)", err, result)
	}
	if msg.Reason != 2 {
		t.Errorf("disconnect Reason = %d, want 2", msg.Reason)
	}
	if msg.Message != "Packet corrupt" {
		t.Errorf("disconnect Message = %q, want %q", msg.Message, "Packet corrupt")
	}
}

// TestFakesshCorruptedPadlenDisconnectAfterKEX proves that packets that
// authenticate successfully but decrypt to an invalid padding length get
// OpenSSH's padlen-specific disconnect instead of the generic Packet corrupt
// message.
func TestFakesshCorruptedPadlenDisconnectAfterKEX(t *testing.T) {
	algs := DirectionAlgorithms{
		Cipher:      CipherAES128GCM,
		compression: compressionNone,
	}
	kr := &kexResult{Hash: crypto.SHA1}
	readerCipher, err := newPacketCipher(clientKeys, algs, kr)
	if err != nil {
		t.Fatalf("newPacketCipher: %v", err)
	}
	gcm, ok := readerCipher.(*gcmCipher)
	if !ok {
		t.Fatalf("newPacketCipher returned %T, want *gcmCipher", readerCipher)
	}

	// Plaintext packet body: padlen=1 followed by four bytes. The AEAD tag is
	// valid, and the packet is long enough to reach decrypted padlen validation.
	plain := []byte{1, 'b', 'a', 'd', '!'}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(plain)))
	wire := append(prefix[:], gcm.aead.Seal(nil, gcm.iv, plain, prefix[:])...)

	rwc := &bufConn{}
	rwc.Write(wire)
	tr := newTransport(rwc, rand.Reader, false)
	tr.enableOpenSSHCompat(true)
	tr.reader.packetCipher = readerCipher
	tr.writer.packetCipher = &fakeCipher{}

	_, err = tr.readPacket()
	if err == nil {
		t.Fatalf("readPacket: expected error, got nil")
	}

	result := rwc.Bytes()
	var msg disconnectMsg
	if err := Unmarshal(result, &msg); err != nil {
		t.Fatalf("Unmarshal(raw conn): %v (bytes: %v)", err, result)
	}
	if msg.Reason != 2 {
		t.Errorf("disconnect Reason = %d, want 2", msg.Reason)
	}
	if msg.Message != "Corrupted padlen 1 on input." {
		t.Errorf("disconnect Message = %q, want %q", msg.Message, "Corrupted padlen 1 on input.")
	}
}

func TestFakesshStreamCipherCorruptedPadlenDisconnectAfterKEX(t *testing.T) {
	tests := []struct {
		name string
		mac  string
	}{
		{"HMAC", HMACSHA256},
		{"EtM", HMACSHA256ETM},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algs := DirectionAlgorithms{
				Cipher:      CipherAES128CTR,
				MAC:         tt.mac,
				compression: compressionNone,
			}
			kr := &kexResult{Hash: crypto.SHA1}
			writerCipher, err := newPacketCipher(clientKeys, algs, kr)
			if err != nil {
				t.Fatalf("newPacketCipher(writer): %v", err)
			}
			writerStream, ok := writerCipher.(*streamPacketCipher)
			if !ok {
				t.Fatalf("writer cipher = %T, want *streamPacketCipher", writerCipher)
			}
			readerCipher, err := newPacketCipher(clientKeys, algs, kr)
			if err != nil {
				t.Fatalf("newPacketCipher(reader): %v", err)
			}
			fakesshSetOpenSSHMinPadding(readerCipher, true)

			wire := buildTestStreamPacketWire(t, writerStream, 0, []byte("badpad"), 1)
			rwc := &bufConn{}
			rwc.Write(wire)
			tr := newTransport(rwc, rand.Reader, false)
			tr.enableOpenSSHCompat(true)
			tr.reader.packetCipher = readerCipher
			tr.writer.packetCipher = &fakeCipher{}

			_, err = tr.readPacket()
			if err == nil {
				t.Fatalf("readPacket: expected error, got nil")
			}

			result := rwc.Bytes()
			var msg disconnectMsg
			if err := Unmarshal(result, &msg); err != nil {
				t.Fatalf("Unmarshal(raw conn): %v (bytes: %v)", err, result)
			}
			if msg.Reason != 2 {
				t.Errorf("disconnect Reason = %d, want 2", msg.Reason)
			}
			if msg.Message != "Corrupted padlen 1 on input." {
				t.Errorf("disconnect Message = %q, want %q", msg.Message, "Corrupted padlen 1 on input.")
			}
		})
	}
}

func buildTestStreamPacketWire(t *testing.T, cipher *streamPacketCipher, seqNum uint32, payload []byte, paddingLength byte) []byte {
	t.Helper()

	prefix := make([]byte, prefixLen)
	binary.BigEndian.PutUint32(prefix[:4], uint32(len(payload)+1+int(paddingLength)))
	prefix[4] = paddingLength
	packet := append([]byte(nil), payload...)
	padding := bytes.Repeat([]byte{0x42}, int(paddingLength))

	var mac []byte
	if cipher.mac != nil {
		cipher.mac.Reset()
		var seqNumBytes [4]byte
		binary.BigEndian.PutUint32(seqNumBytes[:], seqNum)
		cipher.mac.Write(seqNumBytes[:])
		if cipher.etm {
			cipher.cipher.XORKeyStream(prefix[4:5], prefix[4:5])
		}
		cipher.mac.Write(prefix)
		if !cipher.etm {
			cipher.mac.Write(packet)
			cipher.mac.Write(padding)
		}
	}

	if !(cipher.mac != nil && cipher.etm) {
		cipher.cipher.XORKeyStream(prefix, prefix)
	}
	cipher.cipher.XORKeyStream(packet, packet)
	cipher.cipher.XORKeyStream(padding, padding)

	if cipher.mac != nil && cipher.etm {
		cipher.mac.Write(packet)
		cipher.mac.Write(padding)
	}
	if cipher.mac != nil {
		mac = cipher.mac.Sum(nil)
	}

	wire := append(prefix, packet...)
	wire = append(wire, padding...)
	wire = append(wire, mac...)
	return wire
}

// TestFakesshAuthenticatedShortPacketDisconnectAfterKEX proves that packets
// with a valid AEAD tag but authenticated length below OpenSSH's minimum
// packet size (< 1 pad byte + 4 minimum padding bytes) get generic
// "Packet corrupt" rather than padlen-specific disconnects.
func TestFakesshAuthenticatedShortPacketDisconnectAfterKEX(t *testing.T) {
	tests := []struct {
		name      string
		cipherAlg string
		wire      func(t *testing.T, cipher packetCipher, plain []byte) []byte
	}{
		{
			name:      "AES128GCM",
			cipherAlg: CipherAES128GCM,
			wire: func(t *testing.T, cipher packetCipher, plain []byte) []byte {
				t.Helper()
				gcm, ok := cipher.(*gcmCipher)
				if !ok {
					t.Fatalf("cipher = %T, want *gcmCipher", cipher)
				}
				var prefix [4]byte
				binary.BigEndian.PutUint32(prefix[:], uint32(len(plain)))
				return append(prefix[:], gcm.aead.Seal(nil, gcm.iv, plain, prefix[:])...)
			},
		},
		{
			name:      "ChaCha20Poly1305",
			cipherAlg: CipherChaCha20Poly1305,
			wire: func(t *testing.T, cipher packetCipher, plain []byte) []byte {
				t.Helper()
				chacha, ok := cipher.(*chacha20Poly1305Cipher)
				if !ok {
					t.Fatalf("cipher = %T, want *chacha20Poly1305Cipher", cipher)
				}
				return buildTestChaCha20Poly1305Wire(t, chacha, 0, plain)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algs := DirectionAlgorithms{
				Cipher:      tt.cipherAlg,
				MAC:         HMACSHA256,
				compression: compressionNone,
			}
			kr := &kexResult{Hash: crypto.SHA1}
			readerCipher, err := newPacketCipher(clientKeys, algs, kr)
			if err != nil {
				t.Fatalf("newPacketCipher: %v", err)
			}

			wire := tt.wire(t, readerCipher, []byte{1, 'b', 'a', 'd'})
			rwc := &bufConn{}
			rwc.Write(wire)
			tr := newTransport(rwc, rand.Reader, false)
			tr.enableOpenSSHCompat(true)
			tr.reader.packetCipher = readerCipher
			tr.writer.packetCipher = &fakeCipher{}

			_, err = tr.readPacket()
			if err == nil {
				t.Fatalf("readPacket: expected error, got nil")
			}

			result := rwc.Bytes()
			var msg disconnectMsg
			if err := Unmarshal(result, &msg); err != nil {
				t.Fatalf("Unmarshal(raw conn): %v (bytes: %v)", err, result)
			}
			if msg.Reason != 2 {
				t.Errorf("disconnect Reason = %d, want 2", msg.Reason)
			}
			if msg.Message != "Packet corrupt" {
				t.Errorf("disconnect Message = %q, want %q", msg.Message, "Packet corrupt")
			}
		})
	}
}

// TestFakesshAuthenticatedOversizedPaddingDoesNotSendPadlenDisconnect proves
// that valid-tag packets whose padlen is too large for the decrypted packet
// length do not get OpenSSH's padlen-specific disconnect; OpenSSH reserves that
// message for padlen < 4.
func TestFakesshAuthenticatedOversizedPaddingDoesNotSendPadlenDisconnect(t *testing.T) {
	algs := DirectionAlgorithms{
		Cipher:      CipherAES128GCM,
		compression: compressionNone,
	}
	kr := &kexResult{Hash: crypto.SHA1}
	readerCipher, err := newPacketCipher(clientKeys, algs, kr)
	if err != nil {
		t.Fatalf("newPacketCipher: %v", err)
	}
	gcm, ok := readerCipher.(*gcmCipher)
	if !ok {
		t.Fatalf("newPacketCipher returned %T, want *gcmCipher", readerCipher)
	}

	plain := []byte{4, 'b', 'a', 'd', '!'}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(plain)))
	wire := append(prefix[:], gcm.aead.Seal(nil, gcm.iv, plain, prefix[:])...)

	rwc := &bufConn{}
	rwc.Write(wire)
	tr := newTransport(rwc, rand.Reader, false)
	tr.enableOpenSSHCompat(true)
	tr.reader.packetCipher = readerCipher
	tr.writer.packetCipher = &fakeCipher{}

	_, err = tr.readPacket()
	if err == nil {
		t.Fatalf("readPacket: expected error, got nil")
	}

	result := rwc.Bytes()
	if bytes.Contains(result, []byte("Corrupted padlen")) {
		t.Fatalf("raw conn = %q, must not contain padlen-specific disconnect", result)
	}
	if len(result) != 0 {
		t.Fatalf("raw conn = %q, want no compat disconnect for oversized padlen", result)
	}
}

func buildTestChaCha20Poly1305Wire(t *testing.T, cipher *chacha20Poly1305Cipher, seqNum uint32, plain []byte) []byte {
	t.Helper()

	nonce := make([]byte, 12)
	binary.BigEndian.PutUint32(nonce[8:], seqNum)
	s, err := chacha20.NewUnauthenticatedCipher(cipher.contentKey[:], nonce)
	if err != nil {
		t.Fatalf("NewUnauthenticatedCipher(content): %v", err)
	}

	var polyKey, discardBuf [32]byte
	s.XORKeyStream(polyKey[:], polyKey[:])
	s.XORKeyStream(discardBuf[:], discardBuf[:])

	var lengthPlain [4]byte
	binary.BigEndian.PutUint32(lengthPlain[:], uint32(len(plain)))
	lengthCipher, err := chacha20.NewUnauthenticatedCipher(cipher.lengthKey[:], nonce)
	if err != nil {
		t.Fatalf("NewUnauthenticatedCipher(length): %v", err)
	}
	encryptedLength := make([]byte, 4)
	lengthCipher.XORKeyStream(encryptedLength, lengthPlain[:])

	encryptedContent := append([]byte(nil), plain...)
	s.XORKeyStream(encryptedContent, encryptedContent)
	wire := append(encryptedLength, encryptedContent...)

	var mac [poly1305.TagSize]byte
	poly1305.Sum(&mac, wire, &polyKey)
	return append(wire, mac[:]...)
}

// TestFakesshCorruptMACWritesCorruptResponse exercises AES-CTR/HMAC,
// AES-GCM, and ChaCha20-Poly1305 through transport.readPacket with compat
// enabled and a tampered final byte. In all cases, the tampered MAC/tag
// triggers a corrupt-packet error, and the plaintext writer emits the
// "Packet corrupt\x00" response to the raw connection.
func TestFakesshCorruptMACWritesCorruptResponse(t *testing.T) {
	tests := []struct {
		name   string
		cipher string
		mac    string
	}{
		{"AES128CTR-HMACSHA256", CipherAES128CTR, HMACSHA256},
		{"AES128GCM", CipherAES128GCM, HMACSHA256},
		{"ChaCha20Poly1305", CipherChaCha20Poly1305, HMACSHA256},
	}

	kr := &kexResult{Hash: crypto.SHA1}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			algs := DirectionAlgorithms{
				Cipher:      tc.cipher,
				MAC:         tc.mac,
				compression: compressionNone,
			}
			clientCipher, err := newPacketCipher(clientKeys, algs, kr)
			if err != nil {
				t.Fatalf("newPacketCipher(client): %v", err)
			}
			serverCipher, err := newPacketCipher(clientKeys, algs, kr)
			if err != nil {
				t.Fatalf("newPacketCipher(server): %v", err)
			}

			// Write a valid encrypted packet with the client cipher.
			var wire bytes.Buffer
			if err := clientCipher.writeCipherPacket(0, &wire, rand.Reader, []byte("test")); err != nil {
				t.Fatalf("writeCipherPacket: %v", err)
			}

			// Tamper the final byte (within the MAC/tag region).
			tampered := wire.Bytes()
			tampered[len(tampered)-1] ^= 0xFF

			// Feed tampered wire bytes into the transport reader.
			rwc := &bufConn{}
			rwc.Write(tampered)

			tr := newTransport(rwc, rand.Reader, false)
			tr.enableOpenSSHCompat(true)
			tr.reader.packetCipher = serverCipher

			_, err = tr.readPacket()
			if err == nil {
				t.Fatalf("readPacket: expected error, got nil")
			}

			// The writer is still plaintext, so writePacketCorrupt should
			// have written bare "Packet corrupt\x00" to the raw connection.
			result := rwc.Bytes()
			want := []byte("Packet corrupt\x00")
			if !bytes.Contains(result, want) {
				t.Errorf("raw conn = %v, want it to contain %q", result, want)
			}
		})
	}
}

func TestFakesshOpenSSHVersionPrecheckAcceptsSSH199AndSSH21(t *testing.T) {
	tests := []struct {
		name          string
		clientVersion string
	}{
		{"ssh199", "SSH-1.99-legacy"},
		{"ssh21", "SSH-2.1-test"},
		{"whitespaceMajor", "SSH- 2.0-test"},
		{"plusMajor", "SSH-+2.0-test"},
		{"longSSH2", "SSH-2.0-" + strings.Repeat("A", maxVersionStringBytes)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c1, c2, err := netPipe()
			if err != nil {
				t.Fatalf("netPipe: %v", err)
			}
			defer c1.Close()
			defer c2.Close()

			serverConfig := &ServerConfig{
				AsOpenSSH: true,
				PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
					return &Permissions{}, nil
				},
			}
			serverConfig.AddHostKey(testSigners["rsa"])

			srvErrCh := make(chan error, 1)
			go func() {
				_, _, _, err := NewServerConn(c1, serverConfig)
				srvErrCh <- err
			}()

			clientConfig := &ClientConfig{
				ClientVersion:   tt.clientVersion,
				User:            "user",
				Auth:            []AuthMethod{Password("password")},
				HostKeyCallback: FixedHostKey(testSigners["rsa"].PublicKey()),
			}

			conn, _, _, err := NewClientConn(c2, "", clientConfig)
			if err != nil {
				t.Fatalf("NewClientConn: %v", err)
			}
			defer conn.Close()

			select {
			case err := <-srvErrCh:
				if err != nil {
					t.Fatalf("NewServerConn: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("NewServerConn did not return within timeout")
			}
		})
	}
}

func TestFakesshOpenSSHVersionPrecheckRejectsSignedMajorMismatch(t *testing.T) {
	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}
	defer c1.Close()
	defer c2.Close()

	config := &ServerConfig{
		AsOpenSSH: true,
		PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
			return nil, nil
		},
	}
	config.AddHostKey(testSigners["rsa"])

	srvErrCh := make(chan error, 1)
	go func() {
		_, _, _, err := NewServerConn(c1, config)
		srvErrCh <- err
	}()

	c2.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := readVersion(c2); err != nil {
		t.Fatalf("read server version: %v", err)
	}

	if _, err := c2.Write([]byte("SSH--2.0-test\r\n")); err != nil {
		t.Fatalf("write client version: %v", err)
	}

	var resp bytes.Buffer
	io.Copy(&resp, c2)

	response := resp.String()
	if !strings.Contains(response, "Protocol major versions differ.\r\n") {
		t.Errorf("server response = %q, want it to contain %q", response, "Protocol major versions differ.\r\n")
	}
	if strings.Contains(response, "Invalid SSH identification string.\r\n") {
		t.Errorf("server response = %q, must not contain invalid-ident response", response)
	}

	select {
	case err := <-srvErrCh:
		if err == nil {
			t.Errorf("NewServerConn: expected error, got nil")
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("NewServerConn did not return within timeout")
	}
}

func TestFakesshReadVersionOpenSSHAcceptsTabSuffix(t *testing.T) {
	rwc := &bufConn{}
	version := []byte("SSH-2.0-OpenSSH_9.3\tx\r\n")
	rwc.Write(version)

	got, err := readVersionOpenSSH(rwc)
	if err != nil {
		t.Fatalf("readVersionOpenSSH: %v", err)
	}
	if string(got) != "SSH-2.0-OpenSSH_9.3\tx" {
		t.Fatalf("version = %q, want %q", got, "SSH-2.0-OpenSSH_9.3\tx")
	}
	if len(rwc.Bytes()) != 0 {
		t.Fatalf("raw conn wrote unexpected response: %q", rwc.Bytes())
	}
}

func TestFakesshReadVersionOpenSSHAcceptsRepeatedCRTerminator(t *testing.T) {
	rwc := &bufConn{}
	rwc.Write([]byte("SSH-2.0-test\r\r\n"))

	got, err := readVersionOpenSSH(rwc)
	if err != nil {
		t.Fatalf("readVersionOpenSSH: %v", err)
	}
	if string(got) != "SSH-2.0-test" {
		t.Fatalf("version = %q, want %q", got, "SSH-2.0-test")
	}
	if len(rwc.Bytes()) != 0 {
		t.Fatalf("raw conn wrote unexpected response: %q", rwc.Bytes())
	}
}

// TestFakesshOpenSSHVersionPrecheckRejectsSSH15 proves that when AsOpenSSH is
// true, a client sending real SSH1 is rejected with "Protocol major versions
// differ.\r\n" and NewServerConn returns an error.
func TestFakesshOpenSSHVersionPrecheckRejectsSSH15(t *testing.T) {
	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}
	defer c1.Close()
	defer c2.Close()

	config := &ServerConfig{
		AsOpenSSH: true,
		PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
			return nil, nil
		},
	}
	config.AddHostKey(testSigners["rsa"])

	srvErrCh := make(chan error, 1)
	go func() {
		_, _, _, err := NewServerConn(c1, config)
		srvErrCh <- err
	}()

	// Client side: send SSH-1.5 version, then read all response data until
	// the server closes the connection.
	c2.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := readVersion(c2); err != nil {
		t.Fatalf("read server version: %v", err)
	}

	if _, err := c2.Write([]byte("SSH-1.5-test\r\n")); err != nil {
		t.Fatalf("write client version: %v", err)
	}

	var resp bytes.Buffer
	io.Copy(&resp, c2) // read until EOF (server closes after protocol mismatch)

	response := resp.String()
	if !strings.Contains(response, "Protocol major versions differ.\r\n") {
		t.Errorf("server response = %q, want it to contain %q", response, "Protocol major versions differ.\r\n")
	}

	select {
	case err := <-srvErrCh:
		if err == nil {
			t.Errorf("NewServerConn: expected error, got nil")
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("NewServerConn did not return within timeout")
	}
}

// TestFakesshOpenSSHVersionPrecheckRejectsMalformedIdentification proves that
// malformed SSH identification lines get OpenSSH's invalid-identification
// response instead of a delayed generic Protocol mismatch response.
func TestFakesshOpenSSHVersionPrecheckRejectsMalformedIdentification(t *testing.T) {
	tests := []struct {
		name   string
		banner string
	}{
		{"missingSoftwareDash", "SSH-2.0\r\n"},
		{"emptySoftware", "SSH-2.0-\r\n"},
		{"leadingJunkLine", "hello\r\n"},
		{"postCRJunk", "SSH-2.0-test\rX\n"},
		{"nulByte", "SSH-2.0-\x00\r\n"},
		{"overlongSSHBanner", "SSH-2.0-" + strings.Repeat("A", openSSHMaxBannerBytes) + "\r\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c1, c2, err := netPipe()
			if err != nil {
				t.Fatalf("netPipe: %v", err)
			}
			defer c1.Close()
			defer c2.Close()

			config := &ServerConfig{
				AsOpenSSH: true,
				PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
					return nil, nil
				},
			}
			config.AddHostKey(testSigners["rsa"])

			srvErrCh := make(chan error, 1)
			go func() {
				_, _, _, err := NewServerConn(c1, config)
				srvErrCh <- err
			}()

			c2.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err := readVersion(c2); err != nil {
				t.Fatalf("read server version: %v", err)
			}

			if _, err := c2.Write([]byte(tt.banner)); err != nil {
				t.Fatalf("write client version: %v", err)
			}

			var resp bytes.Buffer
			io.Copy(&resp, c2)

			response := resp.String()
			want := "Invalid SSH identification string.\r\n"
			if !strings.Contains(response, want) {
				t.Fatalf("server response = %q, want it to contain %q", response, want)
			}
			if strings.Contains(response, "Protocol mismatch.\r\n") {
				t.Fatalf("server response = %q, must not contain Protocol mismatch", response)
			}

			select {
			case err := <-srvErrCh:
				if err == nil {
					t.Errorf("NewServerConn: expected error, got nil")
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("NewServerConn did not return within timeout")
			}
		})
	}
}
