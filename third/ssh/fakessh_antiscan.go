// Copyright 2025 The Fakessh Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file is a fakessh-local addition to the vendored x/crypto/ssh package.
// It implements opt-in OpenSSH-compatible AntiScan behavior: pre-KEX
// plaintext packets use NULL padding, corrupt packets before KEX write a bare
// "Packet corrupt\x00" line, and corrupt packets after KEX send a framed
// SSH_MSG_DISCONNECT. Default vendored behavior is unchanged when
// ServerConfig.AsOpenSSH is false. See third/AGENTS.md for upgrade notes.

package ssh

import (
	"errors"
	"io"
	"strconv"
	"strings"
)

// errPacketCorrupt is the sentinel used by fakessh-local packet paths to mark
// a corrupt packet that should trigger an OpenSSH-style "Packet corrupt"
// response. It is recognized by fakesshIsCorruptPacketError.
var errPacketCorrupt = errors.New("ssh: packet corrupt")

type fakesshAuthenticatedShortPacketError struct {
	message string
}

func (e fakesshAuthenticatedShortPacketError) Error() string { return e.message }

func fakesshAuthenticatedShortPacket(plain []byte) error {
	if len(plain) >= 5 {
		return nil
	}
	if len(plain) == 0 {
		return fakesshAuthenticatedShortPacketError{message: "ssh: empty packet"}
	}
	padding := plain[0]
	if padding < 4 {
		return fakesshAuthenticatedShortPacketError{message: "ssh: illegal padding " + strconv.Itoa(int(padding))}
	}
	return fakesshAuthenticatedShortPacketError{message: "ssh: padding " + strconv.Itoa(int(padding)) + " too large"}
}

// enableOpenSSHCompat toggles OpenSSH-compatible AntiScan behavior on the
// transport. When enabled, plaintext (pre-KEX) stream-cipher packets use NULL
// padding instead of random padding, matching OpenSSH's behavior before the
// first key exchange. The flag is applied only to the current pre-KEX writer
// streamPacketCipher; once the cipher is replaced by a keyed/encrypted one
// after KEX, packets keep normal random padding as required by RFC 4253.
func (t *transport) enableOpenSSHCompat(enabled bool) {
	t.asOpenSSH = enabled
	if stream, ok := t.writer.packetCipher.(*streamPacketCipher); ok {
		stream.openSSHPadding = enabled
	}
	if stream, ok := t.reader.packetCipher.(*streamPacketCipher); ok {
		stream.openSSHPlaintextCorruptPadding = enabled
	}
}

func fakesshSetOpenSSHMinPadding(cipher packetCipher, enabled bool) {
	if stream, ok := cipher.(*streamPacketCipher); ok {
		stream.openSSHMinPadding = enabled
	}
}

// fakesshParseOpenSSHProtocolVersion validates the SSH identification string
// shape that OpenSSH requires before applying protocol-major compatibility. A
// valid line must be SSH-<major>.<minor>-<non-empty software/version suffix>.
func fakesshParseOpenSSHProtocolVersion(version []byte) (major, minor int, ok bool) {
	rest, ok := strings.CutPrefix(string(version), "SSH-")
	if !ok {
		return 0, 0, false
	}
	major, rest, ok = fakesshScanOpenSSHInt(rest)
	if !ok || !strings.HasPrefix(rest, ".") {
		return 0, 0, false
	}
	rest = rest[1:]
	minor, rest, ok = fakesshScanOpenSSHInt(rest)
	if !ok || !strings.HasPrefix(rest, "-") {
		return 0, 0, false
	}
	if rest[1:] == "" {
		return 0, 0, false
	}
	return major, minor, true
}

func fakesshScanOpenSSHInt(input string) (value int, rest string, ok bool) {
	start := 0
	for start < len(input) && fakesshIsOpenSSHScanSpace(input[start]) {
		start++
	}
	end := start
	if end < len(input) && (input[end] == '+' || input[end] == '-') {
		end++
	}
	digitsStart := end
	for end < len(input) && input[end] >= '0' && input[end] <= '9' {
		end++
	}
	if end == digitsStart {
		return 0, "", false
	}
	value, err := strconv.Atoi(input[start:end])
	if err != nil {
		return 0, "", false
	}
	return value, input[end:], true
}

func fakesshIsOpenSSHScanSpace(c byte) bool {
	switch c {
	case ' ', '\f', '\n', '\r', '\t', '\v':
		return true
	default:
		return false
	}
}

// fakesshOpenSSHProtocolMismatch mirrors OpenSSH's protocol-major check during
// banner exchange: SSH-2.x is accepted, SSH-1.99 is accepted as SSH2-compatible,
// and every other major version is rejected.
func fakesshOpenSSHProtocolMismatch(major, minor int) bool {
	if major == 2 {
		return false
	}
	return major != 1 || minor != 99
}

// fillPadding replaces the padding bytes for a streamPacketCipher. When
// OpenSSH-compat NULL padding is enabled and the cipher is still in plaintext
// (no MAC, noneCipher), padding is cleared to zero instead of being filled
// with random bytes - mirroring OpenSSH's pre-KEX behavior. In all other
// cases (encrypted, MAC-protected, or compat disabled) padding is filled with
// cryptographically random bytes as required by RFC 4253 section 6.
func (s *streamPacketCipher) fillPadding(rand io.Reader, padding []byte) error {
	if s.openSSHPadding && s.mac == nil {
		if _, ok := s.cipher.(noneCipher); ok {
			clear(padding)
			return nil
		}
	}
	_, err := io.ReadFull(rand, padding)
	return err
}

// writePacketCorrupt emits an OpenSSH-style corrupt-packet response. Before
// the first key exchange (plaintext stream cipher with a raw connection
// available), it writes the bare line "Packet corrupt\x00" directly to the raw
// connection - exactly as OpenSSH does for pre-KEX corruption. After KEX, it
// sends a framed SSH_MSG_DISCONNECT with reason SSH_DISCONNECT_PROTOCOL_ERROR
// (2) and message "Packet corrupt" through the encrypted transport.
func (t *transport) writePacketCorrupt() {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	if t.writer.isPlaintext() && t.rawConn != nil {
		_, _ = t.rawConn.Write([]byte("Packet corrupt\x00"))
		return
	}

	_ = t.writePacketLocked(Marshal(&disconnectMsg{Reason: 2, Message: "Packet corrupt"}))
}

// writePacketCorruptedPadlen emits OpenSSH's padlen-specific corrupt-packet
// disconnect for packets that authenticate successfully but decrypt to a
// padding length below SSH's required minimum of 4 bytes.
func (t *transport) writePacketCorruptedPadlen(padlen int) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	_ = t.writePacketLocked(Marshal(&disconnectMsg{
		Reason:  2,
		Message: "Corrupted padlen " + strconv.Itoa(padlen) + " on input.",
	}))
}

// isPlaintext reports whether the connectionState is still in the pre-KEX
// plaintext state: a streamPacketCipher with no MAC and a noneCipher. This
// matches the initial state set up by newTransport.
func (s *connectionState) isPlaintext() bool {
	stream, ok := s.packetCipher.(*streamPacketCipher)
	if !ok || stream.mac != nil {
		return false
	}
	_, ok = stream.cipher.(noneCipher)
	return ok
}

// fakesshIsCorruptPacketError reports whether err indicates a corrupt inbound
// packet that should trigger an OpenSSH-style "Packet corrupt" response under
// AntiScan compatibility. It recognizes:
//   - errPacketCorrupt (fakessh-local sentinel)
//   - cbcError (CBC verification failures)
//   - authenticated packets below OpenSSH's minimum packet size
//   - specific length/MAC/tag errors emitted by stream, GCM, CBC and
//     chacha20-poly1305 cipher read paths.
func fakesshIsCorruptPacketError(err error) bool {
	var short fakesshAuthenticatedShortPacketError
	if errors.As(err, &short) {
		return true
	}
	if errors.Is(err, errPacketCorrupt) {
		return true
	}
	if _, ok := err.(cbcError); ok {
		return true
	}

	message := err.Error()
	switch message {
	case "ssh: invalid packet length, packet too small",
		"ssh: invalid packet length, packet too large",
		"ssh: max packet length exceeded",
		"ssh: MAC failure",
		"cipher: message authentication failed":
		return true
	}

	return false
}

// fakesshCorruptedPadlen extracts the invalid SSH padding length from the
// cipher errors that correspond to OpenSSH's padlen-specific disconnect. OpenSSH
// emits that disconnect only for padlen < 4; oversized padlen errors are not
// special-cased here.
func fakesshCorruptedPadlen(err error) (int, bool) {
	var short fakesshAuthenticatedShortPacketError
	if errors.As(err, &short) {
		return 0, false
	}

	message := err.Error()
	if padlen, ok := strings.CutPrefix(message, "ssh: illegal padding "); ok {
		value, err := strconv.Atoi(padlen)
		return value, err == nil
	}
	return 0, false
}
