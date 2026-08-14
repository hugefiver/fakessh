package main

import (
	"math/rand/v2"
	"strconv"
	"strings"
	"time"

	"github.com/hugefiver/fakessh/conf"
	"github.com/hugefiver/fakessh/third/ssh"
)

// openSSH93KexAlgos is the key exchange algorithm preference list from
// OpenSSH 9.3 (sshd -Q kex / KexAlgorithms default), filtered to algorithms
// implemented by the vendored ssh library or registered by fakessh local
// additions. Algorithms that OpenSSH 9.3 ships but the vendored library does
// not implement (e.g. sntrup761x25519-sha512@openssh.com) are intentionally
// omitted. The list includes diffie-hellman-group18-sha512, registered by
// third/ssh/fakessh_algorithms.go (referenced here via ssh.KeyExchangeDH18SHA512).
var openSSH93KexAlgos = []string{
	"curve25519-sha256",
	"ecdh-sha2-nistp256",
	"ecdh-sha2-nistp384",
	"ecdh-sha2-nistp521",
	"diffie-hellman-group-exchange-sha256",
	"diffie-hellman-group16-sha512",
	ssh.KeyExchangeDH18SHA512,
	"diffie-hellman-group14-sha256",
}

// openSSH93Ciphers is the cipher preference list from OpenSSH 9.3, filtered to
// algorithms implemented by the vendored ssh library. All of OpenSSH 9.3's
// default ciphers are implemented, so the list matches OpenSSH 9.3 as-is.
var openSSH93Ciphers = []string{
	"chacha20-poly1305@openssh.com",
	"aes128-ctr",
	"aes192-ctr",
	"aes256-ctr",
	"aes128-gcm@openssh.com",
	"aes256-gcm@openssh.com",
}

// openSSH93MACs is the MAC preference list from OpenSSH 9.3, filtered to
// algorithms implemented by the vendored ssh library or registered by fakessh
// local additions. Algorithms that OpenSSH 9.3 ships but the vendored library
// does not implement (e.g. umac-64-etm@openssh.com, umac-128-etm@openssh.com)
// are intentionally omitted. The list includes hmac-sha1-etm@openssh.com,
// registered by third/ssh/fakessh_algorithms.go (referenced here via
// ssh.HMACSHA1ETM).
var openSSH93MACs = []string{
	"hmac-sha2-256-etm@openssh.com",
	"hmac-sha2-512-etm@openssh.com",
	ssh.HMACSHA1ETM,
	"hmac-sha2-256",
	"hmac-sha2-512",
	"hmac-sha1",
}

// applyOpenSSH93Algorithms sets the KeyExchanges, Ciphers and MACs fields of an
// ssh.Config to the OpenSSH 9.3 preference lists (filtered to algorithms
// implemented by the vendored ssh library / fakessh local additions) so that
// fakessh advertises the same algorithm lists as a real OpenSSH 9.3 server,
// within what the vendored library supports, when AntiScan mode is on.
func applyOpenSSH93Algorithms(config *ssh.Config) {
	config.KeyExchanges = openSSH93KexAlgos
	config.Ciphers = openSSH93Ciphers
	config.MACs = openSSH93MACs
}

// isOpenSSHCompatClientVersion validates a client identification string using
// the same protocol-version compatibility that OpenSSH applies during banner
// exchange: SSH-2.x is accepted, SSH-1.99 is accepted as SSH2-compatible, and
// other major versions are rejected. The string must still contain a non-empty
// software suffix after the protocol version.
func isOpenSSHCompatClientVersion(version []byte) bool {
	rest, ok := strings.CutPrefix(string(version), "SSH-")
	if !ok {
		return false
	}
	major, rest, ok := scanOpenSSHProtocolInt(rest)
	if !ok || !strings.HasPrefix(rest, ".") {
		return false
	}
	rest = rest[1:]
	minor, rest, ok := scanOpenSSHProtocolInt(rest)
	if !ok || !strings.HasPrefix(rest, "-") || rest[1:] == "" {
		return false
	}
	if major == 2 {
		return true
	}
	return major == 1 && minor == 99
}

func scanOpenSSHProtocolInt(input string) (value int, rest string, ok bool) {
	start := 0
	for start < len(input) && isOpenSSHScanSpace(input[start]) {
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

func isOpenSSHScanSpace(c byte) bool {
	switch c {
	case ' ', '\f', '\n', '\r', '\t', '\v':
		return true
	default:
		return false
	}
}

// sleepAuthDelay sleeps for the configured auth delay. When Delay <= 0 it
// returns immediately; when Deviation <= 0 it sleeps the configured Delay;
// otherwise it sleeps a random duration in [max(0, delay-deviation),
// delay+deviation). Both successful and failed password auth attempts call this
// so that timing-based scanners cannot distinguish success from failure by
// response latency.
func sleepAuthDelay(c *conf.AppConfig) {
	delay := c.Server.Delay
	if delay <= 0 {
		return
	}
	m := c.Server.Deviation
	if m <= 0 {
		time.Sleep(time.Millisecond * time.Duration(delay))
		return
	}
	start := delay - m
	end := delay + m
	if start < 0 {
		start = 0
	}
	time.Sleep(time.Millisecond * time.Duration(start+rand.IntN(end-start)))
}

// rejectExtraChannel rejects non-session and surplus session channels using
// OpenSSH-style rejection reasons: unknown channel types get
// UnknownChannelType/"unknown channel type", and extra session channels (when
// fakessh already has its one active session) get
// ResourceShortage/"resource shortage". This matches the reasons/messages a
// real OpenSSH server returns, instead of the previous Prohibited/"funck off".
func rejectExtraChannel(ch ssh.NewChannel) {
	if ch.ChannelType() != "session" {
		ch.Reject(ssh.UnknownChannelType, "unknown channel type")
		return
	}
	ch.Reject(ssh.ResourceShortage, "resource shortage")
}
