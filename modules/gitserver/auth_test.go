//go:build !no_gitserver
// +build !no_gitserver

package gitserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/hugefiver/fakessh/third/ssh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeConnMetadata is a minimal ssh.ConnMetadata for gitserver tests.
type fakeConnMetadata struct{ user string }

func (f fakeConnMetadata) User() string          { return f.user }
func (f fakeConnMetadata) SessionID() []byte     { return nil }
func (f fakeConnMetadata) ClientVersion() []byte { return []byte("SSH-2.0-test") }
func (f fakeConnMetadata) ServerVersion() []byte { return []byte("SSH-2.0-test") }
func (f fakeConnMetadata) RemoteAddr() net.Addr  { return fakeAddr("remote") }
func (f fakeConnMetadata) LocalAddr() net.Addr   { return fakeAddr("local") }

type fakeAddr string

func (a fakeAddr) Network() string { return string(a) }
func (a fakeAddr) String() string  { return string(a) }

// genEd25519Signer generates a fresh ed25519 keypair and returns the SSH
// signer and the marshaled authorized_keys line (single line, no trailing
// newline) for the public key.
func genEd25519Signer(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromSigner(priv)
	require.NoError(t, err)
	return signer, string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
}

// writeAuthorizedKeys writes lines to a temp authorized_keys file and returns
// its path.
func writeAuthorizedKeys(t *testing.T, lines ...string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "authorized_keys")
	content := ""
	for _, ln := range lines {
		content += ln + "\n"
	}
	require.NoError(t, os.WriteFile(p, []byte(content), 0600))
	return p
}

// newTestServer builds a Server from cfg. When cfg.AuthorizedKeys is empty it
// points at an empty temp file so NewServer does not fail on a missing file
// when WatchKeys=false.
func newTestServer(t *testing.T, cfg *Config) *Server {
	t.Helper()
	if cfg.AuthorizedKeys == "" {
		dir := t.TempDir()
		p := filepath.Join(dir, "authorized_keys")
		require.NoError(t, os.WriteFile(p, []byte(""), 0600))
		cfg.AuthorizedKeys = p
	}
	s, err := NewServer(cfg)
	require.NoError(t, err)
	return s
}

// permissionsForFingerprint returns an *ssh.Permissions carrying the same
// extension map used by PublicKeyCallback. It is used to exercise
// IsGitPermission and GitKeyFingerprint without driving a full SSH handshake.
func permissionsForFingerprint(fp string) *ssh.Permissions {
	return &ssh.Permissions{
		Extensions: map[string]string{
			permExtGitServer:      "1",
			permExtKeyFingerprint: fp,
			permExtKeyComment:     "test-comment",
		},
	}
}

// TestPublicKeyCallbackAcceptsConfiguredSSHUserAndKey verifies that a key
// present in authorized_keys authenticates the configured SSH user, that the
// returned permissions carry the gitserver marker and the SHA256 fingerprint,
// and that IsGitPermission / GitKeyFingerprint decode the permissions.
func TestPublicKeyCallbackAcceptsConfiguredSSHUserAndKey(t *testing.T) {
	t.Parallel()

	signer, line := genEd25519Signer(t)
	akPath := writeAuthorizedKeys(t, line)

	cfg := &Config{
		Enable:         true,
		SSHUser:        "git",
		AuthorizedKeys: akPath,
	}
	srv := newTestServer(t, cfg)

	perms, err := srv.PublicKeyCallback(fakeConnMetadata{user: "git"}, signer.PublicKey())
	require.NoError(t, err)
	require.NotNil(t, perms)

	expectedFP := ssh.FingerprintSHA256(signer.PublicKey())
	assert.Equal(t, expectedFP, perms.Extensions[permExtKeyFingerprint])
	assert.Equal(t, "1", perms.Extensions[permExtGitServer])

	assert.True(t, IsGitPermission(perms))
	assert.Equal(t, expectedFP, GitKeyFingerprint(perms))

	// Nil perms must not crash the helpers.
	assert.False(t, IsGitPermission(nil))
	assert.Equal(t, "", GitKeyFingerprint(nil))
}

// TestPublicKeyCallbackRejectsWrongUserAndUnknownKey verifies that the wrong
// SSH user and an unknown key are both rejected.
func TestPublicKeyCallbackRejectsWrongUserAndUnknownKey(t *testing.T) {
	t.Parallel()

	knownSigner, line := genEd25519Signer(t)
	unknownSigner, _ := genEd25519Signer(t)
	akPath := writeAuthorizedKeys(t, line)

	cfg := &Config{
		Enable:         true,
		SSHUser:        "git",
		AuthorizedKeys: akPath,
	}
	srv := newTestServer(t, cfg)

	// Correct key, wrong user.
	_, err := srv.PublicKeyCallback(fakeConnMetadata{user: "root"}, knownSigner.PublicKey())
	assert.Error(t, err)

	// Correct user, unknown key.
	_, err = srv.PublicKeyCallback(fakeConnMetadata{user: "git"}, unknownSigner.PublicKey())
	assert.Error(t, err)
}

// TestPublicKeyCallbackRejectsAuthorizedKeysOptions verifies that an
// authorized_keys line carrying OpenSSH options (e.g.
// `command="git-shell" ssh-ed25519 AAAA...`) causes NewServer to fail closed
// rather than silently stripping the options.
func TestPublicKeyCallbackRejectsAuthorizedKeysOptions(t *testing.T) {
	t.Parallel()

	_, line := genEd25519Signer(t)
	// Trim trailing newline from MarshalAuthorizedKey so the option prefix
	// and the key line form a single line.
	line = sshLineStrip(line)
	optionLine := `command="git-shell" ` + line

	dir := t.TempDir()
	p := filepath.Join(dir, "authorized_keys")
	require.NoError(t, os.WriteFile(p, []byte(optionLine+"\n"), 0600))

	cfg := &Config{
		Enable:         true,
		SSHUser:        "git",
		AuthorizedKeys: p,
	}

	_, err := NewServer(cfg)
	assert.Error(t, err, "option-bearing authorized_keys line must fail init")
}

// TestPublicKeyCallbackWatchKeysReloads verifies that when WatchKeys=true the
// server picks up newly-added keys on the next PublicKeyCallback without a
// restart, and that an initial empty file is acceptable at construction time.
func TestPublicKeyCallbackWatchKeysReloads(t *testing.T) {
	t.Parallel()

	// Parallel tests share the process-wide file watcher? No, NewServer
	// does not register a real fsnotify watcher here; WatchKeys=true just
	// means "reload on every callback". So parallelism is safe.
	akPath := writeAuthorizedKeys(t)

	cfg := &Config{
		Enable:         true,
		SSHUser:        "git",
		AuthorizedKeys: akPath,
		WatchKeys:      true,
	}
	srv, err := NewServer(cfg)
	require.NoError(t, err)

	signer, line := genEd25519Signer(t)

	// Initially the key is unknown.
	_, err = srv.PublicKeyCallback(fakeConnMetadata{user: "git"}, signer.PublicKey())
	assert.Error(t, err, "key not yet in authorized_keys must be rejected")

	// Append the key to the file.
	f, err := os.OpenFile(akPath, os.O_APPEND|os.O_WRONLY, 0600)
	require.NoError(t, err)
	_, err = f.WriteString(line + "\n")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	// Reload happens on next callback.
	perms, err := srv.PublicKeyCallback(fakeConnMetadata{user: "git"}, signer.PublicKey())
	require.NoError(t, err)
	require.NotNil(t, perms)
	assert.Equal(t, ssh.FingerprintSHA256(signer.PublicKey()), perms.Extensions[permExtKeyFingerprint])
}

// sshLineStrip removes a trailing newline from a single authorized_keys line
// produced by ssh.MarshalAuthorizedKey. It exists as a tiny helper so the
// option-prefix tests read more naturally.
func sshLineStrip(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
