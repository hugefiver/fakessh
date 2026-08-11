//go:build !no_gitserver
// +build !no_gitserver

package gitserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hugefiver/fakessh/third/ssh"
)

// Permission extension keys used to carry gitserver auth results from
// PublicKeyCallback into the session-handling layer. They are unexported
// because callers should use IsGitPermission / GitKeyFingerprint instead of
// reading the map directly.
const (
	permExtGitServer      = "fakessh.gitserver"
	permExtKeyFingerprint = "fakessh.gitserver.key_fingerprint"
	permExtKeyComment     = "fakessh.gitserver.key_comment"
)

// authorizedKeyEntry is the cached record for a single parsed authorized_keys
// entry. keyBytes is the marshaled SSH public key blob (as returned by
// ssh.PublicKey.Marshal) and is compared byte-for-byte during auth.
type authorizedKeyEntry struct {
	keyBytes []byte
	comment  string
}

// Server is the gitserver authentication and session-routing core. It owns a
// normalized copy of the gitserver Config, an in-memory map of authorized
// public keys keyed by SHA256 fingerprint, an in-memory map of configured
// repositories keyed by normalized path, and a mutex guarding both maps.
//
// runBackend is the pluggable backend dispatch hook invoked by HandleSession
// after a client's exec request has been parsed and authorized. NewServer
// installs defaultBackendRunner, which dispatches to serveLocal (local
// backend) or serveSSH (ssh backend). Tests may override runBackend to drive
// deterministic behavior.
type Server struct {
	config Config

	mu       sync.RWMutex
	keysByFP map[string]authorizedKeyEntry
	repos    map[string]RepositoryConfig

	// localSlots caps the number of concurrent local git-shell
	// processes. It is a buffered channel of size
	// config.MaxGitShellProcesses when that value is > 0, or nil for
	// unlimited. nil means acquireLocalSlot is always a no-op success.
	localSlots chan struct{}

	// preExecTimeout bounds how long an authenticated git session may keep a
	// session channel open before sending the authorized exec request. It is a
	// per-Server field so same-package tests can shorten it without mutating a
	// process-wide timeout.
	preExecTimeout time.Duration

	// runBackend dispatches a single authorized Git request to the configured
	// backend. It is called with the connection context, the authorized
	// Request (BackendPath populated), the GIT_PROTOCOL env value ("" if the
	// client did not send one), and the live ssh.Channel. The returned error
	// is mapped to an exit-status sent to the client (nil -> 0, non-nil -> 1
	// in this task; later tasks may refine the mapping).
	runBackend backendRunner
}

// backendRunner is the signature of the backend dispatch hook installed on
// Server.runBackend and invoked by HandleSession once an exec request has been
// parsed and authorized.
//
//   - ctx is the connection/session context; cancellation must propagate to
//     the backend so that connection teardown interrupts long-running
//     git-upload-pack / git-receive-pack transfers.
//   - srv is the owning Server (so backends can reach ResolveLocalRepo and
//     config without a global).
//   - req is the fully authorized Request with BackendPath populated.
//   - gitProtocol is the value of the GIT_PROTOCOL env request sent by the
//     client, or "" when the client sent none. Only GIT_PROTOCOL=version=2 is
//     accepted by HandleSession; other values are rejected before the backend
//     runs.
//   - channel is the live ssh.Channel; the backend owns stdout/stderr/stdin
//     framing and must NOT close it (HandleSession closes the channel after
//     sending exit-status).
type backendRunner func(ctx context.Context, srv *Server, req Request, gitProtocol string, channel ssh.Channel) error

// errLocalSlotsBusy is returned by the local backend when RefuseWhenBusy is
// true and the process-limit slot cannot be acquired without waiting.
var errLocalSlotsBusy = errors.New("gitserver: local git-shell process limit reached")

// errUnknownBackend is returned by the default backend runner when
// config.Backend is neither BackendLocal nor BackendSSH. CheckAndFillConfig
// already rejects unknown backends at config time, so this is a fail-closed
// defense against a Server constructed without going through NewServer.
var errUnknownBackend = errors.New("gitserver: unknown backend")

// defaultBackendRunner is installed by NewServer. It dispatches to the local
// or ssh backend based on srv.config.Backend.
func defaultBackendRunner(ctx context.Context, srv *Server, req Request, gitProtocol string, channel ssh.Channel) error {
	switch srv.config.Backend {
	case BackendLocal:
		return srv.serveLocal(ctx, req, gitProtocol, channel)
	case BackendSSH:
		return srv.serveSSH(ctx, req, gitProtocol, channel)
	default:
		return errUnknownBackend
	}
}

// acquireLocalSlot reserves one of the MaxGitShellProcesses slots. When
// MaxGitShellProcesses is 0 (unlimited) it returns true immediately. When
// RefuseWhenBusy is true it is non-blocking and returns errLocalSlotsBusy
// when no slot is available. Otherwise it blocks until a slot is available
// or ctx is cancelled.
//
// The slot accounting uses a buffered channel of size MaxGitShellProcesses
// that starts empty: sending a token acquires a slot (blocks when the
// channel is full), and receiving a token releases it. This avoids an
// initialization loop that would fill the channel with tokens.
func (s *Server) acquireLocalSlot(ctx context.Context) (bool, error) {
	if s.localSlots == nil {
		return true, nil
	}
	if s.config.RefuseWhenBusy {
		select {
		case s.localSlots <- struct{}{}:
			return true, nil
		default:
			return false, errLocalSlotsBusy
		}
	}
	select {
	case s.localSlots <- struct{}{}:
		return true, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

// releaseLocalSlot returns one slot to the pool. It is safe to call when
// localSlots is nil (unlimited): the method is a no-op in that case.
func (s *Server) releaseLocalSlot() {
	if s.localSlots != nil {
		select {
		case <-s.localSlots:
		default:
			// The channel is empty, which means the slot was never
			// acquired or was already returned. Drop silently to
			// avoid blocking; this is a defensive no-op.
		}
	}
}

// tryAcquireLocalSlot is a non-blocking test helper that reports whether a
// slot is available right now. When localSlots is nil (unlimited) it always
// returns true. It exists so package tests can exercise the slot accounting
// without driving a full backend.
func (s *Server) tryAcquireLocalSlot() bool {
	if s.localSlots == nil {
		return true
	}
	select {
	case s.localSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

// NewServer validates and normalizes c, then builds a Server. When WatchKeys
// is false the authorized_keys file is loaded immediately and any parse error
// or unreadable file is fatal (denies init). When WatchKeys is true the file
// is loaded lazily on each PublicKeyCallback so that operators can fix the
// file without restarting; a missing or unreadable file at callback time
// returns an error that denies the auth attempt.
//
// NewServer stores a copy of c after CheckAndFillConfig mutates it in place.
// Callers may continue to use c afterwards without affecting the Server.
func NewServer(c *Config) (*Server, error) {
	if c == nil {
		return nil, fmt.Errorf("gitserver: NewServer called with nil config")
	}

	if err := CheckAndFillConfig(c); err != nil {
		return nil, err
	}

	// Copy the now-normalized config so later mutation of the caller's struct
	// cannot desync the Server. Slices are copied shallowly; the gitserver
	// does not mutate RepositoryConfig slices after NewServer.
	cfgCopy := *c

	// Build the repository lookup map from the now-normalized
	// cfgCopy.Repositories. CheckAndFillConfig has already normalized each
	// Path/BackendPath, trimmed ACL fingerprints, and rejected duplicates,
	// so this map is keyed by the canonical normalized path. An empty
	// repository list yields an empty (non-nil) map, which Authorize treats
	// as deny-all.
	repos := make(map[string]RepositoryConfig, len(cfgCopy.Repositories))
	for _, r := range cfgCopy.Repositories {
		repos[r.Path] = r
	}

	s := &Server{
		config:         cfgCopy,
		keysByFP:       make(map[string]authorizedKeyEntry),
		repos:          repos,
		preExecTimeout: defaultPreExecTimeout,
		runBackend:     defaultBackendRunner,
	}

	if cfgCopy.MaxGitShellProcesses > 0 {
		s.localSlots = make(chan struct{}, cfgCopy.MaxGitShellProcesses)
	}

	if !cfgCopy.WatchKeys {
		if err := s.loadAuthorizedKeys(); err != nil {
			return nil, err
		}
	}

	return s, nil
}

// PublicKeyCallback is the ssh.ServerConfig.PublicKeyCallback entry point.
// It accepts the connection only when conn.User() == s.config.SSHUser and the
// offered key matches an authorized_keys entry by fingerprint AND by marshaled
// key bytes. On success it returns *ssh.Permissions with gitserver extension
// keys set; on failure it returns nil, errAuth.
//
// When WatchKeys is true the authorized_keys file is reloaded on every call.
// A reload failure denies the attempt with the underlying error (not errAuth)
// so operators can distinguish infra errors from rejected keys.
func (s *Server) PublicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	if conn.User() != s.config.SSHUser {
		return nil, errAuth
	}

	fp := ssh.FingerprintSHA256(key)
	keyBytes := key.Marshal()

	s.mu.RLock()
	if s.config.WatchKeys {
		s.mu.RUnlock()
		if err := s.reloadAuthorizedKeys(); err != nil {
			return nil, fmt.Errorf("gitserver: reload authorized_keys: %w", err)
		}
		s.mu.RLock()
	}
	entry, ok := s.keysByFP[fp]
	s.mu.RUnlock()

	if !ok {
		return nil, errAuth
	}
	if !bytes.Equal(entry.keyBytes, keyBytes) {
		// Fingerprint collision with a different key blob: deny closed.
		return nil, errAuth
	}

	return &ssh.Permissions{
		Extensions: map[string]string{
			permExtGitServer:      "1",
			permExtKeyFingerprint: fp,
			permExtKeyComment:     entry.comment,
		},
	}, nil
}

// IsGitPermission reports whether perms was produced by the gitserver
// PublicKeyCallback. It returns false for nil perms.
func IsGitPermission(perms *ssh.Permissions) bool {
	if perms == nil {
		return false
	}
	if perms.Extensions == nil {
		return false
	}
	v, ok := perms.Extensions[permExtGitServer]
	return ok && v != ""
}

// GitKeyFingerprint extracts the SHA256 fingerprint recorded by
// PublicKeyCallback from perms, or "" if perms is not a gitserver permission.
func GitKeyFingerprint(perms *ssh.Permissions) string {
	if perms == nil || perms.Extensions == nil {
		return ""
	}
	return perms.Extensions[permExtKeyFingerprint]
}

// loadAuthorizedKeys reads, parses, and stores the authorized_keys file. It
// replaces any existing in-memory map atomically. It is fail-closed: any
// unreadable file, unparseable line, or option-bearing line is an error.
func (s *Server) loadAuthorizedKeys() error {
	path := s.config.AuthorizedKeys
	if path == "" {
		return fmt.Errorf("gitserver: authorized_keys path is empty")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("gitserver: read authorized_keys %q: %w", path, err)
	}

	entries, err := parseAuthorizedKeys(data)
	if err != nil {
		return fmt.Errorf("gitserver: parse authorized_keys %q: %w", path, err)
	}

	s.mu.Lock()
	s.keysByFP = entries
	s.mu.Unlock()
	return nil
}

// reloadAuthorizedKeys is the WatchKeys=true path. It is a thin wrapper that
// re-reads the file. Reloading is serialized by the write mutex taken inside
// loadAuthorizedKeys; concurrent PublicKeyCallback callers may each trigger a
// reload, which is acceptable because the operation is idempotent.
func (s *Server) reloadAuthorizedKeys() error {
	return s.loadAuthorizedKeys()
}

// parseAuthorizedKeys parses the contents of an authorized_keys file into a
// fingerprint -> entry map. It is fail-closed:
//
//   - Empty lines and lines beginning with '#' are skipped.
//   - Each remaining line must be a single authorized_keys entry consisting
//     of "<type> <base64> [comment]". OpenSSH options (e.g.
//     `command="git-shell" ssh-ed25519 AAAA...`) are rejected with an error
//     because this implementation does not honor options and silently
//     stripping them would grant unintended access.
//   - Duplicate fingerprints with identical key bytes are de-duplicated
//     (harmless). Duplicate fingerprints with different key bytes are a
//     fail-closed error.
func parseAuthorizedKeys(data []byte) (map[string]authorizedKeyEntry, error) {
	out := make(map[string]authorizedKeyEntry)

	for ln, raw := range bytes.Split(data, []byte("\n")) {
		// Normalize trailing CR so CRLF files parse the same as LF files.
		raw = bytes.TrimRight(raw, "\r")
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 || trimmed[0] == '#' {
			continue
		}

		// ParseAuthorizedKey accepts a single line (no trailing newline) and
		// returns (key, comment, options, rest, err). When options is non-nil
		// the line carried OpenSSH options that we refuse to honor.
		pubKey, comment, options, rest, err := ssh.ParseAuthorizedKey(raw)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", ln+1, err)
		}
		if pubKey == nil {
			// Should not happen when err == nil, but guard defensively.
			return nil, fmt.Errorf("line %d: no key parsed", ln+1)
		}
		if len(options) > 0 {
			return nil, fmt.Errorf("line %d: authorized_keys options are not supported (line starts with %q)", ln+1, options[0])
		}
		// rest must be empty or whitespace-only because we passed a single
		// line. If it contains anything else the line had extra trailing
		// entries, which we treat as a parse error.
		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("line %d: unexpected trailing content after key", ln+1)
		}

		fp := ssh.FingerprintSHA256(pubKey)
		keyBytes := pubKey.Marshal()

		if existing, ok := out[fp]; ok {
			if !bytes.Equal(existing.keyBytes, keyBytes) {
				return nil, fmt.Errorf("line %d: duplicate fingerprint %q with different key bytes", ln+1, fp)
			}
			// Same fingerprint + same key bytes: keep first comment.
			continue
		}

		// Copy keyBytes so the caller cannot mutate the parsed slice via the
		// map. Marshal() already returns a fresh slice, but the copy makes
		// that guarantee explicit and robust against future upstream changes.
		kb := make([]byte, len(keyBytes))
		copy(kb, keyBytes)

		out[fp] = authorizedKeyEntry{
			keyBytes: kb,
			comment:  strings.TrimSpace(comment),
		}
	}

	return out, nil
}

// errAuth is the sentinel returned by PublicKeyCallback for rejected keys.
// It mirrors the package-level errAuth in main.go but is local to gitserver
// so the module does not depend on package main.
var errAuth = fmt.Errorf("gitserver: auth failed")
