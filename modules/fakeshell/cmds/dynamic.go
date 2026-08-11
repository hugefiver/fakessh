package cmds

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Caps on per-session dynamic metadata. These keep a single session's dynamic
// store bounded so an attacker cannot exhaust server memory by touching an
// unbounded number of distinct paths or recording huge previews. The values
// are deliberately small: dynamic state is metadata-only, never file content.
const (
	// MaxDynamicEntries bounds the number of distinct dynamic entries a single
	// session may record. Updates to an existing path do not count against the
	// cap; only new unique paths do. A 257th unique path is rejected.
	MaxDynamicEntries = 256

	// MaxDynamicPathLen bounds the cleaned fake-absolute path length stored as
	// the entry key. Longer paths are rejected before any allocation.
	MaxDynamicPathLen = 512

	// MaxDynamicPreviewBytes bounds the number of preview bytes stored per
	// entry. A longer preview is truncated to this length and deep-copied so
	// the store never aliases the caller's slice.
	MaxDynamicPreviewBytes = 256
)

// validDynamicKinds is the set of entry kinds the store accepts. "file" is the
// only kind produced by touch today; "dir" is permitted so future commands can
// record directory metadata without changing the schema. Unknown kinds are
// rejected to prevent callers from smuggling arbitrary type strings.
var validDynamicKinds = map[string]struct{}{
	"file": {},
	"dir":  {},
}

// DynamicEntry is a single metadata-only record describing a path the session
// has touched or otherwise mutated. It deliberately stores no file content:
// Preview is a tiny (<= MaxDynamicPreviewBytes) hint and Size is an
// attacker-controlled number recorded for realism, never trusted for host
// allocation or access.
type DynamicEntry struct {
	Path      string
	Kind      string
	Size      int64
	Preview   []byte
	SHA256    string
	UpdatedAt time.Time
}

// DynamicStore holds per-session dynamic metadata. It is owned by exactly one
// CommandRunner and is never shared across sessions; cross-session isolation is
// enforced because each NewCommandRunner creates its own store.
//
// mu guards both the entries map and the order slice. order preserves insertion
// order so Entries() is deterministic, which tests and audit logs rely on. The
// store is safe for concurrent use because every method takes mu.
type DynamicStore struct {
	mu      sync.Mutex
	entries map[string]DynamicEntry
	order   []string
}

// NewDynamicStore returns an empty per-session dynamic store.
func NewDynamicStore() *DynamicStore {
	return &DynamicStore{
		entries: make(map[string]DynamicEntry),
	}
}

// Record validates, normalizes and stores a dynamic entry for path.
//
// Validation / normalization:
//
//   - path is normalized through ResolvePath("/", path) so it is always an
//     absolute POSIX fake path confined under "/". Invalid characters, raw
//     ".." segments, backslashes, colons and control bytes are rejected.
//   - the cleaned path length must be <= MaxDynamicPathLen.
//   - kind must be a known kind (at least "file" or "dir"). Empty/unknown
//     kinds are rejected.
//   - size must be non-negative. A negative size is attacker input and is
//     rejected rather than silently clamped.
//   - sha256Hex must be either empty or exactly 64 lowercase hex characters.
//     An uppercase or wrong-length value is normalized to lowercase if valid,
//     or rejected. This keeps the stored hash canonical without trusting the
//     caller's casing.
//   - preview is truncated to MaxDynamicPreviewBytes and deep-copied so the
//     store never aliases the caller's slice; later mutation of the caller's
//     slice cannot affect the stored entry.
//
// Capacity:
//
//   - Updating an existing path (by cleaned key) is always allowed and does
//     not change its insertion position.
//   - Inserting a new unique path when len(entries) >= MaxDynamicEntries is
//     rejected with an error. The store never silently drops oldest entries.
//
// UpdatedAt is set to time.Now().UTC().Truncate(0) so it is non-zero and
// UTC-normalized regardless of the host's local timezone.
//
// The returned DynamicEntry is a deep copy; mutating it cannot affect the
// store.
func (s *DynamicStore) Record(pathArg, kind string, size int64, preview []byte, sha256Hex string) (DynamicEntry, error) {
	cleaned, err := normalizeDynamicPath(pathArg)
	if err != nil {
		return DynamicEntry{}, err
	}

	if err := validateDynamicKind(kind); err != nil {
		return DynamicEntry{}, err
	}

	if size < 0 {
		return DynamicEntry{}, fmt.Errorf("dynamic: negative size %d not allowed", size)
	}

	hash, err := normalizeSHA256(sha256Hex)
	if err != nil {
		return DynamicEntry{}, err
	}

	storedPreview := truncateAndCopyPreview(preview)

	entry := DynamicEntry{
		Path:      cleaned,
		Kind:      kind,
		Size:      size,
		Preview:   storedPreview,
		SHA256:    hash,
		UpdatedAt: time.Now().UTC(),
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.entries[cleaned]; !exists {
		if len(s.entries) >= MaxDynamicEntries {
			return DynamicEntry{}, fmt.Errorf("dynamic: MaxDynamicEntries (%d) reached", MaxDynamicEntries)
		}
		s.order = append(s.order, cleaned)
	}
	s.entries[cleaned] = entry

	// Return a deep copy so callers cannot mutate the stored preview slice.
	return entry.deepCopy(), nil
}

// Entries returns all recorded entries in insertion order. The returned slice
// and every entry's Preview slice are deep copies; mutating them cannot affect
// the store or future calls.
func (s *DynamicStore) Entries() []DynamicEntry {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]DynamicEntry, 0, len(s.order))
	for _, k := range s.order {
		out = append(out, s.entries[k].deepCopy())
	}
	return out
}

// normalizeDynamicPath resolves pathArg from the fake root "/" into an
// absolute POSIX path confined under "/". It also enforces the
// MaxDynamicPathLen cap on the cleaned result. ResolvePath already rejects
// ".." segments, backslashes, colons and control bytes, so this function only
// adds the length cap on top.
func normalizeDynamicPath(pathArg string) (string, error) {
	cleaned, err := ResolvePath("/", pathArg)
	if err != nil {
		return "", fmt.Errorf("dynamic: %w", err)
	}
	if len(cleaned) > MaxDynamicPathLen {
		return "", fmt.Errorf("dynamic: path length %d exceeds MaxDynamicPathLen (%d)", len(cleaned), MaxDynamicPathLen)
	}
	return cleaned, nil
}

func validateDynamicKind(kind string) error {
	if kind == "" {
		return errors.New("dynamic: empty kind not allowed")
	}
	if _, ok := validDynamicKinds[kind]; !ok {
		return fmt.Errorf("dynamic: unknown kind %q", kind)
	}
	return nil
}

// normalizeSHA256 validates sha256Hex. An empty string is allowed (touch
// records no content hash). A non-empty value must decode as 32 bytes of hex;
// it is returned lowercased and canonical.
func normalizeSHA256(sha256Hex string) (string, error) {
	if sha256Hex == "" {
		return "", nil
	}
	lower := strings.ToLower(sha256Hex)
	if len(lower) != 64 {
		return "", fmt.Errorf("dynamic: sha256 length %d, want 64 hex chars", len(lower))
	}
	// Confirm it is valid hex and exactly 32 bytes. We do NOT compute a hash
	// here; we only validate caller-supplied hash form. hex.DecodeString
	// rejects non-hex characters and odd lengths.
	if _, err := hex.DecodeString(lower); err != nil {
		return "", fmt.Errorf("dynamic: invalid sha256 hex: %w", err)
	}
	return lower, nil
}

// truncateAndCopyPreview returns a new slice of length min(len(p),
// MaxDynamicPreviewBytes) containing a copy of the first N bytes of p. It
// never aliases p. A nil/empty input yields a nil slice (not a zero-length
// non-nil slice) so touch's "no preview" records stay zero-alloc.
func truncateAndCopyPreview(p []byte) []byte {
	if len(p) == 0 {
		return nil
	}
	n := len(p)
	if n > MaxDynamicPreviewBytes {
		n = MaxDynamicPreviewBytes
	}
	cp := make([]byte, n)
	copy(cp, p[:n])
	return cp
}

// deepCopy returns a copy of e whose Preview slice does not alias e.Preview.
func (e DynamicEntry) deepCopy() DynamicEntry {
	if e.Preview == nil {
		return e
	}
	cp := make([]byte, len(e.Preview))
	copy(cp, e.Preview)
	e.Preview = cp
	return e
}
