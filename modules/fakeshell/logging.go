//go:build !no_fakeshell && !plan9
// +build !no_fakeshell,!plan9

package fakeshell

import (
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hugefiver/fakessh/modules/fakeshell/cmds"
	"github.com/hugefiver/fakessh/modules/fakeshell/conf"
)

// Bounded session-logging caps. These prevent an attacker from exhausting
// server disk or memory by sending unbounded input: command strings, error
// strings, per-event JSON, event counts and total session log bytes are all
// capped. Once a cap is reached the logger writes at most one truncation
// marker and then drops all further events.
const (
	// MaxLoggedCommandBytes bounds the Command, Error, CWD, Type and each Arg
	// string field in a single event. A longer string is truncated to this
	// length.
	MaxLoggedCommandBytes = 4096

	// MaxLogEventBytes bounds the serialized JSON size of a single event line.
	// An event whose serialized form would exceed this is replaced by a small
	// "event_too_large" marker record so a single attacker event cannot
	// produce a giant log line.
	MaxLogEventBytes = 8192

	// MaxLogEventsPerSession bounds the number of events written to a single
	// session log. After this many events the logger writes one truncation
	// marker and drops the rest.
	MaxLogEventsPerSession = 1024

	// MaxLogBytesPerSession bounds the total bytes written to a single session
	// log file. After this many bytes the logger writes one truncation marker
	// and drops the rest.
	MaxLogBytesPerSession = 1 << 20 // 1 MiB

	// truncationMarkerReserve is the byte budget reserved inside
	// MaxLogBytesPerSession so that the single session-limit truncation marker
	// always fits when the byte cap is hit, even if the cap is reached by an
	// event that itself is near the per-event maximum. The truncation marker
	// serialized form is well under 200 bytes (see writeTruncationMarker), so
	// 256 bytes is a generous reserve. Reserving marker space up front means
	// the logger never has to choose between silently dropping the marker and
	// exceeding MaxLogBytesPerSession: the marker always fits in the reserved
	// tail, so once the byte cap triggers a truncation, a marker is guaranteed
	// to be emitted (rather than silently swallowed).
	truncationMarkerReserve = 256
)

// truncationMarkerReason is the Reason field written in the single
// session-limit truncation marker.
const truncationMarkerReason = "session_log_limit"

// noopLogger implements cmds.EventLogger as a no-op. It is returned when
// LogConfig.Enable is false so that RunLoop can unconditionally call Log
// without a nil check on every event.
type noopLogger struct{}

func (noopLogger) Log(cmds.Event) {}
func (noopLogger) Close() error   { return nil }

// sessionLogger writes bounded JSON Lines session activity to a file. Each
// event is serialized as one JSON object followed by a newline. The file may
// be optionally gzip-compressed.
//
// Safety properties:
//
//   - mu guards the writer, the event/byte counters, and the closed/truncated
//     flags. Log and Close are safe for concurrent use.
//   - All string fields are truncated before serialization; metadata previews
//     are re-bounded to MaxDynamicPreviewBytes defensively.
//   - A single event whose JSON exceeds MaxLogEventBytes is replaced by a
//     small marker record, never written as a giant line.
//   - Once MaxLogEventsPerSession or MaxLogBytesPerSession is reached, at most
//     one truncation marker is written; all subsequent events are dropped.
//   - Close is idempotent: a second call is a no-op.
//   - Logger errors NEVER propagate to command execution; Log is best-effort.
type sessionLogger struct {
	mu     sync.Mutex
	w      io.WriteCloser // gzip writer (when compressed) or underlying file
	raw    io.Closer      // the underlying *os.File, closed after the gzip writer
	path   string
	events int
	bytes  int
	trunc  bool // already wrote the session-limit marker
	closed bool
}

// NewSessionLogger creates a bounded session logger from the given config.
//
// If c.Enable is false, a no-op logger is returned (and nil error) regardless
// of Path/Compress. The caller (NewShell) treats a nil error as "logging is
// ready" and a non-nil error as "logging could not be initialized; abort the
// session before any command runs", mirroring the rootfs load-error posture.
//
// When enabled:
//   - Path defaults to conf.DefaultLogPath ("./sessions") when empty.
//   - The directory is created with 0700 permissions if it does not exist.
//   - Compress "gzip" wraps the file writer in a gzip.Writer; "" writes raw
//     JSON Lines. Other values are rejected by conf.validateLogConfig and
//     should never reach here, but are treated as raw defensively.
//   - The session file name is a timestamp + random suffix to avoid collisions
//     and to avoid trusting attacker-controlled names.
func NewSessionLogger(c conf.LogConfig) (cmds.EventLogger, error) {
	if !c.Enable {
		return noopLogger{}, nil
	}

	path := c.Path
	if path == "" {
		path = conf.DefaultLogPath
	}

	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, fmt.Errorf("fakeshell: create session log dir %q: %w", path, err)
	}

	fname := sessionLogFileName(time.Now().UTC())
	fpath := filepath.Join(path, fname)

	// Create the file with 0600: it contains attacker-controlled (but bounded)
	// command text and should not be world-readable. O_EXCL prevents accidental
	// overwrite of an existing file.
	f, err := os.OpenFile(fpath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("fakeshell: create session log file %q: %w", fpath, err)
	}

	var w io.WriteCloser = f
	if strings.EqualFold(c.Compress, "gzip") {
		w = gzip.NewWriter(f)
	}

	return &sessionLogger{
		w:    w,
		raw:  f,
		path: fpath,
	}, nil
}

// sessionLogFileName builds a collision-resistant file name from a timestamp
// and a short random suffix. The name never incorporates attacker input.
func sessionLogFileName(t time.Time) string {
	const tsLayout = "20060102-150405"
	stamp := t.Format(tsLayout)
	suffix := randomLogSuffix(8)
	return stamp + "_" + suffix + ".log"
}

// Log records a single bounded event. It is safe for concurrent use and never
// panics. If the session cap (events or bytes) has been reached, at most one
// truncation marker is written and the event is dropped.
//
// Byte-cap correctness: the truncation marker is written into a
// truncationMarkerReserve-byte tail reserved inside MaxLogBytesPerSession, so
// once the byte cap is triggered the marker is always emitted rather than
// silently swallowed. Events are admitted only while at least
// truncationMarkerReserve bytes remain after writing them; once that window
// closes the current event is dropped and the marker is written in the
// reserved tail. The marker itself is bounded by MaxLogEventBytes and is well
// under truncationMarkerReserve, so the file never exceeds
// MaxLogBytesPerSession.
func (l *sessionLogger) Log(ev cmds.Event) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return
	}

	// If we already hit a session cap and wrote the truncation marker, drop
	// everything else.
	if l.trunc {
		return
	}

	// Build the bounded JSON line for this event.
	line, oversized := l.marshalEvent(ev)
	if oversized {
		// The single event would exceed MaxLogEventBytes even after
		// truncation of individual fields (e.g. huge metadata count). Replace
		// it with a small marker rather than writing a giant line.
		line = l.marshalEventTooLarge(ev)
	}

	// Check the per-event cap defensively: even the marker must not exceed
	// MaxLogEventBytes.
	if len(line) > MaxLogEventBytes {
		// Should not happen given marshalEventTooLarge is tiny, but fail safe.
		line = l.marshalEventTooLarge(ev)
	}

	// Check session-level caps BEFORE writing. If this event would push us
	// over either cap, write a single truncation marker and then drop this
	// and all future events.
	//
	// For the byte cap, the admit threshold is
	// MaxLogBytesPerSession - truncationMarkerReserve so that the marker
	// always has a reserved tail to land in. This guarantees the marker is
	// emitted whenever the byte cap triggers (rather than silently dropped
	// because no space remained) while still keeping the file at or under
	// MaxLogBytesPerSession.
	eventOver := l.events >= MaxLogEventsPerSession
	byteCeiling := MaxLogBytesPerSession - truncationMarkerReserve
	if byteCeiling < 0 {
		byteCeiling = 0
	}
	byteOver := l.bytes+len(line) > byteCeiling
	if eventOver || byteOver {
		l.writeTruncationMarker()
		return
	}

	if n, err := l.w.Write(line); err == nil {
		l.bytes += n
		l.events++
	}
	// On write error we do not propagate; logging is best-effort.
}

// marshalEvent serializes ev into a single JSON Lines record (including the
// trailing newline). All string and byte fields are bounded. It returns the
// bytes and a bool indicating whether the serialized form exceeded
// MaxLogEventBytes (oversized=true means the caller should substitute a
// marker).
func (l *sessionLogger) marshalEvent(ev cmds.Event) ([]byte, bool) {
	rec := l.boundedRecord(ev)
	b, err := json.Marshal(rec)
	if err != nil {
		// Should be impossible for our record shape, but fail safe.
		return []byte(`{"type":"marshal_error"}` + "\n"), false
	}
	b = append(b, '\n')
	if len(b) > MaxLogEventBytes {
		return b, true
	}
	return b, false
}

// logRecord is the JSON-serializable form of an Event. Reason is an extra
// field used for truncation/oversize markers; it is empty for normal events.
type logRecord struct {
	Time     string         `json:"time"`
	Type     string         `json:"type"`
	CWD      string         `json:"cwd,omitempty"`
	Command  string         `json:"command,omitempty"`
	Args     []string       `json:"args,omitempty"`
	Error    string         `json:"error,omitempty"`
	Metadata []logMetaEntry `json:"metadata,omitempty"`
	Reason   string         `json:"reason,omitempty"`
}

// logMetaEntry is the JSON form of cmds.DynamicEntry with a defensively
// re-bounded preview encoded as base64. We store the bounded preview rather
// than the original (already-bounded) slice so a maliciously-constructed
// DynamicEntry (e.g. in a test) cannot sneak a huge preview into the log.
type logMetaEntry struct {
	Path       string `json:"path"`
	Kind       string `json:"kind"`
	Size       int64  `json:"size"`
	PreviewB64 string `json:"preview,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	UpdatedAt  string `json:"updated_at,omitempty"`
}

// boundedRecord converts a cmds.Event into a logRecord with all fields
// truncated to their respective caps. It never aliases caller memory.
func (l *sessionLogger) boundedRecord(ev cmds.Event) logRecord {
	rec := logRecord{
		Time:    ev.Time.UTC().Format(time.RFC3339Nano),
		Type:    truncateString(ev.Type, MaxLoggedCommandBytes),
		CWD:     truncateString(ev.CWD, MaxLoggedCommandBytes),
		Command: truncateString(ev.Command, MaxLoggedCommandBytes),
		Error:   truncateString(ev.Error, MaxLoggedCommandBytes),
		Reason:  "",
	}

	if len(ev.Args) > 0 {
		args := make([]string, 0, len(ev.Args))
		total := 0
		for _, a := range ev.Args {
			ta := truncateString(a, MaxLoggedCommandBytes)
			args = append(args, ta)
			total += len(ta)
			if total > MaxLoggedCommandBytes {
				// Stop once the joined args would exceed the command cap; we
				// don't try to be precise here, just bounded.
				args = append(args, "...args_truncated")
				break
			}
		}
		rec.Args = args
	}

	if len(ev.Metadata) > 0 {
		md := make([]logMetaEntry, 0, len(ev.Metadata))
		for _, de := range ev.Metadata {
			md = append(md, logMetaEntry{
				Path:       truncateString(de.Path, MaxLoggedCommandBytes),
				Kind:       de.Kind,
				Size:       de.Size,
				PreviewB64: previewToB64(de.Preview),
				SHA256:     de.SHA256,
				UpdatedAt:  de.UpdatedAt.UTC().Format(time.RFC3339Nano),
			})
		}
		rec.Metadata = md
	}

	return rec
}

// marshalEventTooLarge builds a small marker record for an event whose
// serialized form exceeded MaxLogEventBytes. It carries the event type and a
// bounded reason so an auditor can see that an event was dropped.
func (l *sessionLogger) marshalEventTooLarge(ev cmds.Event) []byte {
	rec := logRecord{
		Time:   ev.Time.UTC().Format(time.RFC3339Nano),
		Type:   "event_too_large",
		Reason: "single_event_exceeds_max_log_event_bytes",
	}
	// Include the original event type (bounded) for context if present.
	if ev.Type != "" {
		rec.CWD = truncateString(ev.Type, 128)
	}
	b, _ := json.Marshal(rec)
	b = append(b, '\n')
	return b
}

// writeTruncationMarker writes the single session-limit marker and sets the
// trunc flag so no further events are written. It is called under l.mu.
//
// The marker is ALWAYS written once a session cap is hit (events or bytes).
// The old code gated the write on l.bytes+len(marker) <= MaxLogBytesPerSession,
// which silently dropped the marker when the byte cap was hit with l.bytes
// already within markerLen bytes of the cap - leaving no {type:"truncated"}
// record to tell an auditor truncation had occurred. The fix reserves
// truncationMarkerReserve bytes inside MaxLogBytesPerSession (via Log's
// byteCeiling), so the marker always has a landing zone. We therefore write
// the marker unconditionally here and set the trunc flag. The marker is
// bounded by MaxLogEventBytes (and is well under truncationMarkerReserve, ~88
// bytes), so in the normal path the file never exceeds MaxLogBytesPerSession.
// The only way the file can exceed MaxLogBytesPerSession is if Log's
// byteCeiling is bypassed (e.g. the event-count cap triggers when l.bytes is
// already near the byte cap); in that case the overshoot is at most one marker
// line, bounded by MaxLogEventBytes.
func (l *sessionLogger) writeTruncationMarker() {
	if l.trunc {
		return
	}
	rec := logRecord{
		Time:   time.Now().UTC().Format(time.RFC3339Nano),
		Type:   "truncated",
		Reason: truncationMarkerReason,
	}
	b, _ := json.Marshal(rec)
	b = append(b, '\n')
	// Defensive: the marker must never exceed the per-event cap. It is tiny
	// (~88 bytes) so this should never fire, but fail safe.
	if len(b) > MaxLogEventBytes {
		// Build the smallest possible marker. This is a last resort.
		b = []byte(`{"type":"truncated","reason":"session_log_limit"}` + "\n")
	}
	// Always emit the marker once a session cap is hit. The reserved tail in
	// Log's byte-cap check guarantees space in the normal path. We do not
	// gate on l.bytes+len(b) <= MaxLogBytesPerSession here because that was
	// the exact bug that caused silent drops; instead we write the marker
	// unconditionally (it is bounded by MaxLogEventBytes) and set the trunc
	// flag so no further writes occur.
	if n, err := l.w.Write(b); err == nil {
		l.bytes += n
		l.events++
	}
	l.trunc = true
}

// Close flushes any buffered writer and closes the file. It is idempotent.
func (l *sessionLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil
	}
	l.closed = true

	var firstErr error
	// For gzip, close the gzip writer first (it writes the trailer), then the
	// underlying file. For raw, w == raw == file.
	if l.w != l.raw {
		if err := l.w.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if l.raw != nil {
		if err := l.raw.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Path returns the on-disk path of the session log file. It is intended for
// diagnostics and tests; production code should not depend on it.
func (l *sessionLogger) Path() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.path
}

// truncateString returns s truncated to at most maxBytes. If truncation
// occurs, the result ends with "...". It operates on bytes but never splits a
// multi-byte UTF-8 sequence by validating the cut point: if the cut would
// land in the middle of a rune, it backs off to the previous rune boundary.
func truncateString(s string, maxBytes int) string {
	if maxBytes <= 0 || len(s) <= maxBytes {
		return s
	}
	const ellipsis = "..."
	cut := maxBytes - len(ellipsis)
	if cut < 0 {
		cut = 0
	}
	// Back off to a rune boundary so we don't emit invalid UTF-8.
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut] + ellipsis
}

// previewToB64 returns the base64 encoding of the first MaxDynamicPreviewBytes
// bytes of p. It defends against a maliciously-constructed DynamicEntry whose
// Preview exceeds the cap (the store enforces this, but tests construct
// entries directly). A nil/empty preview returns "".
func previewToB64(p []byte) string {
	if len(p) == 0 {
		return ""
	}
	if len(p) > cmds.MaxDynamicPreviewBytes {
		p = p[:cmds.MaxDynamicPreviewBytes]
	}
	return base64.StdEncoding.EncodeToString(p)
}

// randomLogSuffix returns n hex characters of randomness for a session log
// file name. It reads from crypto/rand so the suffix is unpredictable.
func randomLogSuffix(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		// Fall back to a timestamp-based suffix if the system CSPRNG fails.
		// This is only for file-name uniqueness, not security.
		return fmt.Sprintf("%x", time.Now().UnixNano())[:n]
	}
	return hex.EncodeToString(b)[:n]
}
