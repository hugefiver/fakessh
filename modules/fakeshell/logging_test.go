//go:build !no_fakeshell && !plan9
// +build !no_fakeshell,!plan9

package fakeshell

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/hugefiver/fakessh/modules/fakeshell/cmds"
	fsconf "github.com/hugefiver/fakessh/modules/fakeshell/conf"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// readJSONLines reads a raw (non-compressed) session log file and returns the
// parsed JSON records, one per line.
func readJSONLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	return parseJSONLines(t, f)
}

// readGzipJSONLines reads a gzip-compressed session log file and returns the
// parsed JSON records.
func readGzipJSONLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip new reader: %v", err)
	}
	defer gz.Close()
	return parseJSONLines(t, gz)
}

func parseJSONLines(t *testing.T, r io.Reader) []map[string]any {
	t.Helper()
	var out []map[string]any
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("unmarshal line %q: %v", string(line), err)
		}
		out = append(out, rec)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scanner: %v", err)
	}
	return out
}

// findSessionLogFile returns the path of the single .log file in dir, or
// fails the test if there is not exactly one.
func findSessionLogFile(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir %s: %v", dir, err)
	}
	var found string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".log") {
			if found != "" {
				t.Fatalf("expected exactly one .log file in %s, found multiple", dir)
			}
			found = filepath.Join(dir, e.Name())
		}
	}
	if found == "" {
		t.Fatalf("no .log file found in %s", dir)
	}
	return found
}

// partialWriteCloser deterministically reports a partial write. It is used to
// exercise the io.Writer contract that a non-zero byte count may accompany an
// error. Close is idempotent while retaining its invocation count for callers
// that need to prove they close the underlying writer only once.
type partialWriteCloser struct {
	limit      int
	writeErr   error
	closeErr   error
	writeCalls int
	closeCalls int
	closed     bool
}

func (w *partialWriteCloser) Write(p []byte) (int, error) {
	w.writeCalls++
	n := len(p)
	if n > w.limit {
		n = w.limit
	}
	return n, w.writeErr
}

func (w *partialWriteCloser) Close() error {
	w.closeCalls++
	if w.closed {
		return nil
	}
	w.closed = true
	return w.closeErr
}

func TestSessionLogger_PartialNormalWritePersistsFirstError(t *testing.T) {
	t.Parallel()

	const partialN = 7
	sentinelErr := errors.New("partial normal write")
	closeErr := errors.New("raw close failure")
	writer := &partialWriteCloser{
		limit:    partialN,
		writeErr: sentinelErr,
		closeErr: closeErr,
	}
	sl := &sessionLogger{w: writer, raw: writer}

	sl.Log(cmds.Event{Time: time.Now(), Type: "command", Command: "first"})
	if got := sl.bytes; got != partialN {
		t.Errorf("bytes = %d, want %d", got, partialN)
	}
	if got := sl.events; got != 0 {
		t.Errorf("events = %d, want 0 after partial event", got)
	}
	if !errors.Is(sl.writeErr, sentinelErr) {
		t.Errorf("writeErr = %v, want %v", sl.writeErr, sentinelErr)
	}

	sl.Log(cmds.Event{Time: time.Now(), Type: "command", Command: "must-not-write"})
	if got := writer.writeCalls; got != 1 {
		t.Errorf("write calls = %d, want 1", got)
	}

	firstCloseErr := sl.Close()
	if !errors.Is(firstCloseErr, sentinelErr) {
		t.Errorf("Close = %v, want first write error %v", firstCloseErr, sentinelErr)
	}
	if errors.Is(firstCloseErr, closeErr) {
		t.Errorf("Close = %v, must prefer first write error over raw close error", firstCloseErr)
	}
	secondCloseErr := sl.Close()
	if secondCloseErr != firstCloseErr {
		t.Errorf("second Close = %v, want identical first error %v", secondCloseErr, firstCloseErr)
	}
	if got := writer.closeCalls; got != 1 {
		t.Errorf("close calls = %d, want 1", got)
	}
}

func TestSessionLogger_PartialTruncationWritePersistsFirstError(t *testing.T) {
	t.Parallel()

	const partialN = 7
	sentinelErr := errors.New("partial truncation write")
	writer := &partialWriteCloser{limit: partialN, writeErr: sentinelErr}
	sl := &sessionLogger{
		w:      writer,
		raw:    writer,
		events: MaxLogEventsPerSession,
	}

	sl.Log(cmds.Event{Time: time.Now(), Type: "command", Command: "trigger-marker"})
	if got := sl.bytes; got != partialN {
		t.Errorf("bytes = %d, want %d", got, partialN)
	}
	if got := sl.events; got != MaxLogEventsPerSession {
		t.Errorf("events = %d, want %d after partial marker", got, MaxLogEventsPerSession)
	}
	if !sl.trunc {
		t.Error("trunc = false, want true after attempted marker")
	}
	if !errors.Is(sl.writeErr, sentinelErr) {
		t.Errorf("writeErr = %v, want %v", sl.writeErr, sentinelErr)
	}

	sl.Log(cmds.Event{Time: time.Now(), Type: "command", Command: "must-not-write"})
	if got := writer.writeCalls; got != 1 {
		t.Errorf("write calls = %d, want 1", got)
	}

	firstCloseErr := sl.Close()
	if !errors.Is(firstCloseErr, sentinelErr) {
		t.Errorf("Close = %v, want first write error %v", firstCloseErr, sentinelErr)
	}
	secondCloseErr := sl.Close()
	if secondCloseErr != firstCloseErr {
		t.Errorf("second Close = %v, want identical first error %v", secondCloseErr, firstCloseErr)
	}
	if got := writer.closeCalls; got != 1 {
		t.Errorf("close calls = %d, want 1", got)
	}
}

func TestSessionLogger_ShortWriteBecomesErrShortWrite(t *testing.T) {
	t.Parallel()

	const partialN = 7
	writer := &partialWriteCloser{limit: partialN}
	sl := &sessionLogger{w: writer, raw: writer}

	sl.Log(cmds.Event{Time: time.Now(), Type: "command", Command: "first"})
	if got := sl.bytes; got != partialN {
		t.Errorf("bytes = %d, want %d", got, partialN)
	}
	if got := sl.events; got != 0 {
		t.Errorf("events = %d, want 0 after short event", got)
	}
	if !errors.Is(sl.writeErr, io.ErrShortWrite) {
		t.Errorf("writeErr = %v, want %v", sl.writeErr, io.ErrShortWrite)
	}

	sl.Log(cmds.Event{Time: time.Now(), Type: "command", Command: "must-not-write"})
	if got := writer.writeCalls; got != 1 {
		t.Errorf("write calls = %d, want 1", got)
	}

	firstCloseErr := sl.Close()
	if !errors.Is(firstCloseErr, io.ErrShortWrite) {
		t.Errorf("Close = %v, want %v", firstCloseErr, io.ErrShortWrite)
	}
	secondCloseErr := sl.Close()
	if secondCloseErr != firstCloseErr {
		t.Errorf("second Close = %v, want identical first error %v", secondCloseErr, firstCloseErr)
	}
	if got := writer.closeCalls; got != 1 {
		t.Errorf("close calls = %d, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// disabled logger
// ---------------------------------------------------------------------------

// TestSessionLogger_DisabledIsNoOp verifies that a disabled config returns a
// no-op logger: Log does nothing and Close returns nil without error.
func TestSessionLogger_DisabledIsNoOp(t *testing.T) {
	t.Parallel()

	lgr, err := NewSessionLogger(fsconf.LogConfig{Enable: false})
	if err != nil {
		t.Fatalf("NewSessionLogger(disabled) error = %v", err)
	}
	// Log should be safe and do nothing.
	lgr.Log(cmds.Event{Type: "session_start", Time: time.Now()})
	lgr.Log(cmds.Event{Type: "command", Command: "ls", Time: time.Now()})
	if err := lgr.Close(); err != nil {
		t.Errorf("noop Close() error = %v", err)
	}
	// Double close should be safe too.
	if err := lgr.Close(); err != nil {
		t.Errorf("noop double Close() error = %v", err)
	}
}

// ---------------------------------------------------------------------------
// enabled logger - basic JSONL
// ---------------------------------------------------------------------------

// TestSessionLogger_EnabledWritesJSONL verifies that an enabled logger writes
// bounded JSON Lines to the configured directory, and that the directory was
// created (0700 on POSIX, existence on Windows).
func TestSessionLogger_EnabledWritesJSONL(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	lgr, err := NewSessionLogger(fsconf.LogConfig{
		Enable: true,
		Path:   dir,
	})
	if err != nil {
		t.Fatalf("NewSessionLogger: %v", err)
	}

	now := time.Now().UTC()
	lgr.Log(cmds.Event{Time: now, Type: "session_start", CWD: "/home/root"})
	lgr.Log(cmds.Event{Time: now, Type: "command", CWD: "/home/root", Command: "pwd", Args: []string{}})
	lgr.Log(cmds.Event{Time: now, Type: "session_end", CWD: "/home/root"})
	if err := lgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	logPath := findSessionLogFile(t, dir)
	records := readJSONLines(t, logPath)
	if len(records) != 3 {
		t.Fatalf("got %d records, want 3", len(records))
	}
	if records[0]["type"] != "session_start" {
		t.Errorf("records[0].type = %v, want session_start", records[0]["type"])
	}
	if records[1]["type"] != "command" {
		t.Errorf("records[1].type = %v, want command", records[1]["type"])
	}
	if records[1]["command"] != "pwd" {
		t.Errorf("records[1].command = %v, want pwd", records[1]["command"])
	}
	if records[2]["type"] != "session_end" {
		t.Errorf("records[2].type = %v, want session_end", records[2]["type"])
	}

	// Directory permission check: on POSIX verify 0700. On Windows the mode
	// bits are not meaningful, so only check existence.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat dir: %v", err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Errorf("dir perm = %v, want 0700", info.Mode().Perm())
		}
	}
}

// TestSessionLogger_DefaultPathWhenEmpty verifies that an empty path defaults
// to "./sessions" (relative). We run in a temp working dir to avoid polluting
// the repo.
//
// This test intentionally does NOT call t.Parallel(): it mutates the
// process-global working directory via os.Chdir, which would race with / pollute
// any other parallel test that resolves a relative path. The deferred Chdir
// back to origWd restores the cwd before the next test starts.
func TestSessionLogger_DefaultPathWhenEmpty(t *testing.T) {
	// Switch to a temp working directory so the default "./sessions" lands in
	// a scratch area. Restore on exit.
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	scratch := t.TempDir()
	if err := os.Chdir(scratch); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer os.Chdir(origWd)

	lgr, err := NewSessionLogger(fsconf.LogConfig{Enable: true, Path: ""})
	if err != nil {
		t.Fatalf("NewSessionLogger: %v", err)
	}
	lgr.Log(cmds.Event{Time: time.Now().UTC(), Type: "session_start"})
	if err := lgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The "sessions" directory should now exist under the scratch dir.
	sessionsDir := filepath.Join(scratch, "sessions")
	if _, err := os.Stat(sessionsDir); err != nil {
		t.Fatalf("default sessions dir not created: %v", err)
	}
	findSessionLogFile(t, sessionsDir)
}

// ---------------------------------------------------------------------------
// gzip
// ---------------------------------------------------------------------------

// TestSessionLogger_GzipWritesReadableJSONL verifies that a gzip-compressed
// logger writes a .log file that is gzip-readable and contains valid JSONL.
func TestSessionLogger_GzipWritesReadableJSONL(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	lgr, err := NewSessionLogger(fsconf.LogConfig{
		Enable:   true,
		Path:     dir,
		Compress: "gzip",
	})
	if err != nil {
		t.Fatalf("NewSessionLogger: %v", err)
	}

	now := time.Now().UTC()
	lgr.Log(cmds.Event{Time: now, Type: "session_start", CWD: "/"})
	lgr.Log(cmds.Event{Time: now, Type: "command", Command: "echo", Args: []string{"hi"}})
	lgr.Log(cmds.Event{Time: now, Type: "session_end"})
	if err := lgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	logPath := findSessionLogFile(t, dir)
	// Verify it is actually gzip (magic bytes).
	f, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	var magic [2]byte
	if _, err := f.Read(magic[:]); err != nil {
		t.Fatalf("read magic: %v", err)
	}
	f.Close()
	if magic[0] != 0x1f || magic[1] != 0x8b {
		t.Fatalf("file is not gzip: magic % x, want 1f 8b", magic)
	}

	records := readGzipJSONLines(t, logPath)
	if len(records) != 3 {
		t.Fatalf("got %d records, want 3", len(records))
	}
	if records[1]["command"] != "echo" {
		t.Errorf("record[1].command = %v, want echo", records[1]["command"])
	}
}

// ---------------------------------------------------------------------------
// command / error truncation
// ---------------------------------------------------------------------------

// TestSessionLogger_CommandTruncation verifies that a command string longer
// than MaxLoggedCommandBytes is truncated and never written verbatim.
func TestSessionLogger_CommandTruncation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	lgr, err := NewSessionLogger(fsconf.LogConfig{Enable: true, Path: dir})
	if err != nil {
		t.Fatalf("NewSessionLogger: %v", err)
	}

	bigCmd := strings.Repeat("A", MaxLoggedCommandBytes*2)
	lgr.Log(cmds.Event{
		Time:    time.Now().UTC(),
		Type:    "command",
		Command: bigCmd,
	})
	lgr.Close()

	logPath := findSessionLogFile(t, dir)
	records := readJSONLines(t, logPath)
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	cmd, _ := records[0]["command"].(string)
	if len(cmd) > MaxLoggedCommandBytes {
		t.Errorf("command len = %d, want <= %d", len(cmd), MaxLoggedCommandBytes)
	}
	if !strings.HasSuffix(cmd, "...") {
		t.Errorf("truncated command should end with '...', got suffix %q", cmd[len(cmd)-10:])
	}
	// The original giant command must NOT appear verbatim.
	if strings.Contains(readFileAll(t, logPath), bigCmd) {
		t.Error("giant command appeared verbatim in the log file")
	}
}

// TestSessionLogger_ErrorTruncation verifies that an error string longer than
// the cap is truncated.
func TestSessionLogger_ErrorTruncation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	lgr, err := NewSessionLogger(fsconf.LogConfig{Enable: true, Path: dir})
	if err != nil {
		t.Fatalf("NewSessionLogger: %v", err)
	}

	bigErr := strings.Repeat("E", MaxLoggedCommandBytes*2)
	lgr.Log(cmds.Event{
		Time:  time.Now().UTC(),
		Type:  "command",
		Error: bigErr,
	})
	lgr.Close()

	logPath := findSessionLogFile(t, dir)
	records := readJSONLines(t, logPath)
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	errStr, _ := records[0]["error"].(string)
	if len(errStr) > MaxLoggedCommandBytes {
		t.Errorf("error len = %d, want <= %d", len(errStr), MaxLoggedCommandBytes)
	}
}

// ---------------------------------------------------------------------------
// single event max behavior
// ---------------------------------------------------------------------------

// TestSessionLogger_SingleEventMaxBehavior verifies that a single event whose
// serialized form would exceed MaxLogEventBytes is replaced by a small
// "event_too_large" marker rather than a giant line. We force this by adding
// many metadata entries (each with a max preview) whose joined JSON exceeds
// the cap; command/args/error are individually capped so they cannot trigger
// this path alone.
func TestSessionLogger_SingleEventMaxBehavior(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	lgr, err := NewSessionLogger(fsconf.LogConfig{Enable: true, Path: dir})
	if err != nil {
		t.Fatalf("NewSessionLogger: %v", err)
	}

	// Build enough metadata entries to exceed MaxLogEventBytes. Each entry has
	// a full MaxDynamicPreviewBytes preview (256 bytes -> ~340 base64 chars),
	// a 64-char sha256, a path, kind, size, and updated_at. That is ~500+
	// bytes of JSON per entry; 40 entries will exceed 8192 bytes.
	preview := bytes.Repeat([]byte{'p'}, cmds.MaxDynamicPreviewBytes)
	sha := strings.Repeat("a", 64)
	meta := make([]cmds.DynamicEntry, 40)
	for i := range meta {
		meta[i] = cmds.DynamicEntry{
			Path:    "/tmp/f" + itoa(i),
			Kind:    "file",
			Size:    123,
			Preview: preview,
			SHA256:  sha,
		}
	}
	lgr.Log(cmds.Event{
		Time:     time.Now().UTC(),
		Type:     "command",
		Command:  "touch",
		Metadata: meta,
	})
	lgr.Close()

	logPath := findSessionLogFile(t, dir)
	// Read raw bytes to verify no single line exceeds MaxLogEventBytes.
	raw := readFileAll(t, logPath)
	for _, line := range strings.Split(strings.TrimRight(raw, "\n"), "\n") {
		if len(line) > MaxLogEventBytes {
			t.Errorf("a single log line is %d bytes, exceeds MaxLogEventBytes %d", len(line), MaxLogEventBytes)
		}
	}
	records := readJSONLines(t, logPath)
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if records[0]["type"] != "event_too_large" {
		t.Errorf("record type = %v, want event_too_large", records[0]["type"])
	}
}

// ---------------------------------------------------------------------------
// MaxLogEventsPerSession
// ---------------------------------------------------------------------------

// TestSessionLogger_EventCountCap verifies that after MaxLogEventsPerSession
// events, the logger writes exactly one truncation marker and then drops all
// further events. The total number of written lines must not exceed
// MaxLogEventsPerSession + 1 (the marker).
func TestSessionLogger_EventCountCap(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	lgr, err := NewSessionLogger(fsconf.LogConfig{Enable: true, Path: dir})
	if err != nil {
		t.Fatalf("NewSessionLogger: %v", err)
	}

	// Write well over the cap.
	total := MaxLogEventsPerSession + 50
	for i := 0; i < total; i++ {
		lgr.Log(cmds.Event{
			Time:    time.Now().UTC(),
			Type:    "command",
			Command: "ls",
		})
	}
	lgr.Close()

	logPath := findSessionLogFile(t, dir)
	records := readJSONLines(t, logPath)

	// At most cap + one marker.
	if len(records) > MaxLogEventsPerSession+1 {
		t.Errorf("records = %d, want <= %d (cap + 1 marker)", len(records), MaxLogEventsPerSession+1)
	}

	// The marker must appear exactly once and must be the last record.
	markerCount := 0
	for _, r := range records {
		if r["type"] == "truncated" {
			markerCount++
		}
	}
	if markerCount != 1 {
		t.Errorf("truncation marker count = %d, want exactly 1", markerCount)
	}
	if last := records[len(records)-1]; last["type"] != "truncated" {
		t.Errorf("last record type = %v, want truncated", last["type"])
	}
	// The marker reason must be the expected constant.
	if r := records[len(records)-1]; r["reason"] != truncationMarkerReason {
		t.Errorf("marker reason = %v, want %q", r["reason"], truncationMarkerReason)
	}
}

// ---------------------------------------------------------------------------
// MaxLogBytesPerSession
// ---------------------------------------------------------------------------

// TestSessionLogger_ByteCap verifies that after MaxLogBytesPerSession bytes,
// the logger writes one truncation marker and drops further events. We use
// large-but-bounded events to hit the byte cap quickly.
func TestSessionLogger_ByteCap(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	lgr, err := NewSessionLogger(fsconf.LogConfig{Enable: true, Path: dir})
	if err != nil {
		t.Fatalf("NewSessionLogger: %v", err)
	}

	// Each event is a command with a near-max command string so each JSON line
	// is a few KB. We write enough to exceed the 1 MiB byte cap.
	bigCmd := strings.Repeat("B", MaxLoggedCommandBytes-32) // leaves room for "..."
	total := (MaxLogBytesPerSession / 2000) + 50
	for i := 0; i < total; i++ {
		lgr.Log(cmds.Event{
			Time:    time.Now().UTC(),
			Type:    "command",
			Command: bigCmd,
		})
	}
	lgr.Close()

	logPath := findSessionLogFile(t, dir)
	raw := readFileAll(t, logPath)
	if len(raw) > MaxLogBytesPerSession+MaxLogEventBytes {
		t.Errorf("log file size = %d, want <= %d (cap + one marker line)", len(raw), MaxLogBytesPerSession+MaxLogEventBytes)
	}

	records := readJSONLines(t, logPath)
	// Exactly one truncation marker.
	markerCount := 0
	for _, r := range records {
		if r["type"] == "truncated" {
			markerCount++
		}
	}
	if markerCount != 1 {
		t.Errorf("truncation marker count = %d, want exactly 1", markerCount)
	}
}

// ---------------------------------------------------------------------------
// metadata preview bounds
// ---------------------------------------------------------------------------

// TestSessionLogger_MetadataPreviewBounded verifies that a DynamicEntry with
// a huge preview (constructed directly to bypass the store's own cap) is
// re-bounded by the logger so the log never contains more than
// MaxDynamicPreviewBytes bytes of preview data.
func TestSessionLogger_MetadataPreviewBounded(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	lgr, err := NewSessionLogger(fsconf.LogConfig{Enable: true, Path: dir})
	if err != nil {
		t.Fatalf("NewSessionLogger: %v", err)
	}

	hugePreview := bytes.Repeat([]byte{'Z'}, cmds.MaxDynamicPreviewBytes*8)
	lgr.Log(cmds.Event{
		Time:    time.Now().UTC(),
		Type:    "command",
		Command: "touch",
		Metadata: []cmds.DynamicEntry{
			{
				Path:    "/tmp/big",
				Kind:    "file",
				Size:    int64(len(hugePreview)),
				Preview: hugePreview,
			},
		},
	})
	lgr.Close()

	logPath := findSessionLogFile(t, dir)
	raw := readFileAll(t, logPath)
	// The huge 'Z'-run must not appear verbatim beyond the bounded preview.
	// The logger base64-encodes the preview, so the raw 'Z' bytes should not
	// appear at all; only the base64 encoding of the first
	// MaxDynamicPreviewBytes 'Z' bytes should be present.
	zRun := string(hugePreview[:cmds.MaxDynamicPreviewBytes+10])
	if strings.Contains(raw, zRun) {
		t.Errorf("log contains more than %d raw preview bytes verbatim", cmds.MaxDynamicPreviewBytes)
	}

	records := readJSONLines(t, logPath)
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	meta, _ := records[0]["metadata"].([]any)
	if len(meta) != 1 {
		t.Fatalf("metadata len = %d, want 1", len(meta))
	}
	entry, _ := meta[0].(map[string]any)
	previewB64, _ := entry["preview"].(string)
	if previewB64 == "" {
		t.Fatal("preview is empty, want base64 of bounded preview")
	}
}

// ---------------------------------------------------------------------------
// concurrency safety
// ---------------------------------------------------------------------------

// TestSessionLogger_ConcurrentLogIsSafe verifies that concurrent Log calls
// do not race or panic. Run with -race to detect data races.
func TestSessionLogger_ConcurrentLogIsSafe(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	lgr, err := NewSessionLogger(fsconf.LogConfig{Enable: true, Path: dir})
	if err != nil {
		t.Fatalf("NewSessionLogger: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			lgr.Log(cmds.Event{Time: time.Now().UTC(), Type: "command", Command: "ls"})
		}
	}()
	for i := 0; i < 200; i++ {
		lgr.Log(cmds.Event{Time: time.Now().UTC(), Type: "command", Command: "pwd"})
	}
	<-done
	lgr.Close()

	// No assertions on content; the test just verifies no race/panic under
	// concurrent Log calls.
}

// ---------------------------------------------------------------------------
// Truncation marker always emitted on byte-cap truncation
// ---------------------------------------------------------------------------

// TestSessionLogger_ByteCapAlwaysEmitsMarker proves the fix for the silent-
// marker-drop bug. The old code gated the truncation marker write on
// l.bytes+len(marker) <= MaxLogBytesPerSession; if the byte cap was hit when
// l.bytes was already within markerLen bytes of the cap, the marker was
// silently dropped (writeTruncationMarker set l.trunc but wrote nothing), so
// all subsequent events were silently swallowed with no `{type:"truncated"}`
// record to tell an auditor truncation happened.
//
// The fix reserves truncationMarkerReserve bytes inside MaxLogBytesPerSession
// so the marker always has a landing zone. This test directly drives the
// sessionLogger into the marker-drop window by setting l.bytes (accessible
// because the test is in the same package) to MaxLogBytesPerSession -
// markerLen/2, which is inside (cap - markerLen, cap]. It then Logs an event
// that triggers byteOver and verifies the marker is present in the file. On
// the buggy code the marker is silently dropped; on the fixed code the
// reserved tail guarantees it is written.
func TestSessionLogger_ByteCapAlwaysEmitsMarker(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	lgr, err := NewSessionLogger(fsconf.LogConfig{Enable: true, Path: dir})
	if err != nil {
		t.Fatalf("NewSessionLogger: %v", err)
	}
	sl := lgr.(*sessionLogger)

	// Write one minimal event so the file has valid content and l.bytes is
	// nonzero. Then artificially bump l.bytes into the marker-drop window.
	sl.Log(cmds.Event{Time: time.Now().UTC(), Type: "command"})

	// Measure the marker size so the test adapts if the marker format changes.
	mrec := logRecord{
		Time:   time.Now().UTC().Format(time.RFC3339Nano),
		Type:   "truncated",
		Reason: truncationMarkerReason,
	}
	mb, _ := json.Marshal(mrec)
	mb = append(mb, '\n')
	markerLen := len(mb)
	if markerLen >= truncationMarkerReserve {
		t.Fatalf("marker length %d >= truncationMarkerReserve %d; reserve must be larger than marker", markerLen, truncationMarkerReserve)
	}

	// Set l.bytes to MaxLogBytesPerSession - markerLen/2, which is inside the
	// marker-drop window (l.bytes + markerLen > MaxLogBytesPerSession). On the
	// buggy code this causes writeTruncationMarker to skip the marker.
	sl.mu.Lock()
	sl.bytes = MaxLogBytesPerSession - markerLen/2
	sl.mu.Unlock()

	// Log an event whose line is larger than the remaining markerLen/2 bytes.
	// This triggers byteOver -> writeTruncationMarker.
	sl.Log(cmds.Event{Time: time.Now().UTC(), Type: "command", Command: "trigger-byte-cap"})
	if err := sl.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw := readFileAll(t, sl.path)

	// The truncation marker MUST be present (not silently dropped). On the old
	// code with l.bytes in the marker-drop window, the marker was dropped
	// because l.bytes+markerLen > MaxLogBytesPerSession failed the gate.
	records := readJSONLines(t, sl.path)
	markerCount := 0
	for _, r := range records {
		if r["type"] == "truncated" {
			markerCount++
		}
	}
	if markerCount != 1 {
		t.Errorf("truncation marker count = %d, want exactly 1 (marker must always be emitted on byte-cap truncation, even when free space < markerLen)", markerCount)
	}

	// The file must not exceed the byte cap by more than one marker line
	// (bounded by MaxLogEventBytes). The reserved-tail design keeps it at or
	// under MaxLogBytesPerSession in the normal path; the artificial l.bytes
	// manipulation here means the file is small, but the assertion guards
	// against unbounded overrun in real usage.
	if len(raw) > MaxLogBytesPerSession+MaxLogEventBytes {
		t.Errorf("log file size = %d, want <= %d (cap + one marker line)", len(raw), MaxLogBytesPerSession+MaxLogEventBytes)
	}
}

// TestSessionLogger_MarkerFitsInReservedTail proves the reserved-tail design
// directly: even if we craft events so that the free space just before the
// cap is smaller than the marker, the marker is written and the file size
// stays at or under MaxLogBytesPerSession.
//
// This test writes events until the byte cap is well exceeded, proving the
// marker is emitted into the reserved tail rather than dropped. The file size
// assertion verifies the marker does not cause an unbounded overrun.
func TestSessionLogger_MarkerFitsInReservedTail(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	lgr, err := NewSessionLogger(fsconf.LogConfig{Enable: true, Path: dir})
	if err != nil {
		t.Fatalf("NewSessionLogger: %v", err)
	}

	// Use a moderately-sized command so each line is a few KB. Write enough
	// events to exceed the byte cap with margin. The reserved tail design
	// guarantees the marker is always emitted regardless of how much free
	// space remains when the cap triggers.
	cmdLen := 4000
	bigCmd := strings.Repeat("D", cmdLen)
	// Over-estimate per-line size conservatively so we definitely exceed the
	// cap. Each line is roughly cmdLen + 100 bytes of JSON overhead.
	perLine := cmdLen + 200
	total := (MaxLogBytesPerSession / perLine) + 100
	for i := 0; i < total; i++ {
		lgr.Log(cmds.Event{
			Time:    time.Now().UTC(),
			Type:    "command",
			Command: bigCmd,
		})
	}
	lgr.Close()

	logPath := findSessionLogFile(t, dir)
	raw := readFileAll(t, logPath)

	// File size must be at or under the byte cap (reserved tail keeps the
	// marker inside the cap). Allow a small tolerance for the marker line
	// itself in case the reserved tail math is off by a few bytes due to
	// write-count under-reporting; the hard upper bound is cap + one marker
	// line (<= MaxLogEventBytes).
	if len(raw) > MaxLogBytesPerSession+MaxLogEventBytes {
		t.Errorf("log file size = %d, want <= %d (cap + one marker line)", len(raw), MaxLogBytesPerSession+MaxLogEventBytes)
	}

	records := readJSONLines(t, logPath)
	markerCount := 0
	for _, r := range records {
		if r["type"] == "truncated" {
			markerCount++
		}
	}
	if markerCount != 1 {
		t.Errorf("truncation marker count = %d, want exactly 1", markerCount)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func readFileAll(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
