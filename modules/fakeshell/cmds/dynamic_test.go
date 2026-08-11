package cmds

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	fsconf "github.com/hugefiver/fakessh/modules/fakeshell/conf"
	"github.com/spf13/afero"
)

// ---------------------------------------------------------------------------
// DynamicStore - preview handling
// ---------------------------------------------------------------------------

// TestDynamicStore_PreviewCapAndTruncation verifies that Record truncates a
// caller preview longer than MaxDynamicPreviewBytes to exactly the cap.
func TestDynamicStore_PreviewCapAndTruncation(t *testing.T) {
	t.Parallel()

	s := NewDynamicStore()
	big := bytes.Repeat([]byte{'x'}, MaxDynamicPreviewBytes*4)
	e, err := s.Record("/tmp/a", "file", int64(len(big)), big, "")
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if len(e.Preview) != MaxDynamicPreviewBytes {
		t.Fatalf("preview len = %d, want %d", len(e.Preview), MaxDynamicPreviewBytes)
	}
	if !bytes.Equal(e.Preview, big[:MaxDynamicPreviewBytes]) {
		t.Fatalf("preview content mismatch")
	}
}

// TestDynamicStore_PreviewNoAliasing verifies that Record deep-copies the
// caller's preview slice: mutating the caller slice after Record must not
// affect the stored entry, and mutating the returned entry's preview must not
// affect a later Entries() call.
func TestDynamicStore_PreviewNoAliasing(t *testing.T) {
	t.Parallel()

	s := NewDynamicStore()
	caller := []byte("hello")
	e, err := s.Record("/tmp/a", "file", 5, caller, "")
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	// Mutate caller slice after Record.
	caller[0] = 'X'
	got := s.Entries()
	if got[0].Preview[0] != 'h' {
		t.Errorf("stored preview mutated by caller slice aliasing: %q", got[0].Preview)
	}

	// Mutate returned entry's preview after Entries().
	e.Preview[0] = 'Z'
	got2 := s.Entries()
	if got2[0].Preview[0] != 'h' {
		t.Errorf("stored preview mutated by returned entry aliasing: %q", got2[0].Preview)
	}
}

// TestDynamicStore_NilPreviewStaysNil verifies that a nil/empty preview is
// stored as nil (not a zero-length non-nil slice) so "no preview" records
// stay zero-allocation.
func TestDynamicStore_NilPreviewStaysNil(t *testing.T) {
	t.Parallel()

	s := NewDynamicStore()
	e, err := s.Record("/tmp/a", "file", 0, nil, "")
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if e.Preview != nil {
		t.Errorf("nil preview stored as non-nil %q", e.Preview)
	}
	got := s.Entries()
	if got[0].Preview != nil {
		t.Errorf("nil preview returned as non-nil %q", got[0].Preview)
	}
}

// ---------------------------------------------------------------------------
// DynamicStore - max entries
// ---------------------------------------------------------------------------

// TestDynamicStore_MaxEntriesRejects257th verifies that inserting a 257th
// unique path is rejected but updating an existing path is always allowed.
func TestDynamicStore_MaxEntriesRejects257th(t *testing.T) {
	t.Parallel()

	s := NewDynamicStore()

	// Fill to exactly the cap with unique paths.
	for i := 0; i < MaxDynamicEntries; i++ {
		p := path3(i)
		if _, err := s.Record(p, "file", 0, nil, ""); err != nil {
			t.Fatalf("Record(%d) %q: %v", i, p, err)
		}
	}

	// 257th unique path must be rejected.
	_, err := s.Record("/tmp/extra", "file", 0, nil, "")
	if err == nil {
		t.Fatal("257th unique path accepted, want rejection")
	}
	if !strings.Contains(err.Error(), "MaxDynamicEntries") {
		t.Errorf("257th error = %q, want substring 'MaxDynamicEntries'", err.Error())
	}

	// Updating an existing path must still succeed even at the cap.
	if _, err := s.Record(path3(0), "file", 99, nil, ""); err != nil {
		t.Fatalf("update existing at cap: %v", err)
	}
	got := s.Entries()
	if len(got) != MaxDynamicEntries {
		t.Errorf("after update, entries = %d, want %d", len(got), MaxDynamicEntries)
	}
	// Verify the update took effect on the first-inserted path.
	if got[0].Path != path3(0) {
		t.Errorf("entries[0].Path = %q, want %q", got[0].Path, path3(0))
	}
	if got[0].Size != 99 {
		t.Errorf("updated size = %d, want 99", got[0].Size)
	}
}

// ---------------------------------------------------------------------------
// DynamicStore - validation
// ---------------------------------------------------------------------------

// TestDynamicStore_InvalidPaths verifies that invalid path arguments are
// rejected: traversal, backslash, colon, control bytes, and over-length.
func TestDynamicStore_InvalidPaths(t *testing.T) {
	t.Parallel()

	s := NewDynamicStore()

	// ".." traversal must be rejected by ResolvePath.
	if _, err := s.Record("..", "file", 0, nil, ""); err == nil {
		t.Error("Record('..') accepted, want rejection")
	}
	// backslash
	if _, err := s.Record(`a\b`, "file", 0, nil, ""); err == nil {
		t.Error("Record('a\\b') accepted, want rejection")
	}
	// colon
	if _, err := s.Record("a:b", "file", 0, nil, ""); err == nil {
		t.Error("Record('a:b') accepted, want rejection")
	}
	// control byte
	if _, err := s.Record("a\x00b", "file", 0, nil, ""); err == nil {
		t.Error("Record('a\\x00b') accepted, want rejection")
	}

	// over-length: build a path whose cleaned length exceeds the cap.
	huge := "/" + strings.Repeat("a", MaxDynamicPathLen)
	if _, err := s.Record(huge, "file", 0, nil, ""); err == nil {
		t.Error("Record(over-length) accepted, want rejection")
	}
}

// TestDynamicStore_InvalidKinds verifies empty and unknown kinds are rejected.
func TestDynamicStore_InvalidKinds(t *testing.T) {
	t.Parallel()

	s := NewDynamicStore()

	if _, err := s.Record("/tmp/a", "", 0, nil, ""); err == nil {
		t.Error("Record(kind='') accepted, want rejection")
	}
	if _, err := s.Record("/tmp/a", "symlink", 0, nil, ""); err == nil {
		t.Error("Record(kind='symlink') accepted, want rejection")
	}
	if _, err := s.Record("/tmp/a", "FILE", 0, nil, ""); err == nil {
		t.Error("Record(kind='FILE') accepted, want rejection (case-sensitive)")
	}
}

// TestDynamicStore_NegativeSizeRejected verifies a negative size is rejected.
func TestDynamicStore_NegativeSizeRejected(t *testing.T) {
	t.Parallel()

	s := NewDynamicStore()
	if _, err := s.Record("/tmp/a", "file", -1, nil, ""); err == nil {
		t.Error("Record(size=-1) accepted, want rejection")
	}
}

// TestDynamicStore_HashValidation verifies SHA256 hash normalization and
// rejection: empty allowed, valid 64-hex normalized to lowercase, uppercase
// normalized, wrong-length rejected, non-hex rejected.
func TestDynamicStore_HashValidation(t *testing.T) {
	t.Parallel()

	s := NewDynamicStore()

	// empty allowed
	if _, err := s.Record("/tmp/a", "file", 0, nil, ""); err != nil {
		t.Errorf("Record(hash='') failed: %v", err)
	}
	// valid lowercase 64-hex accepted
	lower := strings.Repeat("0123456789abcdef", 4) // 64 chars
	e, err := s.Record("/tmp/a", "file", 0, nil, lower)
	if err != nil {
		t.Errorf("Record(hash=lower) failed: %v", err)
	}
	if e.SHA256 != lower {
		t.Errorf("stored hash = %q, want %q", e.SHA256, lower)
	}
	// valid uppercase 64-hex normalized to lowercase
	upper := strings.Repeat("0123456789ABCDEF", 4)
	e, err = s.Record("/tmp/a", "file", 0, nil, upper)
	if err != nil {
		t.Errorf("Record(hash=upper) failed: %v", err)
	}
	if e.SHA256 != lower {
		t.Errorf("uppercase hash not normalized: got %q, want %q", e.SHA256, lower)
	}
	// wrong length rejected
	if _, err := s.Record("/tmp/a", "file", 0, nil, "abc"); err == nil {
		t.Error("Record(hash='abc') accepted, want rejection")
	}
	// non-hex rejected
	if _, err := s.Record("/tmp/a", "file", 0, nil, strings.Repeat("z", 64)); err == nil {
		t.Error("Record(hash=64*'z') accepted, want rejection")
	}
}

// ---------------------------------------------------------------------------
// DynamicStore - Entries ordering & deep copy
// ---------------------------------------------------------------------------

// TestDynamicStore_EntriesDeterministicOrder verifies Entries returns entries
// in insertion order, and that updating an existing path does not change its
// position.
func TestDynamicStore_EntriesDeterministicOrder(t *testing.T) {
	t.Parallel()

	s := NewDynamicStore()
	paths := []string{"/tmp/zebra", "/tmp/apple", "/tmp/mango"}
	for _, p := range paths {
		if _, err := s.Record(p, "file", 0, nil, ""); err != nil {
			t.Fatalf("Record(%q): %v", p, err)
		}
	}

	got := s.Entries()
	if len(got) != 3 {
		t.Fatalf("entries = %d, want 3", len(got))
	}
	// Insertion order, NOT sorted.
	for i, want := range paths {
		if got[i].Path != want {
			t.Errorf("entries[%d].Path = %q, want %q", i, got[i].Path, want)
		}
	}

	// Update /tmp/apple; its position must stay at index 1.
	if _, err := s.Record("/tmp/apple", "file", 42, nil, ""); err != nil {
		t.Fatalf("update: %v", err)
	}
	got = s.Entries()
	if got[1].Path != "/tmp/apple" {
		t.Errorf("after update, entries[1].Path = %q, want /tmp/apple", got[1].Path)
	}
	if got[1].Size != 42 {
		t.Errorf("after update, entries[1].Size = %d, want 42", got[1].Size)
	}
	if got[0].Path != "/tmp/zebra" || got[2].Path != "/tmp/mango" {
		t.Errorf("update changed positions: %q %q %q", got[0].Path, got[1].Path, got[2].Path)
	}
}

// TestDynamicStore_EntriesDeepCopy verifies mutating a returned entry's preview
// does not affect subsequent Entries() calls.
func TestDynamicStore_EntriesDeepCopy(t *testing.T) {
	t.Parallel()

	s := NewDynamicStore()
	if _, err := s.Record("/tmp/a", "file", 0, []byte("data"), ""); err != nil {
		t.Fatalf("Record: %v", err)
	}

	got1 := s.Entries()
	got1[0].Preview[0] = 'X'
	got1[0].Path = "/tampered"

	got2 := s.Entries()
	if got2[0].Preview[0] != 'd' {
		t.Errorf("Entries deep copy failed: preview mutated to %q", got2[0].Preview)
	}
	if got2[0].Path != "/tmp/a" {
		t.Errorf("Entries deep copy failed: path mutated to %q", got2[0].Path)
	}
}

// TestDynamicStore_UpdatedAtNonZeroAndUTC verifies UpdatedAt is non-zero and
// UTC.
func TestDynamicStore_UpdatedAtNonZeroAndUTC(t *testing.T) {
	t.Parallel()

	s := NewDynamicStore()
	before := time.Now().UTC().Add(-time.Second)
	e, err := s.Record("/tmp/a", "file", 0, nil, "")
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if e.UpdatedAt.IsZero() {
		t.Error("UpdatedAt is zero")
	}
	if e.UpdatedAt.Location() != time.UTC {
		t.Errorf("UpdatedAt location = %v, want UTC", e.UpdatedAt.Location())
	}
	if e.UpdatedAt.Before(before) {
		t.Errorf("UpdatedAt %v before record time %v", e.UpdatedAt, before)
	}
}

// ---------------------------------------------------------------------------
// touch - metadata only & ls integration
// ---------------------------------------------------------------------------

// newTestRunnerWithTmp builds a CommandRunner wired to a memmap rootfs that
// contains /tmp (which the embedded rootfs does NOT have), /home/root, /bin,
// /etc/passwd. stdout/stderr are captured buffers. PWD is /home/root.
func newTestRunnerWithTmp(t *testing.T) (*CommandRunner, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()

	cfg := &fsconf.FakeshellConfig{}
	cfg.EnvConfig.Home = "/home/root"
	cfg.FillDefault()
	if err := fsconf.CheckAndFillConfig(cfg); err != nil {
		t.Fatalf("CheckAndFillConfig: %v", err)
	}

	fs := afero.NewMemMapFs()
	for _, dir := range []string{"/home", "/home/root", "/bin", "/etc", "/tmp"} {
		if err := fs.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	f, err := fs.Create("/etc/passwd")
	if err != nil {
		t.Fatalf("create /etc/passwd: %v", err)
	}
	f.Close()

	r := NewCommandRunner(cfg)
	r.RootFS = fs
	r.SetEnv("PWD", "/home/root")

	var out, errb bytes.Buffer
	r.Stdout = &out
	r.Stderr = &errb
	return r, &out, &errb
}

// TestCmdTouch_RecordsMetadataOnly verifies touch records a file entry with
// size 0, no preview, no RootFS write, and that ls /tmp then shows it.
func TestCmdTouch_RecordsMetadataOnly(t *testing.T) {
	t.Parallel()

	r, out, _ := newTestRunnerWithTmp(t)

	if err := CmdTouch.Run(r, "/tmp/a"); err != nil {
		t.Fatalf("touch /tmp/a: %v", err)
	}

	// No RootFS write: /tmp/a must NOT exist in static RootFS.
	exists, err := afero.Exists(r.RootFS, "/tmp/a")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if exists {
		t.Error("touch wrote /tmp/a into static RootFS; want metadata-only")
	}

	// Dynamic store must have exactly one entry for /tmp/a, kind file.
	entries := r.Dynamic.Entries()
	if len(entries) != 1 {
		t.Fatalf("dynamic entries = %d, want 1", len(entries))
	}
	e := entries[0]
	if e.Path != "/tmp/a" {
		t.Errorf("entry path = %q, want /tmp/a", e.Path)
	}
	if e.Kind != "file" {
		t.Errorf("entry kind = %q, want file", e.Kind)
	}
	if e.Size != 0 {
		t.Errorf("entry size = %d, want 0", e.Size)
	}
	if e.Preview != nil {
		t.Errorf("entry preview = %v, want nil", e.Preview)
	}
	if e.SHA256 != "" {
		t.Errorf("entry sha256 = %q, want empty", e.SHA256)
	}

	// ls /tmp must now show 'a' merged from dynamic metadata.
	out.Reset()
	if err := CmdLs.Run(r, "/tmp"); err != nil {
		t.Fatalf("ls /tmp: %v", err)
	}
	got := out.String()
	// /tmp was empty in RootFS; after touch, merged output is just "a\n".
	if got != "a\n" {
		t.Errorf("ls /tmp output = %q, want %q", got, "a\n")
	}
}

// TestCmdTouch_MissingParentReturnsError verifies touch on a path whose parent
// does not exist returns an error, writes shell-like stderr, and records NO
// metadata.
func TestCmdTouch_MissingParentReturnsError(t *testing.T) {
	t.Parallel()

	r, _, errb := newTestRunnerWithTmp(t)

	err := CmdTouch.Run(r, "/nope/a")
	if err == nil {
		t.Fatal("touch /nope/a expected error, got nil")
	}
	if !strings.Contains(errb.String(), "No such file or directory") {
		t.Errorf("stderr = %q, want substring 'No such file or directory'", errb.String())
	}

	// No metadata must have been recorded.
	if entries := r.Dynamic.Entries(); len(entries) != 0 {
		t.Errorf("dynamic entries = %d after failed touch, want 0", len(entries))
	}
}

// TestCmdTouch_NoArgsReturnsError verifies touch with no args errors.
func TestCmdTouch_NoArgsReturnsError(t *testing.T) {
	t.Parallel()

	r, _, errb := newTestRunnerWithTmp(t)
	err := CmdTouch.Run(r)
	if err == nil {
		t.Fatal("touch (no args) expected error, got nil")
	}
	if !strings.Contains(errb.String(), "missing file operand") {
		t.Errorf("stderr = %q, want substring 'missing file operand'", errb.String())
	}
}

// TestCmdTouch_TooManyArgsReturnsError verifies touch with >1 args errors.
func TestCmdTouch_TooManyArgsReturnsError(t *testing.T) {
	t.Parallel()

	r, _, errb := newTestRunnerWithTmp(t)
	err := CmdTouch.Run(r, "/tmp/a", "/tmp/b")
	if err == nil {
		t.Fatal("touch (2 args) expected error, got nil")
	}
	if !strings.Contains(errb.String(), "too many arguments") {
		t.Errorf("stderr = %q, want substring 'too many arguments'", errb.String())
	}
}

// TestCmdTouch_RelativeFromCwd verifies touch resolves a relative arg from PWD.
func TestCmdTouch_RelativeFromCwd(t *testing.T) {
	t.Parallel()

	r, _, _ := newTestRunnerWithTmp(t)
	// PWD is /home/root; touch relative "myfile" -> /home/root/myfile.
	if err := CmdTouch.Run(r, "myfile"); err != nil {
		t.Fatalf("touch myfile: %v", err)
	}
	entries := r.Dynamic.Entries()
	if len(entries) != 1 || entries[0].Path != "/home/root/myfile" {
		t.Errorf("entries = %+v, want [{/home/root/myfile}]", entries)
	}
}

// ---------------------------------------------------------------------------
// Same-session isolation
// ---------------------------------------------------------------------------

// TestCmdTouch_SessionIsolation verifies two runners sharing the same static
// rootfs DO NOT share dynamic state: only the runner that touched /tmp/a sees
// it in ls /tmp.
func TestCmdTouch_SessionIsolation(t *testing.T) {
	t.Parallel()

	cfg := &fsconf.FakeshellConfig{}
	cfg.EnvConfig.Home = "/home/root"
	cfg.FillDefault()
	if err := fsconf.CheckAndFillConfig(cfg); err != nil {
		t.Fatalf("CheckAndFillConfig: %v", err)
	}

	// A single shared static rootfs with /tmp.
	sharedFs := afero.NewMemMapFs()
	for _, dir := range []string{"/home", "/home/root", "/tmp"} {
		if err := sharedFs.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	r1 := NewCommandRunner(cfg)
	r1.RootFS = sharedFs
	r1.SetEnv("PWD", "/home/root")
	var out1 bytes.Buffer
	r1.Stdout = &out1
	r1.Stderr = &bytes.Buffer{}

	r2 := NewCommandRunner(cfg)
	r2.RootFS = sharedFs // SAME static rootfs pointer
	r2.SetEnv("PWD", "/home/root")
	var out2 bytes.Buffer
	r2.Stdout = &out2
	r2.Stderr = &bytes.Buffer{}

	// runner1 touches /tmp/a.
	if err := CmdTouch.Run(r1, "/tmp/a"); err != nil {
		t.Fatalf("runner1 touch /tmp/a: %v", err)
	}

	// runner1 ls /tmp must show 'a'.
	out1.Reset()
	if err := CmdLs.Run(r1, "/tmp"); err != nil {
		t.Fatalf("runner1 ls /tmp: %v", err)
	}
	if got := out1.String(); got != "a\n" {
		t.Errorf("runner1 ls /tmp = %q, want %q", got, "a\n")
	}

	// runner2 ls /tmp must NOT show 'a' (no dynamic state leak).
	if err := CmdLs.Run(r2, "/tmp"); err != nil {
		t.Fatalf("runner2 ls /tmp: %v", err)
	}
	if got := out2.String(); got != "\n" {
		t.Errorf("runner2 ls /tmp = %q, want %q (dynamic state leaked across sessions)", got, "\n")
	}

	// runner2 dynamic store must be empty.
	if entries := r2.Dynamic.Entries(); len(entries) != 0 {
		t.Errorf("runner2 dynamic entries = %d, want 0 (session isolation broken)", len(entries))
	}
}

// ---------------------------------------------------------------------------
// ls merge - duplicate handling
// ---------------------------------------------------------------------------

// TestCmdLs_MergesDynamicAndStaticDedup verifies that when a dynamic entry's
// basename collides with a static RootFS name, ls prints it only once.
func TestCmdLs_MergesDynamicAndStaticDedup(t *testing.T) {
	t.Parallel()

	r, out, _ := newTestRunnerWithTmp(t)

	// /tmp is empty in static rootfs. Touch /tmp/a and /tmp/b.
	if err := CmdTouch.Run(r, "/tmp/a"); err != nil {
		t.Fatalf("touch /tmp/a: %v", err)
	}
	if err := CmdTouch.Run(r, "/tmp/b"); err != nil {
		t.Fatalf("touch /tmp/b: %v", err)
	}

	// Touch /tmp/a again to verify dedup: dynamic store has /tmp/a once,
	// and ls must print 'a' once.
	if err := CmdTouch.Run(r, "/tmp/a"); err != nil {
		t.Fatalf("touch /tmp/a (2nd): %v", err)
	}

	out.Reset()
	if err := CmdLs.Run(r, "/tmp"); err != nil {
		t.Fatalf("ls /tmp: %v", err)
	}
	got := out.String()
	// Sorted: a, b. Deduped: a appears once.
	want := "a  b\n"
	if got != want {
		t.Errorf("ls /tmp output = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// ls - dynamic file/dir fallback (regression for Task 3 correction)
// ---------------------------------------------------------------------------

// TestCmdLs_DynamicFilePrintsBasename verifies the Task 3 correction: after
// `touch /tmp/a`, `ls /tmp/a` must print the basename "a" (not "No such file
// or directory"), because /tmp/a exists only in the per-session dynamic store
// and not in the static RootFS.
func TestCmdLs_DynamicFilePrintsBasename(t *testing.T) {
	t.Parallel()

	r, out, errb := newTestRunnerWithTmp(t)

	if err := CmdTouch.Run(r, "/tmp/a"); err != nil {
		t.Fatalf("touch /tmp/a: %v", err)
	}

	// /tmp/a must NOT exist in static RootFS (touch is metadata-only).
	if exists, _ := afero.Exists(r.RootFS, "/tmp/a"); exists {
		t.Fatal("touch wrote /tmp/a into static RootFS; want metadata-only")
	}

	// ls /tmp/a must resolve to the dynamic file entry and print basename.
	out.Reset()
	errb.Reset()
	if err := CmdLs.Run(r, "/tmp/a"); err != nil {
		t.Fatalf("ls /tmp/a: %v (stderr=%q)", err, errb.String())
	}
	if got, want := out.String(), "a\n"; got != want {
		t.Errorf("ls /tmp/a output = %q, want %q", got, want)
	}
	if errb.String() != "" {
		t.Errorf("ls /tmp/a stderr = %q, want empty", errb.String())
	}
}

// TestCmdLs_DynamicFileNotVisibleToOtherRunner verifies that a dynamic file
// entry recorded by one runner is NOT visible to a second runner that shares
// the same static RootFS: `ls /tmp/a` on runner2 must error "No such file".
func TestCmdLs_DynamicFileNotVisibleToOtherRunner(t *testing.T) {
	t.Parallel()

	cfg := &fsconf.FakeshellConfig{}
	cfg.EnvConfig.Home = "/home/root"
	cfg.FillDefault()
	if err := fsconf.CheckAndFillConfig(cfg); err != nil {
		t.Fatalf("CheckAndFillConfig: %v", err)
	}

	sharedFs := afero.NewMemMapFs()
	for _, dir := range []string{"/home", "/home/root", "/tmp"} {
		if err := sharedFs.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	r1 := NewCommandRunner(cfg)
	r1.RootFS = sharedFs
	r1.SetEnv("PWD", "/home/root")
	var out1, errb1 bytes.Buffer
	r1.Stdout = &out1
	r1.Stderr = &errb1

	r2 := NewCommandRunner(cfg)
	r2.RootFS = sharedFs // same static rootfs pointer
	r2.SetEnv("PWD", "/home/root")
	var out2, errb2 bytes.Buffer
	r2.Stdout = &out2
	r2.Stderr = &errb2

	// runner1 touches /tmp/a (metadata-only, in r1.Dynamic).
	if err := CmdTouch.Run(r1, "/tmp/a"); err != nil {
		t.Fatalf("runner1 touch /tmp/a: %v", err)
	}

	// runner1 ls /tmp/a sees the basename.
	if err := CmdLs.Run(r1, "/tmp/a"); err != nil {
		t.Fatalf("runner1 ls /tmp/a: %v", err)
	}
	if got := out1.String(); got != "a\n" {
		t.Errorf("runner1 ls /tmp/a = %q, want %q", got, "a\n")
	}

	// runner2 ls /tmp/a must NOT see it (per-session isolation).
	err := CmdLs.Run(r2, "/tmp/a")
	if err == nil {
		t.Fatal("runner2 ls /tmp/a accepted, want 'No such file' error")
	}
	if !strings.Contains(errb2.String(), "No such file or directory") {
		t.Errorf("runner2 stderr = %q, want substring 'No such file or directory'", errb2.String())
	}
	if out2.String() != "" {
		t.Errorf("runner2 stdout = %q, want empty (dynamic state leaked)", out2.String())
	}
}

// TestCmdLs_DynamicDirListsDynamicChildren verifies the future-compatible
// dynamic-dir path: a dynamic "dir" entry (recorded directly via the store,
// since no built-in creates one yet) lists its direct dynamic children when
// the path is absent from static RootFS.
func TestCmdLs_DynamicDirListsDynamicChildren(t *testing.T) {
	t.Parallel()

	r, out, _ := newTestRunnerWithTmp(t)

	// Record a dynamic dir /tmp/dyn directly via the store (no built-in yet),
	// plus two dynamic files under it.
	if _, err := r.Dynamic.Record("/tmp/dyn", "dir", 0, nil, ""); err != nil {
		t.Fatalf("record dir /tmp/dyn: %v", err)
	}
	if _, err := r.Dynamic.Record("/tmp/dyn/b", "file", 0, nil, ""); err != nil {
		t.Fatalf("record file /tmp/dyn/b: %v", err)
	}
	if _, err := r.Dynamic.Record("/tmp/dyn/a", "file", 0, nil, ""); err != nil {
		t.Fatalf("record file /tmp/dyn/a: %v", err)
	}

	// /tmp/dyn is absent from static RootFS; ls must fall back to the dynamic
	// dir entry and list its dynamic children, sorted + deduped.
	out.Reset()
	if err := CmdLs.Run(r, "/tmp/dyn"); err != nil {
		t.Fatalf("ls /tmp/dyn: %v", err)
	}
	if got, want := out.String(), "a  b\n"; got != want {
		t.Errorf("ls /tmp/dyn output = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// path3 returns a deterministic 3-digit zero-padded path like "/tmp/f042" for
// the max-entries test, so insertion order is stable and easy to assert.
func path3(i int) string {
	return fmt.Sprintf("/tmp/f%03d", i)
}
