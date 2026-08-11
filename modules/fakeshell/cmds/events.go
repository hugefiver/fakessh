package cmds

import "time"

// EventLogger is the interface used by the fakeshell package to record
// bounded session activity. Implementations must be safe for concurrent use.
// Log must never panic and must never block the caller indefinitely; a
// best-effort, drop-on-error posture is expected so that logging never
// interferes with command execution.
//
// The interface lives in the cmds package (rather than fakeshell) to avoid an
// import cycle: fakeshell imports cmds, so cmds cannot import fakeshell.
type EventLogger interface {
	Log(Event)
	Close() error
}

// Event is a single bounded session activity record. The logger truncates all
// string and byte fields before serialization, so callers should not
// pre-truncate. Metadata must only contain DynamicEntry records from the
// per-session DynamicStore (metadata-only, never file content); the logger
// re-bounds each Preview defensively.
type Event struct {
	Time     time.Time
	Type     string
	CWD      string
	Command  string
	Args     []string
	Error    string
	Metadata []DynamicEntry
}
