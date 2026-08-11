package cmds

import (
	"fmt"
	"io"
)

// MaxCommandOutputBytes is the hard upper bound for a single fake command's
// output. Recon-style commands must never stream unbounded data to the client.
const MaxCommandOutputBytes = 64 * 1024

const outputTruncatedMarker = "\n[fakeshell: output truncated]\n"

// truncateOutput returns data capped to MaxCommandOutputBytes bytes. When data
// is truncated, the returned string ends with a stable marker while still
// fitting within the cap.
func truncateOutput(data string) string {
	if len(data) <= MaxCommandOutputBytes {
		return data
	}

	marker := outputTruncatedMarker
	if len(marker) >= MaxCommandOutputBytes {
		return marker[:MaxCommandOutputBytes]
	}

	keep := MaxCommandOutputBytes - len(marker)
	return data[:keep] + marker
}

// writeBounded writes at most MaxCommandOutputBytes bytes to w. If data is too
// large, it is truncated with the same stable marker used by truncateOutput.
func writeBounded(w io.Writer, data string) error {
	_, err := io.WriteString(w, truncateOutput(data))
	return err
}

// fakeFileContent returns tiny allowlisted fake file contents for recon-style
// commands. It never reads from the host filesystem and only matches exact fake
// POSIX paths.
func fakeFileContent(filePath string) (string, bool) {
	switch filePath {
	case "/etc/hostname":
		return "fakeshell\n", true
	case "/etc/os-release":
		return "NAME=\"FakeShell Linux\"\nPRETTY_NAME=\"FakeShell Linux\"\nID=fakeshell\n", true
	case "/etc/passwd":
		return "root:x:0:0:root:/root:/bin/sh\n", true
	case "/proc/version":
		return "Linux version 6.1.0-fakeshell (fakeshell@localhost) #1 SMP PREEMPT_DYNAMIC\n", true
	case "/proc/uptime":
		return "12345.67 89012.34\n", true
	default:
		return "", false
	}
}

// unsupportedOption creates a stable bounded error for options Task 2 commands
// intentionally do not emulate. The option text may originate from attacker
// input, so it is clipped before becoming part of an error string.
func unsupportedOption(cmd string, opt string) error {
	return fmt.Errorf("%s: unsupported option %s", clipErrorToken(cmd), clipErrorToken(opt))
}

func clipErrorToken(s string) string {
	const maxErrorTokenBytes = 80
	if len(s) <= maxErrorTokenBytes {
		return s
	}
	return s[:maxErrorTokenBytes] + "..."
}
