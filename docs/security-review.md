# Code review and upstream maintenance register

Review date: 2026-09-19. Baseline: `third/ssh/commit.txt`, x/crypto `v0.55.0`,
commit `f44d03d253a1503e51b059ca880867c51d878242`.

This register separates first-party repairs from findings retained in vendored
code. The initial review was source-based, not a claim that every reported
scenario had been reproduced. The changes below do not modify `third/ssh`, its
local patches, tests, fixtures, or version metadata.

## Vendored findings — not fixed by this repair

| ID | Status at checked revision | Location and finding | Evidence required at next synchronization |
| --- | --- | --- | --- |
| SSH-UP-001 | Open in local vendored source; upstream fix availability not checked | `third/ssh/handshake.go`, `handshakeTransport.readLoop`; `third/ssh/server.go`, `NewServerConn`: delivery into the bounded `incoming` queue can remain blocked after authentication fails. Closing the socket does not unblock a Go channel send; the read/key-exchange goroutines can remain alive. | Verify that shutdown interrupts queued delivery and that failed authentication terminates the handshake goroutines, including a full incoming queue. Inspect the caller's error cleanup as well as transport shutdown. |
| SSH-UP-002 | Open in local vendored source; upstream fix availability not checked | `third/ssh/mux.go`, `mux.onePacket`; `third/ssh/channel.go`, `channel.handlePacket`: an unsupported message in the connection phase can be interpreted as a channel packet and queued to `ch.msg` without a consumer. Full-queue sends can prevent mux teardown. | Verify message-type validation before channel routing, rejection of unsupported channel-stage messages, and bounded shutdown when the peer closes. |

Both findings are availability/resource-lifecycle risks. The first-party TCP
deadlines and cleanup changes below **do not unblock these internal Go channel
sends** and must not be recorded as fixes for them. No upstream issue, advisory,
or fixed release is asserted without checking a corresponding source.

### Required synchronization record

For every upstream synchronization, update each row above and append a record
containing:

- previous and target upstream tag/commit, plus check date;
- each finding's status: open, fixed with evidence, not applicable with reason,
  or not verified;
- the relevant upstream change and the resulting local source behavior;
- targeted regression commands/results, runtime/platform, and untested cases;
- whether import rewrites and local feature patches remain intact, and what
  action is still needed.

Recheck previously fixed entries too: local patch merging can reintroduce a
problem. General test success alone does not close an entry. See
[`third/AGENTS.md`](../third/AGENTS.md) for synchronization rules.

## First-party remediation

Numbers refer to the initial review findings, not an external advisory.

| Review items | Repair and regression surface |
| --- | --- |
| 2, 11 | `ssh.go`: pre-session and non-Git TCP deadlines bound blocked network I/O; Git sessions clear that deadline. Discard exits on normal EOF. `ssh_timeout_test.go` exercises real loopback SSH, including idle sessions, blocked replies, and unbounded active Git sessions; `ssh_fakeshell_test.go` covers EOF. |
| 4 | `modules/gitserver/auth.go`: authentication explicitly rejects SSH certificates. Only raw authorized public keys are supported; matching a certificate blob is not certificate validation. Certificate regressions are in `auth_test.go`. |
| 5 | Watch-mode reload and lookup share one synchronization boundary, preventing reordered file snapshots during concurrent authentication. `auth_test.go` exercises overlapping reads and revocation. |
| 6 | Repository roots are made absolute before symlink resolution, containment checks, and command construction. `request_test.go` and `backend_local_unix_test.go` cover relative roots. |
| 7 | `current_user` inherits the current identity without invoking privileged supplementary-group changes. Explicit privilege drops still clear supplementary groups. Unix command/process tests cover the distinction. |
| 8, 9, 10 | Git backend process waiting is independent of SSH input copying; closing the session request stream cancels backend work. Unix cancellation terminates the isolated process group and releases the process slot without waiting for a blocked network writer. Exit observation does not reap the leader: the original PID/PGID remains reserved until every possible group signal is finished, then the exclusive owner calls `Cmd.Wait`. Normal completion drains stdout/stderr before returning. Session, process, lifecycle-ordering, and non-reaping observer tests cover these boundaries. |
| 12 | Per-IP bucket use and cleanup take the same mutex, so cleanup cannot delete a bucket between its full-token check and a concurrent deduction. Deterministic interleaving coverage is in `rate_test.go`. |
| 13 | Authentication inputs, client versions, channel types, and global-request types are quoted in logs. `antiscan_test.go` and `ssh_timeout_test.go` check control characters do not become new log lines. |
| 14 | `-gen` creates a new private-key file exclusively with mode `0600`; an existing file or symlink is not overwritten. `key_test.go` covers existing targets and creation. |
| 15 | RootFS ZIP preflight rejects an ambiguous trailing-data EOCD candidate instead of checking an earlier directory than `archive/zip`. A small fixture in `rootfs_regression_test.go` checks both parsers; resource-limit tests remain in `rootfs_test.go`. |
| 16 | Directory import resolves relative paths beneath a pinned `os.Root` and retains object-identity checks, preventing a replaced ancestor from redirecting traversal outside that root. Replacement coverage is in `rootfs_regression_test.go`. |
| 17 | RootFS file opens use Unix nonblocking mode before type/identity checks; initial root opening retains a final `/.` component so the syscall requires a directory rather than blocking on a replacement FIFO. `rootfs_fifo_unix_test.go` tests both file and directory entry paths in timeout-bounded subprocesses. |
| 18–21 | Shell input preserves malformed-line discard state across reads, UTF-8 bytes, and escaped trailing separators/spaces. Assignment restrictions apply only to command-prefix assignments. `input_test.go` and `syntax_test.go` cover these cases. |
| 22, 23 | Redirection targets reserve metadata capacity before execution. Independent writers to the same path record the maximum final position; duplicated descriptors still share a writer. Capacity and same-path tests are in `syntax_test.go`. |

### Compatibility and ownership notes

- Certificate authentication now fails explicitly; configure a raw public key
  instead. This change does not add CA, principal, or certificate-option support.
- `-gen -key <existing-path>` now fails instead of overwriting that path. Choose
  a new path; removal or rotation of an existing host key is an operator action.
- RootFS ZIP archives with ambiguous EOCD trailing data are rejected. Ordinary
  supported archives and their existing resource caps are unchanged.
- Git's backend owns local processes and pipes. The application connection
  owner closes TCP immediately on connection-context cancellation, even if the
  connection loop or exit-status send is blocked writing a reply. Normal Git
  completion sends channel-close first and keeps the connection loop alive for
  the peer's orderly shutdown, with a one-second transport-close fallback. A
  blocked channel-close is also bounded. These timers start during teardown,
  not during an active transfer. Transport closure releases remaining SSH copy I/O;
  `ssh.Channel.Close()` by itself is not a force-close/read-cancel primitive.
- Normal Git transfers retain no fixed duration limit. This is not a new
  timeout policy for authorized, still-running Git commands.
- The local backend is the exclusive reaper of its direct child. Linux uses
  `waitid(WNOWAIT)` and BSD/macOS use `kqueue NOTE_EXIT` to observe exit while
  retaining PID identity through output draining or group cancellation. No
  other waiter or SIGCHLD auto-reaper may reap that child. A zombie may remain
  while output is draining; descendants that deliberately leave the isolated
  process group are outside this process-group cleanup guarantee.
- RootFS directory/FIFO concerns require a concurrently modified host source.
  They are not evidence of remote shell command execution or host-file-body
  exposure. The virtual shell remains metadata-only.

## Verification and outstanding evidence

Final integration verification on 2026-09-19:

- Windows/amd64, Go 1.27.1.
- Docker Linux/amd64, Debian-based `golang:1.26`, Go 1.26.8 and
  OpenSSH 10.0p2. Source and the existing Go module cache were mounted read-only;
  network access and dependency downloads were disabled during tests.

| Check | Result |
| --- | --- |
| `go test ./... -count=1 -timeout=180s` | Passed on Windows and Linux after the final corrections. |
| `go vet ./...` | Passed on Windows and Linux. |
| `go test -tags "no_gitserver no_fakeshell" ./... -count=1 -timeout=180s` | Passed on Windows and Linux. |
| `go test -race . ./modules/gitserver ./modules/fakeshell/... -count=1 -timeout=180s` | Passed on Linux; Windows affected-package race checks passed, including the final SSH and process-lifecycle corrections. |
| Non-root Linux `go test ./modules/gitserver ./modules/fakeshell -count=1 -timeout=180s` | Passed as UID/GID 65534, exercising current-user process execution, directory replacement, and FIFO regressions without root privileges. |
| Real loopback SSH regressions in `ssh_timeout_test.go` | Passed, including EOF/idle cleanup, blocked replies, quoted request/channel logs, and cancellation during a completed Git backend's blocked exit-status send. |
| `TestGitBackendSuccessfulOpenSSHCompletionPreservesOutputAndExitStatus` | Passed on Linux with the actual OpenSSH client, including 10 consecutive runs: at least 4 MiB each of stdout/stderr, output backpressure, stdin EOF, and exit status 0. |
| Local process and RootFS Unix regressions | Passed on Linux, including non-reaping exit observation, signal-before-reap ordering, descendants retaining output pipes, and both file/directory FIFO replacement paths. |
| Git and RootFS BSD/macOS test binaries | Cross-compilation passed; native BSD/macOS execution not performed. |

The independent review identified two additional lifecycle corrections before
delivery: TCP-first (and immediate TCP-after-channel-close) teardown could
truncate a normal OpenSSH session, and group signaling after reaping the leader
could target a reused PGID. The tests above cover both corrections. The OpenSSH
test itself now finishes both pipe readers before calling `Cmd.Wait`; the
existing logger permissions test now supplies a nonexistent log directory so
its unchanged `0700` assertion actually tests directory creation.

Linux runtime evidence is now available. BSD/macOS kqueue behavior still has
source-review and cross-compilation evidence only, not native runtime evidence.
Windows may skip open-directory replacement tests when its filesystem refuses
renaming an open directory; those cases were additionally exercised on Linux.

No Nix evaluation or full release-platform matrix has been performed as part
of this repair. The two vendored findings above remain open regardless of the
first-party test results.
