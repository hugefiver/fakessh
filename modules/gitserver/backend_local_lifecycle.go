//go:build !no_gitserver

package gitserver

import (
	"context"
	"fmt"
	"io"
)

// localProcess separates observing exit from reaping. The caller exclusively
// owns the child: neither another Wait nor SIGCHLD auto-reaping may reap it.
// Keeping that child unreaped reserves its PID, and thus its original PGID,
// until the last possible group signal. An exit notification alone does not
// provide that identity guarantee.
type localProcess interface {
	waitExited() error // must not reap, including on error
	terminateGroup()
	reap() error // the only operation allowed to release the child's PID
}

func waitLocalProcess(ctx context.Context, process localProcess, stdin io.Closer, stdoutDone, stderrDone <-chan error) error {
	exited := make(chan error, 1)
	go func() { exited <- process.waitExited() }()

	var observeErr error
	select {
	case observeErr = <-exited:
	case <-ctx.Done():
		// Prefer a fully completed command over concurrent cancellation.
		select {
		case observeErr = <-exited:
		default:
			_ = stdin.Close()
			process.terminateGroup()
			// Join the non-reaping observer before releasing the PID as well.
			<-exited
			_ = process.reap()
			return ctx.Err()
		}
	}
	_ = stdin.Close()
	if observeErr != nil {
		// Observation failure is not permission to reap early and later send
		// a numeric group signal. Clean up while we still own the child.
		process.terminateGroup()
		_ = process.reap()
		return fmt.Errorf("gitserver: observe git-shell exit: %w", observeErr)
	}

	stdoutErr, stderrErr, outputPending := waitLocalOutput(ctx, stdoutDone, stderrDone)
	if outputPending {
		process.terminateGroup()
	}
	// No path may signal the group after this point. In particular, the
	// leader stays unreaped throughout a potentially blocked SSH Write.
	processErr := process.reap()
	if outputPending {
		return ctx.Err()
	}
	if processErr != nil {
		return processErr
	}
	if stdoutErr != nil {
		return stdoutErr
	}
	return stderrErr
}

// waitLocalOutput drains both output copies on normal completion. If ctx is
// cancelled, collect results already available so full completion wins a race.
func waitLocalOutput(ctx context.Context, stdoutDone, stderrDone <-chan error) (stdoutErr, stderrErr error, cancelled bool) {
	for stdoutDone != nil || stderrDone != nil {
		select {
		case err := <-stdoutDone:
			stdoutErr = err
			stdoutDone = nil
		default:
		}
		select {
		case err := <-stderrDone:
			stderrErr = err
			stderrDone = nil
		default:
		}
		if stdoutDone == nil && stderrDone == nil {
			return stdoutErr, stderrErr, false
		}
		select {
		case err := <-stdoutDone:
			stdoutErr = err
			stdoutDone = nil
		case err := <-stderrDone:
			stderrErr = err
			stderrDone = nil
		case <-ctx.Done():
			select {
			case err := <-stdoutDone:
				stdoutErr = err
				stdoutDone = nil
			default:
			}
			select {
			case err := <-stderrDone:
				stderrErr = err
				stderrDone = nil
			default:
			}
			return stdoutErr, stderrErr, stdoutDone != nil || stderrDone != nil
		}
	}
	return stdoutErr, stderrErr, false
}
