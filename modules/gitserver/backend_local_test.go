//go:build !no_gitserver
// +build !no_gitserver

package gitserver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLocalSlotAcquireReleaseRefusesWhenBusy verifies the local git-shell
// process-limit slot accounting on the Server configured with
// MaxGitShellProcesses=1 and RefuseWhenBusy=true. The first acquire
// succeeds, a second concurrent acquire fails (busy), and after the slot is
// released a third acquire succeeds again.
//
// This test is OS-independent: it exercises the in-process semaphore on the
// Server without invoking the git-shell child. It runs on every platform
// that compiles the gitserver module.
func TestLocalSlotAcquireReleaseRefusesWhenBusy(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, &Config{
		Enable:               true,
		MaxGitShellProcesses: 1,
		RefuseWhenBusy:       true,
	})

	// First acquire: must succeed (the slot is free).
	acq1 := srv.tryAcquireLocalSlot()
	assert.True(t, acq1, "first acquire must succeed when the slot is free")

	// Second acquire while the first is held: must fail because the slot
	// is busy and RefuseWhenBusy is true.
	acq2 := srv.tryAcquireLocalSlot()
	assert.False(t, acq2, "second acquire must fail when slot is busy and RefuseWhenBusy is true")

	// Release the slot and acquire again: must succeed.
	srv.releaseLocalSlot()
	acq3 := srv.tryAcquireLocalSlot()
	assert.True(t, acq3, "acquire after release must succeed")

	// Clean up so the channel is balanced.
	srv.releaseLocalSlot()
}

// TestLocalSlotUnlimitedWhenMaxZero verifies that when
// MaxGitShellProcesses=0 the slot accounting is disabled and every acquire
// succeeds without consuming or returning any slot.
func TestLocalSlotUnlimitedWhenMaxZero(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, &Config{
		Enable:               true,
		MaxGitShellProcesses: 0,
		RefuseWhenBusy:       true,
	})

	require.Nil(t, srv.localSlots, "localSlots must be nil when MaxGitShellProcesses=0")

	for i := 0; i < 5; i++ {
		assert.True(t, srv.tryAcquireLocalSlot(), "unlimited acquire %d must succeed", i)
	}

	// releaseLocalSlot on a nil pool must be a safe no-op.
	srv.releaseLocalSlot()
}
