package main

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/hugefiver/fakessh/conf"
	"github.com/hugefiver/fakessh/third/ssh"
	"go.uber.org/zap"
)

// fakeConnMetadata is a minimal ssh.ConnMetadata for app-level tests.
type fakeConnMetadata struct{ user string }

func (f fakeConnMetadata) User() string          { return f.user }
func (f fakeConnMetadata) SessionID() []byte     { return nil }
func (f fakeConnMetadata) ClientVersion() []byte { return []byte("SSH-2.0-test") }
func (f fakeConnMetadata) ServerVersion() []byte { return []byte("SSH-2.0-test") }
func (f fakeConnMetadata) RemoteAddr() net.Addr  { return fakeAddr("remote") }
func (f fakeConnMetadata) LocalAddr() net.Addr   { return fakeAddr("local") }

type fakeAddr string

func (a fakeAddr) Network() string { return string(a) }
func (a fakeAddr) String() string  { return string(a) }

// fakeNewChannel records the last rejection reason/message passed to Reject.
type fakeNewChannel struct {
	typ     string
	reason  ssh.RejectionReason
	message string
}

func (f *fakeNewChannel) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	return nil, nil, errors.New("unexpected accept")
}
func (f *fakeNewChannel) Reject(reason ssh.RejectionReason, message string) error {
	f.reason = reason
	f.message = message
	return nil
}
func (f *fakeNewChannel) ChannelType() string { return f.typ }
func (f *fakeNewChannel) ExtraData() []byte   { return nil }

// TestSleepAuthDelayAppliesConfiguredDelay locks the existing "m <= 0" branch:
// with Delay=1 and Deviation=0, sleepAuthDelay must sleep a fixed 5ms.
func TestSleepAuthDelayAppliesConfiguredDelay(t *testing.T) {
	t.Parallel()

	c := &conf.AppConfig{}
	c.Server.Delay = 1
	c.Server.Deviation = 0

	start := time.Now()
	sleepAuthDelay(c)
	elapsed := time.Since(start)

	if elapsed < 4*time.Millisecond {
		t.Fatalf("expected delay >= 4ms, got %v", elapsed)
	}
}

// TestAuthCallbackSleepsOnSuccessAndFailure verifies that authCallback sleeps
// on both success and failure paths (so timing cannot distinguish them), and
// that success returns nil while failure returns errAuth. It does NOT run in
// parallel because it mutates package globals `log` and `cl`.
func TestAuthCallbackSleepsOnSuccessAndFailure(t *testing.T) {
	// authCallback reads globals cl.IsLogPasswd and log; set them.
	prevLog := log
	prevCl := cl
	t.Cleanup(func() {
		log = prevLog
		cl = prevCl
	})
	log = zap.NewNop().Sugar()
	cl = &conf.FlagArgsStruct{IsLogPasswd: false}

	c := &conf.AppConfig{}
	c.Server.Users = []*conf.User{{User: "user", Password: "good"}}
	c.Server.Delay = 1
	c.Server.Deviation = 0

	cb := authCallback(c)

	// Success path: correct password.
	startOk := time.Now()
	_, errOk := cb(fakeConnMetadata{user: "user"}, []byte("good"))
	elapsedOk := time.Since(startOk)

	if errOk != nil {
		t.Fatalf("expected nil error on success, got %v", errOk)
	}
	if elapsedOk < 4*time.Millisecond {
		t.Fatalf("expected success delay >= 4ms, got %v", elapsedOk)
	}

	// Failure path: wrong password.
	startBad := time.Now()
	_, errBad := cb(fakeConnMetadata{user: "user"}, []byte("bad"))
	elapsedBad := time.Since(startBad)

	if !errors.Is(errBad, errAuth) {
		t.Fatalf("expected errAuth on failure, got %v", errBad)
	}
	if elapsedBad < 4*time.Millisecond {
		t.Fatalf("expected failure delay >= 4ms, got %v", elapsedBad)
	}
}

// TestRejectExtraChannelReasons verifies OpenSSH-style rejection reasons:
// non-session channels get UnknownChannelType/"unknown channel type", and
// extra session channels get ResourceShortage/"resource shortage".
func TestRejectExtraChannelReasons(t *testing.T) {
	t.Parallel()

	nonSession := &fakeNewChannel{typ: "direct-tcpip"}
	rejectExtraChannel(nonSession)
	if nonSession.reason != ssh.UnknownChannelType {
		t.Fatalf("non-session: expected %v, got %v", ssh.UnknownChannelType, nonSession.reason)
	}
	if nonSession.message != "unknown channel type" {
		t.Fatalf("non-session: expected %q, got %q", "unknown channel type", nonSession.message)
	}

	extraSession := &fakeNewChannel{typ: "session"}
	rejectExtraChannel(extraSession)
	if extraSession.reason != ssh.ResourceShortage {
		t.Fatalf("extra session: expected %v, got %v", ssh.ResourceShortage, extraSession.reason)
	}
	if extraSession.message != "resource shortage" {
		t.Fatalf("extra session: expected %q, got %q", "resource shortage", extraSession.message)
	}
}

func TestIsOpenSSHCompatClientVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{"ssh2", "SSH-2.0-OpenSSH_9.3", true},
		{"ssh2NonZeroMinor", "SSH-2.1-test", true},
		{"ssh2WhitespaceMajor", "SSH- 2.0-test", true},
		{"ssh2PlusMajor", "SSH-+2.0-test", true},
		{"ssh199", "SSH-1.99-legacy", true},
		{"negativeMajor", "SSH--2.0-test", false},
		{"ssh1", "SSH-1.5-legacy", false},
		{"missingSoftware", "SSH-2.0-", false},
		{"missingDash", "SSH-2.0", false},
		{"invalid", "not-ssh", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isOpenSSHCompatClientVersion([]byte(tt.version))
			if got != tt.want {
				t.Fatalf("isOpenSSHCompatClientVersion(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}
