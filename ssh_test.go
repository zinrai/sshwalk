package main

import (
	"errors"
	"testing"
)

// The auth-before-connect ordering is the crux of the walk: an auth rejection
// is a non-nil error, so if it were checked after the generic error branch a
// rejected credential would be misrecorded as an unreachable host and stop the
// walk. These cases pin that ordering.
func TestClassifyDial(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want dialOutcome
	}{
		{"nil is authenticated", nil, dialAuthenticated},
		{
			"auth rejection",
			errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password]"),
			dialAuthRejected,
		},
		{
			"connect failure",
			errors.New("dial tcp 192.0.2.1:22: connect: connection refused"),
			dialConnectFailed,
		},
		{
			"timeout is connect failure",
			errors.New("dial tcp 192.0.2.1:22: i/o timeout"),
			dialConnectFailed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyDial(tt.err); got != tt.want {
				t.Errorf("classifyDial(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}

// isAuthError matches on x/crypto/ssh handshake text because the library
// exports no typed auth error. These cases lock in the strings we depend on so
// a library upgrade that changes them fails here rather than silently
// reclassifying rejected credentials as unreachable hosts.
func TestIsAuthError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{
			"unable to authenticate",
			errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password]"),
			true,
		},
		{
			"no supported methods remain",
			errors.New("ssh: handshake failed: ssh: no supported methods remain"),
			true,
		},
		{
			"permission denied",
			errors.New("ssh: handshake failed: ssh: permission denied"),
			true,
		},
		{
			"connection refused is not auth",
			errors.New("dial tcp 192.0.2.1:22: connect: connection refused"),
			false,
		},
		{
			"i/o timeout is not auth",
			errors.New("dial tcp 192.0.2.1:22: i/o timeout"),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAuthError(tt.err); got != tt.want {
				t.Errorf("isAuthError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestExitCodeOf(t *testing.T) {
	if got := exitCodeOf(nil); got != 0 {
		t.Errorf("exitCodeOf(nil) = %d, want 0", got)
	}
	// A non-exit error (transport failure, signal kill) maps to -1. The
	// *ssh.ExitError -> status path needs a real remote command and is left to
	// end-to-end use rather than a unit test.
	if got := exitCodeOf(errors.New("connection lost")); got != -1 {
		t.Errorf("exitCodeOf(non-exit error) = %d, want -1", got)
	}
}
