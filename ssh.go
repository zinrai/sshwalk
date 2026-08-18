package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// The connect and command timeouts are overridable by flags; these are the
// defaults. The attempt delay is deliberately not a flag: it is a lockout
// guard that should not be turned off casually.
const (
	defaultConnectTimeout = 10 * time.Second
	defaultCommandTimeout = 60 * time.Second
	attemptDelay          = 1 * time.Second
)

// walkHost tries each credential against one host in order, stopping at the
// first that authenticates, then runs the command. A connect failure stops
// the walk (the port is closed, so further credentials cannot help); an auth
// rejection advances to the next credential.
func walkHost(host string, creds []Credential, remoteCmd string, connectTimeout, commandTimeout time.Duration) Result {
	res := Result{Host: host}

	for i, cred := range creds {
		res.Attempts = append(res.Attempts, cred.User)

		if i > 0 {
			// Space out attempts so a run does not trip fail2ban or PAM
			// lockout and lock out the target's legitimate operators.
			time.Sleep(attemptDelay)
		}

		client, err := dial(host, cred, connectTimeout)
		switch classifyDial(err) {
		case dialAuthRejected:
			continue
		case dialConnectFailed:
			// Connection itself failed; more credentials would fail the same.
			res.Connected = false
			res.Error = fmt.Sprintf("connect: %v", err)
			return res
		}

		res.Connected = true
		res.Authenticated = true
		res.AuthUser = cred.User
		res.AuthIndex = i + 1

		runCommand(client, remoteCmd, &res, commandTimeout)
		client.Close()
		return res
	}

	// Host reachable but every credential was rejected: manual follow-up.
	res.Connected = true
	res.Authenticated = false
	res.Error = "all credentials rejected"
	return res
}

func dial(host string, cred Credential, connectTimeout time.Duration) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User:            cred.User,
		Auth:            []ssh.AuthMethod{ssh.Password(cred.secret)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         connectTimeout,
	}

	// Dial the TCP connection ourselves so the timeout still fires when the
	// handshake stalls after the socket opens, which ssh.Dial does not cover.
	conn, err := net.DialTimeout("tcp", host, connectTimeout)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(connectTimeout)); err != nil {
		conn.Close()
		return nil, err
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, host, config)
	if err != nil {
		conn.Close()
		return nil, err
	}
	// Command timeout is enforced separately, so drop the handshake deadline.
	_ = conn.SetDeadline(time.Time{})

	return ssh.NewClient(c, chans, reqs), nil
}

// runCommand runs remoteCmd on an authenticated client. A non-zero exit is a
// normal, recorded outcome, not an error of the tool.
func runCommand(client *ssh.Client, remoteCmd string, res *Result, commandTimeout time.Duration) {
	session, err := client.NewSession()
	if err != nil {
		res.Error = fmt.Sprintf("session: %v", err)
		return
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	done := make(chan error, 1)
	go func() { done <- session.Run(remoteCmd) }()

	select {
	case err := <-done:
		res.ExitCode = exitCodeOf(err)
		if err != nil && res.ExitCode < 0 {
			res.Error = fmt.Sprintf("run: %v", err)
		}
	case <-time.After(commandTimeout):
		// Best-effort signal; the server may or may not honor it.
		_ = session.Signal(ssh.SIGKILL)
		res.ExitCode = -1
		res.Error = fmt.Sprintf("command timed out after %s", commandTimeout)
	}

	res.Stdout = stdout.String()
	res.Stderr = stderr.String()
}

// exitCodeOf maps the run error to the remote exit status, or -1 when the
// command did not exit cleanly (signal kill, transport error).
func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	var ee *ssh.ExitError
	if errors.As(err, &ee) {
		return ee.ExitStatus()
	}
	return -1
}

// dialOutcome classifies one credential's dial attempt. The three cases drive
// the walk: keep trying, stop as unreachable, or proceed to run the command.
type dialOutcome int

const (
	dialAuthRejected dialOutcome = iota
	dialConnectFailed
	dialAuthenticated
)

// classifyDial maps a dial error to the walk decision. The order is the crux
// of the tool: an auth rejection is a non-nil error, so it must be detected
// before the generic connect-failure branch, or a rejected credential would
// be misrecorded as an unreachable host and stop the walk.
func classifyDial(err error) dialOutcome {
	if isAuthError(err) {
		return dialAuthRejected
	}
	if err != nil {
		return dialConnectFailed
	}
	return dialAuthenticated
}

// isAuthError reports whether err is an auth rejection rather than a
// connection failure. x/crypto/ssh exports no typed auth error, so match on
// the handshake failure text it returns once auth methods are exhausted.
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "unable to authenticate") ||
		strings.Contains(msg, "no supported methods remain") ||
		strings.Contains(msg, "permission denied")
}
