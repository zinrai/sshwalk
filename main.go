// Command sshwalk connects to one host over SSH, trying a list of
// credentials in order until one authenticates, then runs a command on the
// host and prints one JSON Lines record to stdout.
//
// It is intended for operators auditing machines they administer whose login
// credentials are inconsistent, where it is not known in advance which
// credential will work. It processes a single host per invocation; drive a
// fleet with a shell loop and collect the output with a redirect.
//
// Use only against hosts you are authorized to access.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
)

// These are overwritten at release time via -ldflags; the names must match
// the -X targets in .goreleaser.yaml.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	credFile := flag.String("cred-file", "", "file with credentials to try, one per line: user:password")
	host := flag.String("host", "", "target host as host:port, for example 192.0.2.10:22 (required)")
	command := flag.String("command", "hostname", "command to run on the host")
	connectTimeout := flag.Duration("connect-timeout", defaultConnectTimeout, "TCP connect and SSH handshake timeout")
	commandTimeout := flag.Duration("command-timeout", defaultCommandTimeout, "timeout for the remote command")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Printf("sshwalk %s (commit %s, built %s)\n", version, commit, date)
		return nil
	}

	if *credFile == "" {
		return fmt.Errorf("-cred-file is required")
	}
	if *host == "" {
		return fmt.Errorf("-host is required")
	}
	if *connectTimeout <= 0 {
		return fmt.Errorf("-connect-timeout must be positive")
	}
	if *commandTimeout <= 0 {
		return fmt.Errorf("-command-timeout must be positive")
	}

	// Require an explicit port so a typo fails here as a usage error, rather
	// than being dialed and misrecorded as an unreachable host.
	if _, _, err := net.SplitHostPort(*host); err != nil {
		return fmt.Errorf("host must be given as host:port (e.g. 192.0.2.10:22): %w", err)
	}

	creds, err := loadCredentials(*credFile)
	if err != nil {
		return fmt.Errorf("loading credentials: %w", err)
	}
	if len(creds) == 0 {
		return fmt.Errorf("no credentials found in %s", *credFile)
	}

	res := walkHost(*host, creds, *command, *connectTimeout, *commandTimeout)

	if err := writeResult(os.Stdout, res); err != nil {
		return fmt.Errorf("writing result: %w", err)
	}
	fmt.Fprintf(os.Stderr, "%s: %s\n", *host, statusLine(res))

	if !res.Authenticated {
		// Non-zero exit flags a host for manual attention, so a surrounding
		// shell loop can collect the follow-up set.
		os.Exit(2)
	}
	return nil
}

func usage() {
	fmt.Fprint(os.Stderr, `Usage: sshwalk --cred-file FILE --host HOST [--command COMMAND]

Runs COMMAND on HOST using the first credential that authenticates and prints
one JSON Lines record to stdout. COMMAND defaults to "hostname".

Flags:
`)
	flag.PrintDefaults()
}

func statusLine(r Result) string {
	switch {
	case !r.Connected:
		return "UNREACHABLE"
	case !r.Authenticated:
		return "AUTH-FAILED (manual)"
	default:
		return fmt.Sprintf("ok as %s (rc=%d)", r.AuthUser, r.ExitCode)
	}
}
