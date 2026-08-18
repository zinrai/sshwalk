package main

import (
	"encoding/json"
	"io"
	"os"
)

// Result is one host's outcome, emitted as a single JSON Lines record.
//
// The three-way state is deliberate:
//   - Connected=false            -> host unreachable (network/port)
//   - Connected, !Authenticated  -> host up, no credential worked (manual)
//   - Connected, Authenticated   -> logged in; ExitCode/Stdout/Stderr valid
//
// AuthUser and AuthIndex record which credential succeeded. AuthIndex is the
// 1-based position in the credential list, so a specific password can be
// named without writing the password itself. It is 0 when no credential
// worked. It also equals the number of attempts, since the walk stops at the
// first success.
type Result struct {
	Host          string   `json:"host"`
	Connected     bool     `json:"connected"`
	Authenticated bool     `json:"authenticated"`
	AuthUser      string   `json:"auth_user"`
	AuthIndex     int      `json:"auth_index"`
	Attempts      []string `json:"attempts"`
	ExitCode      int      `json:"exit_code"`
	Stdout        string   `json:"stdout"`
	Stderr        string   `json:"stderr"`
	Error         string   `json:"error"`
}

// writeResult emits one JSONL record and flushes it, so the line reaches a
// downstream pipe or redirect immediately.
func writeResult(w io.Writer, r Result) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err := w.Write(append(b, '\n')); err != nil {
		return err
	}
	if f, ok := w.(*os.File); ok {
		_ = f.Sync()
	}
	return nil
}
