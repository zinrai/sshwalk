package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Credential is one login to try. The password is read from the credential
// file, which is expected to be protected by file permissions.
type Credential struct {
	User   string
	secret string
}

// loadCredentials reads the credential list, one "user:password" line each.
// The line is split on the first colon only, so a password may itself contain
// colons. Blank lines and lines whose first non-space character is '#' are
// ignored. The password is taken verbatim, not trimmed, so trailing spaces in
// a password are preserved.
func loadCredentials(path string) ([]Credential, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var creds []Credential
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()

		trimmed := strings.TrimSpace(text)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		user, secret, ok := strings.Cut(text, ":")
		if !ok {
			return nil, fmt.Errorf("line %d: expected user:password", line)
		}
		user = strings.TrimSpace(user)
		if user == "" {
			return nil, fmt.Errorf("line %d: empty user", line)
		}
		if secret == "" {
			return nil, fmt.Errorf("line %d: empty password for user %q", line, user)
		}

		creds = append(creds, Credential{User: user, secret: secret})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return creds, nil
}
