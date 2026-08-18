package main

import (
	"os"
	"path/filepath"
	"testing"
)

// writeCredFile writes contents to a temp file and returns its path.
func writeCredFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "creds.txt")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("writing cred file: %v", err)
	}
	return path
}

func TestLoadCredentials(t *testing.T) {
	path := writeCredFile(t, "# tried top to bottom\n\nroot:hunter2\nubuntu:s3cret\n")

	creds, err := loadCredentials(path)
	if err != nil {
		t.Fatalf("loadCredentials: %v", err)
	}

	want := []Credential{
		{User: "root", secret: "hunter2"},
		{User: "ubuntu", secret: "s3cret"},
	}
	if len(creds) != len(want) {
		t.Fatalf("got %d credentials, want %d", len(creds), len(want))
	}
	for i, w := range want {
		if creds[i] != w {
			t.Errorf("cred[%d] = %+v, want %+v", i, creds[i], w)
		}
	}
}

// The password is everything after the first colon, so a password containing
// colons is preserved verbatim.
func TestLoadCredentialsPasswordWithColon(t *testing.T) {
	path := writeCredFile(t, "root:a:b:c\n")

	creds, err := loadCredentials(path)
	if err != nil {
		t.Fatalf("loadCredentials: %v", err)
	}
	if len(creds) != 1 || creds[0].secret != "a:b:c" {
		t.Fatalf("got %+v, want secret %q", creds, "a:b:c")
	}
}

// The order of the credential list is the walk order, so it must be preserved.
func TestLoadCredentialsPreservesOrder(t *testing.T) {
	path := writeCredFile(t, "root:second\nroot:first\nubuntu:third\n")

	creds, err := loadCredentials(path)
	if err != nil {
		t.Fatalf("loadCredentials: %v", err)
	}
	got := []string{creds[0].secret, creds[1].secret, creds[2].secret}
	want := []string{"second", "first", "third"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestLoadCredentialsErrors(t *testing.T) {
	tests := []struct {
		name     string
		contents string
	}{
		{"no colon", "root\n"},
		{"empty user", ":hunter2\n"},
		{"empty password", "root:\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeCredFile(t, tt.contents)
			if _, err := loadCredentials(path); err == nil {
				t.Errorf("loadCredentials(%q) = nil error, want error", tt.contents)
			}
		})
	}
}

// A file with only comments and blank lines yields no credentials; main
// rejects that separately, so loadCredentials must not error on it.
func TestLoadCredentialsEmpty(t *testing.T) {
	path := writeCredFile(t, "# nothing here\n\n")
	creds, err := loadCredentials(path)
	if err != nil {
		t.Fatalf("loadCredentials: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("got %d credentials, want 0", len(creds))
	}
}

func TestLoadCredentialsMissingFile(t *testing.T) {
	if _, err := loadCredentials(filepath.Join(t.TempDir(), "nope.txt")); err == nil {
		t.Error("loadCredentials(missing file) = nil error, want error")
	}
}
