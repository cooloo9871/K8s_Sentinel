package auth

import (
	"os"
	"path/filepath"
	"testing"
)

// JWT_SECRET overrides the file so the key survives restarts without a PV; a
// trailing newline (typical of a mounted Secret) is trimmed.
func TestSecretFromEnv(t *testing.T) {
	t.Setenv("JWT_SECRET", "0123456789abcdef0123456789abcdef\n")
	path := filepath.Join(t.TempDir(), ".jwt-secret")
	got, err := LoadOrCreateSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "0123456789abcdef0123456789abcdef" {
		t.Errorf("secret = %q, want the env value trimmed", got)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("a secret file was written even though the env provided the key")
	}
}

// A short JWT_SECRET is refused at startup rather than silently weakening every
// session token.
func TestSecretFromEnvTooShort(t *testing.T) {
	t.Setenv("JWT_SECRET", "short")
	if _, err := LoadOrCreateSecret(filepath.Join(t.TempDir(), ".jwt-secret")); err == nil {
		t.Error("a 5-character JWT_SECRET was accepted")
	}
}

// Without the env the file behaviour is unchanged: generated once, reused after.
func TestSecretFileFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".jwt-secret")
	first, err := LoadOrCreateSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Error("the secret changed between loads of the same file")
	}
}
