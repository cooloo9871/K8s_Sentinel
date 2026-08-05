package auth

import (
	"os"
	"path/filepath"
	"testing"
)

// A 32-byte secret is raw random bytes, so its last byte can legitimately be a
// space, tab, CR or LF. Trimming before checking the length misread those as the
// wrong size, wrote a fresh secret over the file, and logged every user out —
// on roughly one restart in 64.
func TestASecretEndingInWhitespaceSurvivesARestart(t *testing.T) {
	for name, last := range map[string]byte{"newline": '\n', "space": ' ', "tab": '\t', "cr": '\r'} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ".jwt-secret")
			secret := make([]byte, 32)
			for i := range secret {
				secret[i] = 'a'
			}
			secret[31] = last
			if err := os.WriteFile(path, secret, 0600); err != nil {
				t.Fatal(err)
			}

			got, err := LoadOrCreateSecret(path)
			if err != nil {
				t.Fatalf("LoadOrCreateSecret: %v", err)
			}
			if string(got) != string(secret) {
				t.Errorf("secret was regenerated instead of reused — every session would be invalidated")
			}
		})
	}
}

// The tolerance for a hand-placed secret given a trailing newline by an editor
// still has to work.
func TestAHandEditedSecretIsStillTrimmed(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".jwt-secret")
	body := make([]byte, 32)
	for i := range body {
		body[i] = 'k'
	}
	if err := os.WriteFile(path, append(body, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadOrCreateSecret(path)
	if err != nil {
		t.Fatalf("LoadOrCreateSecret: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("got %q, want the 32 bytes without the editor's newline", got)
	}
}

// Reading it twice has to give the same answer, or sessions do not survive.
func TestTheSecretIsStableAcrossReloads(t *testing.T) {
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
		t.Error("a freshly created secret was not reused on the next load")
	}
}
