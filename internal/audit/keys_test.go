package audit

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestLoadOrCreateSigningKey_CreatesThenReuses confirms the first call generates
// and persists a keypair (private + public files), reports created=true, and a
// second call reuses the same key (created=false) rather than minting a new one.
func TestLoadOrCreateSigningKey_CreatesThenReuses(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "signing.key")

	priv1, created, err := LoadOrCreateSigningKey(keyPath)
	if err != nil {
		t.Fatalf("first LoadOrCreateSigningKey: %v", err)
	}
	if !created {
		t.Error("first call created=false, want true")
	}

	// Both files exist; the public one sits at the derived .pub path.
	pubPath := PublicKeyPath(keyPath)
	if pubPath != filepath.Join(dir, "signing.pub") {
		t.Errorf("PublicKeyPath = %q, want signing.pub next to the key", pubPath)
	}
	for _, p := range []string{keyPath, pubPath} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected %q to exist: %v", p, err)
		}
	}

	priv2, created, err := LoadOrCreateSigningKey(keyPath)
	if err != nil {
		t.Fatalf("second LoadOrCreateSigningKey: %v", err)
	}
	if created {
		t.Error("second call created=true, want false (reuse)")
	}
	if !bytes.Equal(priv1, priv2) {
		t.Error("second call returned a different key; the key was not reused")
	}
}

// TestLoadPublicKey_MatchesPrivate confirms the persisted public key is the one
// that pairs with the generated private key: a signature made with the private
// key verifies under the loaded public key.
func TestLoadPublicKey_MatchesPrivate(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "signing.key")

	priv, _, err := LoadOrCreateSigningKey(keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateSigningKey: %v", err)
	}
	pub, err := LoadPublicKey(PublicKeyPath(keyPath))
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}

	msg := []byte("ganimedes audit entry")
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(pub, msg, sig) {
		t.Error("signature from the private key did not verify under the loaded public key")
	}
}

// TestLoadSigningKey_Missing: a missing key file is reported as os.ErrNotExist so
// LoadOrCreateSigningKey can tell "generate one" from a real failure.
func TestLoadSigningKey_Missing(t *testing.T) {
	_, err := LoadSigningKey(filepath.Join(t.TempDir(), "nope.key"))
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LoadSigningKey(missing) err = %v, want an os.ErrNotExist wrap", err)
	}
}

// TestLoadPublicKey_Garbage: a file that is not a PEM public key is a clear
// error, not a nil key that would make every signature "verify".
func TestLoadPublicKey_Garbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.pub")
	if err := os.WriteFile(path, []byte("not a pem key"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := LoadPublicKey(path); err == nil {
		t.Fatal("LoadPublicKey accepted garbage, want an error")
	}
}

// TestLoadOrCreateSigningKey_CorruptExisting: an existing but unparseable key file
// is a hard error, not a trigger to silently overwrite it with a fresh key.
func TestLoadOrCreateSigningKey_CorruptExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.key")
	if err := os.WriteFile(path, []byte("garbage, not a PEM key"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, _, err := LoadOrCreateSigningKey(path); err == nil {
		t.Fatal("LoadOrCreateSigningKey silently accepted a corrupt key file, want an error")
	}
}
