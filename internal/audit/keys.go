package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// The audit log is signed with Ed25519 (Constitution Art. 2.3), so a verifier
// can prove not only that history was not edited (the hash chain) but that these
// entries were produced by the holder of a specific key (authenticity). Keys are
// stored as PEM so standard tooling (openssl, other JCS verifiers) can read them
// and an offline third party can verify with only the public key and the log.
const (
	pemTypePrivate = "PRIVATE KEY"
	pemTypePublic  = "PUBLIC KEY"
)

// PublicKeyPath returns the conventional path of the public key that pairs with
// the signing key at privPath: the same name with a .pub extension. Verify reads
// it by default, so a signed log checks out on the same host with no flags.
func PublicKeyPath(privPath string) string {
	return strings.TrimSuffix(privPath, ".key") + ".pub"
}

// LoadOrCreateSigningKey loads the Ed25519 signing key at path, generating and
// persisting a fresh keypair if the file does not yet exist. The bool return is
// true when a new key was created, so the caller can tell the user.
//
// A new private key is written to path with 0600 permissions (it must stay
// secret: whoever holds it can forge valid signatures), and the matching public
// key is written beside it at PublicKeyPath(path) with 0644 so it can be shared
// with anyone who needs to verify the log. Both are PEM-encoded (PKCS#8 for the
// private key, PKIX for the public).
//
// An existing private key is reused only with its matching public key; a missing
// public half is recreated from it. An orphaned, invalid, or mismatched public
// file is never replaced. The two-file publication is not atomic: failures are
// reported and a later call can repair a missing public half.
func LoadOrCreateSigningKey(path string) (priv ed25519.PrivateKey, created bool, err error) {
	priv, err = LoadSigningKey(path)
	switch {
	case err == nil:
		if err := ensurePublicKey(PublicKeyPath(path), priv); err != nil {
			return nil, false, err
		}
		return priv, false, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, false, err
	}
	// A public key may be the only surviving trust anchor for older logs. A
	// missing private half must never turn into permission to replace it. Lstat
	// also treats a dangling symlink as existing material rather than an empty
	// destination where a new keypair may be published.
	pubPath := PublicKeyPath(path)
	if _, err := os.Lstat(pubPath); err == nil {
		return nil, false, fmt.Errorf("public key %q exists without its signing key; refusing to replace it", pubPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, false, fmt.Errorf("checking public key %q: %w", pubPath, err)
	}

	// Not there yet: generate, persist, and report it as newly created.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, false, fmt.Errorf("generating signing key: %w", err)
	}
	if err := writePrivateKey(path, priv); err != nil {
		return nil, false, err
	}
	if err := writePublicKey(PublicKeyPath(path), pub); err != nil {
		return nil, false, err
	}
	return priv, true, nil
}

// Keypair publication is not atomic. A failed public-file write can leave a
// valid private key behind; retrying must repair only the missing public half,
// never mint a replacement private key or overwrite a different trust anchor.
func ensurePublicKey(path string, priv ed25519.PrivateKey) error {
	derived := ed25519.PublicKey(priv[ed25519.SeedSize:])
	pub, err := LoadPublicKey(path)
	if errors.Is(err, os.ErrNotExist) {
		return writePublicKey(path, derived)
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(pub, derived) {
		return fmt.Errorf("public key %q does not match the signing key; refusing to replace it", path)
	}
	return nil
}

// LoadSigningKey loads an Ed25519 private key from a PEM PKCS#8 file. A missing
// file returns an error wrapping os.ErrNotExist, so callers can tell "not created
// yet" apart from a real read or parse failure.
func LoadSigningKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading signing key %q: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != pemTypePrivate {
		return nil, fmt.Errorf("signing key %q: not a PEM %q block", path, pemTypePrivate)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing signing key %q: %w", path, err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key %q is %T, want ed25519", path, key)
	}
	return priv, nil
}

// LoadPublicKey loads an Ed25519 public key from a PEM PKIX file. It is what
// Verify checks signatures against; an offline verifier needs only this file and
// the log, never the private key.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading public key %q: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != pemTypePublic {
		return nil, fmt.Errorf("public key %q: not a PEM %q block", path, pemTypePublic)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key %q: %w", path, err)
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key %q is %T, want ed25519", path, key)
	}
	return pub, nil
}

// writePrivateKey PEM-encodes priv (PKCS#8) and writes it to path at 0600.
func writePrivateKey(path string, priv ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("encoding signing key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: pemTypePrivate, Bytes: der})
	// O_EXCL: never clobber an existing key. Silently replacing the material that
	// seals the whole log would be a security bug, not a convenience.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("creating signing key %q: %w", path, err)
	}
	if _, err := f.Write(pemBytes); err != nil {
		return errors.Join(fmt.Errorf("writing signing key %q: %w", path, err), f.Close())
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing signing key %q: %w", path, err)
	}
	return nil
}

// writePublicKey PEM-encodes pub (PKIX) and writes it to path at 0644.
func writePublicKey(path string, pub ed25519.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("encoding public key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: pemTypePublic, Bytes: der})
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("creating public key %q: %w", path, err)
	}
	if _, err := f.Write(pemBytes); err != nil {
		return errors.Join(fmt.Errorf("writing public key %q: %w", path, err), f.Close())
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing public key %q: %w", path, err)
	}
	return nil
}
