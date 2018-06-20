package crypto

import (
	"crypto"
	"encoding/json"
	"errors"

	"golang.org/x/crypto/ed25519"
)

// ErrED25519Verification is missing from golang.org/x/crypto/ed25519
var ErrED25519Verification = errors.New("crypto/ed25519: verification error")

// SigningMethodEd25519 implements the ED25519 family of signing methods signing
// methods
type SigningMethodEd25519 struct {
	Name string
	Hash crypto.Hash
	_    struct{}
}

var (
	// SigningMethodED25519 implements SigningMethodEd25519.
	SigningMethodED25519 = &SigningMethodEd25519{
		Name: "ED25519",
		Hash: crypto.Hash(0),
	}
)

// Alg returns the name of the SigningMethodEd25519 instance.
func (m *SigningMethodEd25519) Alg() string { return m.Name }

// Verify implements the Verify method from SigningMethod.
// For this verify method, key must be an ed25519.PublicKey.
func (m *SigningMethodEd25519) Verify(raw []byte, signature Signature, key interface{}) error {

	ed25519Key, ok := key.(ed25519.PublicKey)
	if !ok {
		return ErrInvalidKey
	}

	// Check public key size
	if len(ed25519Key) != ed25519.PublicKeySize {
		return ErrInvalidKey
	}

	// Verify the signature
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519Key, raw, signature) {
		return ErrED25519Verification
	}

	return nil
}

// Sign implements the Sign method from SigningMethod.
// For this signing method, key must be an ed25519.PrivateKey.
func (m *SigningMethodEd25519) Sign(data []byte, key interface{}) (Signature, error) {

	ed25519Key, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}

	if len(ed25519Key) != ed25519.PrivateKeySize {
		return nil, ErrInvalidKey
	}

	return ed25519.Sign(ed25519Key, data), nil
}

// Hasher implements the Hasher method from SigningMethod.
func (m *SigningMethodEd25519) Hasher() crypto.Hash {
	return m.Hash
}

// MarshalJSON is in case somebody decides to place SigningMethodEd25519
// inside the Header, presumably because they (wrongly) decided it was a good
// idea to use the SigningMethod itself instead of the SigningMethod's Alg
// method. In order to keep things sane, marshalling this will simply
// return the JSON-compatible representation of m.Alg().
func (m *SigningMethodEd25519) MarshalJSON() ([]byte, error) {
	return []byte(`"` + m.Alg() + `"`), nil
}

var _ json.Marshaler = (*SigningMethodEd25519)(nil)
