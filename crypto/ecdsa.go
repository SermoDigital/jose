package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
)

// ErrECDSAVerification is missing from crypto/ecdsa compared to crypto/rsa
var ErrECDSAVerification = errors.New("crypto/ecdsa: verification error")

// SigningMethodECDSA implements the ECDSA family of signing methods signing
// methods
type SigningMethodECDSA struct {
	Name string
	Hash crypto.Hash
	KeySize int
	_    struct{}
}

// ECPoint is a marshalling structure for the EC points R and S.
type ECPoint struct {
	R *big.Int
	S *big.Int
}

// Specific instances of EC SigningMethods.
var (
	// SigningMethodES256 implements ES256.
	SigningMethodES256 = &SigningMethodECDSA{
		Name: "ES256",
		Hash: crypto.SHA256,
		KeySize: 32,
	}

	// SigningMethodES384 implements ES384.
	SigningMethodES384 = &SigningMethodECDSA{
		Name: "ES384",
		Hash: crypto.SHA384,
		KeySize: 48,
	}

	// SigningMethodES512 implements ES512.
	SigningMethodES512 = &SigningMethodECDSA{
		Name: "ES512",
		Hash: crypto.SHA512,
		KeySize: 66,
	}
)

// Alg returns the name of the SigningMethodECDSA instance.
func (m *SigningMethodECDSA) Alg() string { return m.Name }

// Verify implements the Verify method from SigningMethod.
// For this verify method, key must be an *ecdsa.PublicKey.
func (m *SigningMethodECDSA) Verify(raw []byte, signature Signature, key interface{}) error {

	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return ErrInvalidKey
	}

	r := big.NewInt(0).SetBytes(signature[:m.KeySize])
	s := big.NewInt(0).SetBytes(signature[m.KeySize:])

	// Verify the signature
	if !ecdsa.Verify(ecdsaKey, m.sum(raw), r, s) {
		return ErrECDSAVerification
	}
	return nil
}

// Sign implements the Sign method from SigningMethod.
// For this signing method, key must be an *ecdsa.PrivateKey.
func (m *SigningMethodECDSA) Sign(data []byte, key interface{}) (Signature, error) {

	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}

	r, s, err := ecdsa.Sign(rand.Reader, ecdsaKey, m.sum(data))
	if err != nil {
		return nil, err
	}

	rBytes := r.Bytes()
	rBytesPadded := make([]byte, m.KeySize)
	copy(rBytesPadded[m.KeySize-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	sBytesPadded := make([]byte, m.KeySize)
	copy(sBytesPadded[m.KeySize-len(sBytes):], sBytes)

	return append(rBytesPadded, sBytesPadded...), nil
}

func (m *SigningMethodECDSA) sum(b []byte) []byte {
	h := m.Hash.New()
	h.Write(b)
	return h.Sum(nil)
}

// Hasher implements the Hasher method from SigningMethod.
func (m *SigningMethodECDSA) Hasher() crypto.Hash {
	return m.Hash
}

// MarshalJSON is in case somebody decides to place SigningMethodECDSA
// inside the Header, presumably because they (wrongly) decided it was a good
// idea to use the SigningMethod itself instead of the SigningMethod's Alg
// method. In order to keep things sane, marshalling this will simply
// return the JSON-compatible representation of m.Alg().
func (m *SigningMethodECDSA) MarshalJSON() ([]byte, error) {
	return []byte(`"` + m.Alg() + `"`), nil
}

var _ json.Marshaler = (*SigningMethodECDSA)(nil)
