package jws

import (
	"crypto"
	"sync"
)

var (
	mu = &sync.RWMutex{}

	signingMethods = map[string]SigningMethod{
		SigningMethodES256.Alg(): SigningMethodES256,
		SigningMethodES384.Alg(): SigningMethodES384,
		SigningMethodES512.Alg(): SigningMethodES512,

		SigningMethodPS256.Alg(): SigningMethodPS256,
		SigningMethodPS384.Alg(): SigningMethodPS384,
		SigningMethodPS512.Alg(): SigningMethodPS512,

		SigningMethodRS256.Alg(): SigningMethodRS256,
		SigningMethodRS384.Alg(): SigningMethodRS384,
		SigningMethodRS512.Alg(): SigningMethodRS512,

		SigningMethodHS256.Alg(): SigningMethodHS256,
		SigningMethodHS384.Alg(): SigningMethodHS384,
		SigningMethodHS512.Alg(): SigningMethodHS512,
	}
)

// SigningMethod is an interface that provides a way to sign JWS tokens.
type SigningMethod interface {
	// Alg describes the signing algorithm, and is used to uniquely
	// describe the specific SigningMethod.
	Alg() string

	// Verify accepts the raw content, the signature, and the key used
	// to sign the raw content, and returns any errors found while validating
	// the signature and content.
	Verify(raw []byte, sig Signature, key interface{}) error

	// Sign returns a Signature for the raw bytes, as well as any errors
	// that occurred during the signing.
	Sign(raw []byte, key interface{}) (Signature, error)

	// Used to cause quick panics when a SigningMethod whose form of hashing
	// isn't linked in the binary when you register a SigningMethod.
	// To spoof this, see "SigningMethodNone".
	Hasher() crypto.Hash
}

// RegisterSigningMethod registers the SigningMethod in the global map.
// This is typically done inside the caller's init function.
func RegisterSigningMethod(sm SigningMethod) {
	if GetSigningMethod(sm.Alg()) != nil {
		panic("jose/jws: cannot duplicate signing methods")
	}

	if !sm.Hasher().Available() {
		panic("jose/jws: specific hash is unavailable")
	}

	mu.Lock()
	signingMethods[sm.Alg()] = sm
	mu.Unlock()
}

// RemoveSigningMethod removes the SigningMethod from the global map.
func RemoveSigningMethod(sm SigningMethod) {
	mu.Lock()
	delete(signingMethods, sm.Alg())
	mu.Unlock()
}

// GetSigningMethod retrieves a SigningMethod from the global map.
func GetSigningMethod(alg string) SigningMethod {
	mu.RLock()
	defer mu.RUnlock()
	return signingMethods[alg]
}
