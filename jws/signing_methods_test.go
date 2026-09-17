package jws

import (
	"crypto"
	"testing"

	c "github.com/SermoDigital/jose/crypto"
)

// MySigningMethod is the default "none" algorithm.
var MySigningMethod = &TestSigningMethod{
	Name: "SuperSignerAlgorithm1000",
	Hash: crypto.Hash(0),
}

type TestSigningMethod struct {
	Name string
	Hash crypto.Hash
}

func (m *TestSigningMethod) Verify(_ []byte, _ c.Signature, _ interface{}) error {
	return nil
}

func (m *TestSigningMethod) Sign(_ []byte, _ interface{}) (c.Signature, error) {
	return nil, nil
}

func (m *TestSigningMethod) Alg() string         { return m.Name }
func (m *TestSigningMethod) Sum(b []byte) []byte { return nil }
func (m *TestSigningMethod) Hasher() crypto.Hash { return m.Hash }

// GetSigningMethod is implicitly tested inside the following two functions.

func TestRegisterSigningMethod(t *testing.T) {

	RegisterSigningMethod(MySigningMethod)

	if GetSigningMethod("SuperSignerAlgorithm1000") == nil {
		t.Error("Expected SuperSignerAlgorithm1000, got nil")
	}

	RemoveSigningMethod(MySigningMethod)
}

func TestRemoveSigningMethod(t *testing.T) {
	RegisterSigningMethod(MySigningMethod)

	if GetSigningMethod("SuperSignerAlgorithm1000") == nil {
		t.Error("Expected SuperSignerAlgorithm1000, got nil")
	}

	RemoveSigningMethod(MySigningMethod)

	if a := GetSigningMethod("SuperSignerAlgorithm1000"); a != nil {
		t.Errorf("Expected nil, got %v", a)
	}
}

// A non-zero hash that was never registered is still rejected.
func TestRegisterSigningMethodUnavailableHash(t *testing.T) {
	sm := &TestSigningMethod{
		Name: "UnavailableHashAlgorithm",
		Hash: crypto.MD4,
	}

	if sm.Hasher().Available() {
		t.Skip("crypto.MD4 is registered in this build")
	}

	defer func() {
		if recover() == nil {
			RemoveSigningMethod(sm)
			t.Error("Expected a panic for an unavailable hash, got none")
		}
	}()

	RegisterSigningMethod(sm)
}
