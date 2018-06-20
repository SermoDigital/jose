package crypto

import (
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ed25519"
)

var (
	ed25519_test_data               = []byte("Hello World!")
	ed25519PubKey, ed25519PriKey, _ = ed25519.GenerateKey(rand.Reader)
)

func TestED25519Verify(t *testing.T) {
	sig, err := SigningMethodED25519.Sign(ed25519_test_data, ed25519PriKey)
	if err != nil {
		t.Error("SigningMethodED25519 Sign failed: ", err)
	}

	if len(sig) != ed25519.SignatureSize {
		t.Error("SigningMethodED25519 Sign failed: ", err)
	}

	if err = SigningMethodED25519.Verify(ed25519_test_data, sig, ed25519PubKey); err != nil {
		t.Error("SigningMethodED25519 Verify failed: ", err)
	}
}

func TestED25519VerifyWrongKey(t *testing.T) {
	_, err := SigningMethodED25519.Sign(ed25519_test_data, ed25519_test_data)

	if err != ErrInvalidKey {
		t.Error("SigningMethodED25519 Verify should failed with ErrInvalidKey: ", err)
	}
}

func TestED25519VerifyWrongSig(t *testing.T) {
	pubKey, priKey, _ := ed25519.GenerateKey(rand.Reader)

	_, err := SigningMethodED25519.Sign(ed25519_test_data, priKey)

	if err != nil {
		t.Error("SigningMethodED25519 Sign failed: ", err)
	}

	err = SigningMethodED25519.Verify(ed25519_test_data, ed25519_test_data, pubKey)
	if err != ErrED25519Verification {
		t.Error("SigningMethodED25519 Verify should failed with ErrED25519Verification: ", err)
	}

}

func TestED25519Sign(t *testing.T) {
	data := []byte("Hello world!")
	sig, err := SigningMethodED25519.Sign(data, ed25519PriKey)
	if err != nil {
		t.Error("SigningMethodED25519 Sign failed: ", err)
	}

	if len(sig) != ed25519.SignatureSize {
		t.Error("SigningMethodED25519 Sign failed: ", err)
	}
}

func TestED25519SignWrongKey(t *testing.T) {
	_, err := SigningMethodED25519.Sign(ed25519_test_data, ed25519_test_data)

	if err != ErrInvalidKey {
		t.Error("SigningMethodED25519 Sign should failed with ErrInvalidKey: ", err)
	}

}
