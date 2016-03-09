package jwt_test

import (
	"testing"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
)

func TestMultipleAudienceBug_AfterMarshal(t *testing.T) {

	// Create JWS claims
	claims := jws.Claims{}
	claims.SetAudience("example.com", "api.example.com")

	token := jws.NewJWT(claims, crypto.SigningMethodHS256)
	serializedToken, _ := token.Serialize([]byte("abcdef"))

	// Unmarshal JSON
	newToken, _ := jws.ParseJWT(serializedToken)

	c := newToken.Claims()

	// Get Audience
	aud, ok := c.Audience()
	if !ok {

		// Fails
		t.Fail()
	}

	t.Logf("aud Value: %s", aud)
	t.Logf("aud Type : %T", aud)
}

func TestMultipleAudienceFix_AfterMarshal(t *testing.T) {
	// Create JWS claims
	claims := jws.Claims{}
	claims.SetAudience("example.com", "api.example.com")

	token := jws.NewJWT(claims, crypto.SigningMethodHS256)
	serializedToken, _ := token.Serialize([]byte("abcdef"))

	// Unmarshal JSON
	newToken, _ := jws.ParseJWT(serializedToken)

	c := newToken.Claims()

	// Get Audience
	aud, ok := c.Audience()
	if !ok {

		// Fails
		t.Fail()
	}

	t.Logf("aud len(): %d", len(aud))
	t.Logf("aud Value: %s", aud)
	t.Logf("aud Type : %T", aud)
}

func TestSingleAudienceFix_AfterMarshal(t *testing.T) {
	// Create JWS claims
	claims := jws.Claims{}
	claims.SetAudience("example.com")

	token := jws.NewJWT(claims, crypto.SigningMethodHS256)
	serializedToken, _ := token.Serialize([]byte("abcdef"))

	// Unmarshal JSON
	newToken, _ := jws.ParseJWT(serializedToken)
	c := newToken.Claims()

	// Get Audience
	aud, ok := c.Audience()
	if !ok {

		// Fails
		t.Fail()
	}

	t.Logf("aud len(): %d", len(aud))
	t.Logf("aud Value: %s", aud)
	t.Logf("aud Type : %T", aud)
}
