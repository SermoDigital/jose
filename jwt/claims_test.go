package jwt_test

import (
	"testing"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
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

func TestValidate(t *testing.T) {
	const before, now, after, leeway float64 = 10, 20, 30, 5

	exp := func(t float64) jwt.Claims {
		return jwt.Claims{"exp": t}
	}
	nbf := func(t float64) jwt.Claims {
		return jwt.Claims{"nbf": t}
	}

	var tests = []struct {
		desc      string
		c         jwt.Claims
		now       float64
		expLeeway float64
		nbfLeeway float64
		err       error
	}{
		// test for nbf < now <= exp
		{desc: "exp == nil && nbf == nil", c: jwt.Claims{}, now: now, err: nil},

		{desc: "now > exp", now: now, c: exp(before), err: jwt.ErrTokenIsExpired},
		{desc: "now = exp", now: now, c: exp(now), err: nil},
		{desc: "now < exp", now: now, c: exp(after), err: nil},

		{desc: "nbf < now", c: nbf(before), now: now, err: nil},
		{desc: "nbf = now", c: nbf(now), now: now, err: jwt.ErrTokenNotYetValid},
		{desc: "nbf > now", c: nbf(after), now: now, err: jwt.ErrTokenNotYetValid},

		// test for nbf-x < now <= exp+y
		{desc: "now < exp+x", now: now + leeway - 1, expLeeway: leeway, c: exp(now), err: nil},
		{desc: "now = exp+x", now: now + leeway, expLeeway: leeway, c: exp(now), err: nil},
		{desc: "now > exp+x", now: now + leeway + 1, expLeeway: leeway, c: exp(now), err: jwt.ErrTokenIsExpired},

		{desc: "nbf-x > now", c: nbf(now), nbfLeeway: leeway, now: now - leeway + 1, err: nil},
		{desc: "nbf-x = now", c: nbf(now), nbfLeeway: leeway, now: now - leeway, err: jwt.ErrTokenNotYetValid},
		{desc: "nbf-x < now", c: nbf(now), nbfLeeway: leeway, now: now - leeway - 1, err: jwt.ErrTokenNotYetValid},
	}

	for i, tt := range tests {
		if got, want := tt.c.Validate(tt.now, tt.expLeeway, tt.nbfLeeway), tt.err; got != want {
			t.Errorf("%d - %q: got %v want %v", i, tt.desc, got, want)
		}
	}
}
