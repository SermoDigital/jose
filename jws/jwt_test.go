package jws

import (
	"errors"
	"testing"
	"time"

	"github.com/SermoDigital/jose/crypto"
)

var claims = Claims{
	"name": "Eric",
	"scopes": []string{
		"user.account.info",
		"user.account.update",
		"user.account.delete",
	},
	"admin": true,
	"data": struct {
		Foo, Bar int
	}{
		Foo: 12,
		Bar: 50,
	},
}

func TestBasicJWT(t *testing.T) {
	j := NewJWT(claims, crypto.SigningMethodRS512)
	b, err := j.Serialize(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	w, err := ParseJWT(b)
	if err != nil {
		t.Error(err)
	}

	if w.Claims().Get("name") != "Eric" &&
		w.Claims().Get("admin") != true &&
		w.Claims().Get("scopes").([]string)[0] != "user.account.info" {
		Error(t, claims, w.Claims())
	}

	if err := w.Validate(now(), rsaPub, crypto.SigningMethodRS512); err != nil {
		t.Error(err)
	}
}

func TestJWTValidator(t *testing.T) {
	j := NewJWT(claims, crypto.SigningMethodRS512)
	j.Claims().SetIssuer("example.com")

	b, err := j.Serialize(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	w, err := ParseJWT(b)
	if err != nil {
		t.Error(err)
	}

	d := float64(time.Now().Add(1 * time.Hour).Unix())
	fn := func(c Claims) error {
		if c.Get("name") != "Eric" &&
			c.Get("admin") != true &&
			c.Get("scopes").([]string)[0] != "user.account.info" {
			return errors.New("invalid")
		}
		return nil
	}
	v := NewValidator(Claims{"iss": "example.com"}, d, d, fn)
	if err := w.Validate(now(), rsaPub, crypto.SigningMethodRS512, v); err != nil {
		t.Error(err)
	}
}
