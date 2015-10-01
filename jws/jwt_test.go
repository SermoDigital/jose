package jws

import (
	"testing"

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
}
