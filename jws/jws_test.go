package jws

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/SermoDigital/jose/crypto"
)

type easy []byte

func (e *easy) UnmarshalJSON(b []byte) error {
	if len(b) > 1 && b[0] == '"' && b[len(b)-1] == '"' {
		b = b[1 : len(b)-1]
	}
	// json.Marshal encodes easy as it would a []byte, so in
	// `"base64"` format.
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(b)))
	n, err := base64.StdEncoding.Decode(dst, b)
	if err != nil {
		return err
	}
	*e = easy(dst[:n])
	return nil
}

var _ json.Unmarshaler = (*easy)(nil)

var easyData = easy("easy data!")

func TestParseWithUnmarshaler(t *testing.T) {
	j := New(easyData, crypto.SigningMethodRS512)
	b, err := j.Flat(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	var e easy
	j2, err := Parse(b, &e)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(easyData, *j2.payload.v.(*easy)) {
		Error(t, easyData, *j2.payload.v.(*easy))
	}
}

func TestParseCompact(t *testing.T) {
	j := New(easyData, crypto.SigningMethodRS512)
	b, err := j.Compact(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	j2, err := ParseCompact(b)
	if err != nil {
		t.Error(err)
	}

	var k easy
	if err := k.UnmarshalJSON([]byte(j2.payload.v.(string))); err != nil {
		t.Error(err)
	}

	if !bytes.Equal(k, easyData) {
		Error(t, easyData, k)
	}
}

func TestParseGeneral(t *testing.T) {
	sm := []crypto.SigningMethod{crypto.SigningMethodRS512, crypto.SigningMethodPS384, crypto.SigningMethodPS256}
	j := New(easyData, sm...)
	b, err := j.General(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	j2, err := ParseGeneral(b)
	if err != nil {
		t.Error(err)
	}

	for i, v := range j2.sb {
		k := v.protected.Get("alg").(string)
		if k != sm[i].Alg() {
			Error(t, sm[i].Alg(), k)
		}
	}
}

func TestValidateMulti(t *testing.T) {
	sm := []crypto.SigningMethod{crypto.SigningMethodRS512, crypto.SigningMethodPS384, crypto.SigningMethodPS256}
	j := New(easyData, sm...)
	b, err := j.General(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	j2, err := ParseGeneral(b)
	if err != nil {
		t.Error(err)
	}

	keys := []interface{}{rsaPub, rsaPub, rsaPub}
	if err := j2.ValidateMulti(keys, sm, Any); err != nil {
		t.Error(err)
	}
}

func TestValidateMultiMismatchedAlgs(t *testing.T) {
	sm := []crypto.SigningMethod{crypto.SigningMethodRS256, crypto.SigningMethodPS384, crypto.SigningMethodPS512}
	j := New(easyData, sm...)
	b, err := j.General(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	j2, err := ParseGeneral(b)
	if err != nil {
		t.Error(err)
	}

	// Shuffle it.
	sm = []crypto.SigningMethod{crypto.SigningMethodRS512, crypto.SigningMethodPS256, crypto.SigningMethodPS384}

	keys := []interface{}{rsaPub, rsaPub, rsaPub}
	if err := j2.ValidateMulti(keys, sm, Any); err == nil {
		t.Error("Should NOT be nil")
	}
}

func TestValidateMultiNotEnoughMethods(t *testing.T) {
	sm := []crypto.SigningMethod{crypto.SigningMethodRS256, crypto.SigningMethodPS384, crypto.SigningMethodPS512}
	j := New(easyData, sm...)
	b, err := j.General(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	j2, err := ParseGeneral(b)
	if err != nil {
		t.Error(err)
	}

	sm = sm[0 : len(sm)-1]

	keys := []interface{}{rsaPub, rsaPub, rsaPub}
	if err := j2.ValidateMulti(keys, sm, Any); err == nil {
		t.Error("Should NOT be nil")
	}
}

func TestValidateMultiNotEnoughKeys(t *testing.T) {
	sm := []crypto.SigningMethod{crypto.SigningMethodRS256, crypto.SigningMethodPS384, crypto.SigningMethodPS512}
	j := New(easyData, sm...)
	b, err := j.General(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	j2, err := ParseGeneral(b)
	if err != nil {
		t.Error(err)
	}

	keys := []interface{}{rsaPub, rsaPub}
	if err := j2.ValidateMulti(keys, sm, Any); err == nil {
		t.Error("Should NOT be nil")
	}
}

func TestValidate(t *testing.T) {
	j := New(easyData, crypto.SigningMethodPS512)
	b, err := j.Flat(rsaPriv)
	if err != nil {
		t.Error(err)
	}

	j2, err := ParseFlat(b)
	if err != nil {
		t.Error(err)
	}

	if err := j2.Validate(rsaPub, crypto.SigningMethodPS512); err != nil {
		t.Error(err)
	}
}
