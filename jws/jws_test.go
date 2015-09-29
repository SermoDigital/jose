package jws

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
)

type easy []byte

func (e *easy) UnmarshalJSON(b []byte) error {
	// json.Marshal encodes easy as it would a []byte, so in
	// `"base64"` format.
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(b)-2))
	n, err := base64.StdEncoding.Decode(dst, b[1:len(b)-1])
	if err != nil {
		return err
	}
	*e = easy(dst[:n])
	return nil
}

var _ json.Unmarshaler = (*easy)(nil)

var easyData = easy(`"easy data!"`)

func TestParseWithUnmarshaler(t *testing.T) {
	j := New(easyData, SigningMethodRS512)
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
