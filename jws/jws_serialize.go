package jws

import (
	"bytes"
	"encoding/json"
)

// Flat serializes the JWS to its "flattened" form per
// https://tools.ietf.org/html/rfc7515#section-7.2.2
func (j *JWS) Flat(key interface{}) ([]byte, error) {
	if len(j.sb) < 1 {
		return nil, ErrNotEnoughMethods
	}
	if err := j.sign(key); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Payload rawBase64 `json:"payload"`
		sigHead
	}{
		Payload: j.plcache,
		sigHead: j.sb[0],
	})
}

// General serializes the JWS into its "general" form per
// https://tools.ietf.org/html/rfc7515#section-7.2.1
//
// If only one key is passed it's used for all the provided
// crypto.SigningMethods. Otherwise, len(keys) must equal the number
// of crypto.SigningMethods added.
func (j *JWS) General(keys ...interface{}) ([]byte, error) {
	if err := j.sign(keys...); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Payload    rawBase64 `json:"payload"`
		Signatures []sigHead `json:"signatures"`
	}{
		Payload:    j.plcache,
		Signatures: j.sb,
	})
}

// Compact serializes the JWS into its "compact" form per
// https://tools.ietf.org/html/rfc7515#section-7.1
func (j *JWS) Compact(key interface{}) ([]byte, error) {
	if len(j.sb) < 1 {
		return nil, ErrNotEnoughMethods
	}

	if err := j.sign(key); err != nil {
		return nil, err
	}

	sig, err := j.sb[0].Signature.Base64()
	if err != nil {
		return nil, err
	}
	return format(
		j.sb[0].Protected,
		j.plcache,
		sig,
	), nil
}

// sign signs each index of j's sb member.
func (j *JWS) sign(keys ...interface{}) error {
	if err := j.cache(); err != nil {
		return err
	}

	if len(keys) < 1 ||
		len(keys) > 1 && len(keys) != len(j.sb) {
		return ErrNotEnoughKeys
	}

	if len(keys) == 1 {
		k := keys[0]
		keys = make([]interface{}, len(j.sb))
		for i := range keys {
			keys[i] = k
		}
	}

	for i := range j.sb {
		if err := j.sb[i].cache(); err != nil {
			return err
		}

		raw := format(j.sb[i].Protected, j.plcache)
		sig, err := j.sb[i].method.Sign(raw, keys[i])
		if err != nil {
			return err
		}
		j.sb[i].Signature = sig
	}

	return nil
}

// cache marshals the payload, but only if it's changed since the last cache.
func (j *JWS) cache() error {
	if !j.clean {
		var err error
		j.plcache, err = j.payload.Base64()
		j.clean = err == nil
		return err
	}
	return nil
}

// cache marshals the protected and unprotected headers, but only if
// they've changed since their last cache.
func (s *sigHead) cache() error {
	if !s.clean {
		var err error

		s.Protected, err = s.protected.Base64()
		if err != nil {
			goto err_return
		}

		s.Unprotected, err = s.unprotected.Base64()
		if err != nil {
			goto err_return
		}

	err_return:
		s.clean = err == nil
		return err
	}
	return nil
}

// format formats a slice of bytes in the order given, joining
// them with a period.
func format(a ...[]byte) []byte {
	return bytes.Join(a, []byte{'.'})
}
