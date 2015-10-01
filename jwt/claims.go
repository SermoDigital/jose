package jwt

import (
	"encoding/json"

	"github.com/SermoDigital/jose"
)

// Claims implements a set of JOSE Claims with the addition of some helper
// methods, similar to net/url.Values.
type Claims map[string]interface{}

// Validate validates the Claims per the claims found in
// https://tools.ietf.org/html/rfc7519#section-4.1
func (c Claims) Validate(now, expLeeway, nbfLeeway int64) error {
	if exp, ok := c.expiration(); ok {
		if !within(exp, expLeeway, now) {
			return ErrTokenIsExpired
		}
	}

	if nbf, ok := c.notBefore(); ok {
		if !within(nbf, nbfLeeway, now) {
			return ErrTokenNotYetValid
		}
	}
	return nil
}

func (c Claims) expiration() (int64, bool) {
	v, ok := c.Get("exp").(int64)
	return v, ok
}

func (c Claims) notBefore() (int64, bool) {
	v, ok := c.Get("nbf").(int64)
	return v, ok
}

func within(cur, delta, max int64) bool {
	return cur+delta < max || cur-delta < max
}

// Get retrieves the value corresponding with key from the Claims.
func (c Claims) Get(key string) interface{} {
	if c == nil {
		return nil
	}
	return c[key]
}

// Set sets Claims[key] = val. It'll overwrite without warning.
func (c Claims) Set(key string, val interface{}) {
	c[key] = val
}

// Del removes the value that corresponds with key from the Claims.
func (c Claims) Del(key string) {
	delete(c, key)
}

// Has returns true if a value for the given key exists inside the Claims.
func (c Claims) Has(key string) bool {
	_, ok := c[key]
	return ok
}

// MarshalJSON implements json.Marshaler for Claims.
func (c Claims) MarshalJSON() ([]byte, error) {
	if c == nil || len(c) == 0 {
		return nil, nil
	}
	b, err := json.Marshal(map[string]interface{}(c))
	if err != nil {
		return nil, err
	}
	return jose.EncodeEscape(b), nil
}

// Base64 implements the Encoder interface.
func (c Claims) Base64() ([]byte, error) {
	return c.MarshalJSON()
}

// UnmarshalJSON implements json.Unmarshaler for Claims.
func (c *Claims) UnmarshalJSON(b []byte) error {
	if b == nil {
		return nil
	}

	b, err := jose.DecodeEscaped(b)
	if err != nil {
		return err
	}

	// Since json.Unmarshal calls UnmarshalJSON,
	// calling json.Unmarshal on *p would be infinitely recursive
	// A temp variable is needed because &map[string]interface{}(*p) is
	// invalid Go.

	tmp := map[string]interface{}(*c)
	if err = json.Unmarshal(b, &tmp); err != nil {
		return err
	}
	*c = Claims(tmp)
	return nil
}

var (
	_ json.Marshaler   = (Claims)(nil)
	_ json.Unmarshaler = (*Claims)(nil)
)
