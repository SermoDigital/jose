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
	if exp, ok := c.Expiration(); ok {
		if !within(exp, expLeeway, now) {
			return ErrTokenIsExpired
		}
	}

	if nbf, ok := c.NotBefore(); ok {
		if !within(nbf, nbfLeeway, now) {
			return ErrTokenNotYetValid
		}
	}
	return nil
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
	return json.Marshal(map[string]interface{}(c))
}

// Base64 implements the Encoder interface.
func (c Claims) Base64() ([]byte, error) {
	b, err := c.MarshalJSON()
	if err != nil {
		return nil, err
	}
	return jose.Base64Encode(b), nil
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

// Issuer retrieves claim "iss" per its type in
// https://tools.ietf.org/html/rfc7519#section-4.1.1
func (c Claims) Issuer() (string, bool) {
	v, ok := c.Get("iss").(string)
	return v, ok
}

// Subject retrieves claim "sub" per its type in
// https://tools.ietf.org/html/rfc7519#section-4.1.2
func (c Claims) Subject() (string, bool) {
	v, ok := c.Get("sub").(string)
	return v, ok
}

// Audience retrieves claim "aud" per its type in
// https://tools.ietf.org/html/rfc7519#section-4.1.3
func (c Claims) Audience() (interface{}, bool) {
	switch t := c.Get("aud").(type) {
	case string, []string:
		return t, true
	case interface{}, []interface{}:
		return stringify(t)
	default:
		return nil, false
	}
}

func stringify(a ...interface{}) ([]string, bool) {
	if len(a) == 0 {
		return nil, false
	}

	s := make([]string, len(a))
	for i := range a {
		str, ok := a[i].(string)
		if !ok {
			return nil, false
		}
		s[i] = str
	}
	return s, true
}

// Expiration retrieves claim "exp" per its type in
// https://tools.ietf.org/html/rfc7519#section-4.1.4
func (c Claims) Expiration() (int64, bool) {
	v, ok := c.Get("exp").(int64)
	return v, ok
}

// NotBefore retrieves claim "nbf" per its type in
// https://tools.ietf.org/html/rfc7519#section-4.1.5
func (c Claims) NotBefore() (int64, bool) {
	v, ok := c.Get("nbf").(int64)
	return v, ok
}

// IssuedAt retrieves claim "iat" per its type in
// https://tools.ietf.org/html/rfc7519#section-4.1.6
func (c Claims) IssuedAt() (int64, bool) {
	v, ok := c.Get("iat").(int64)
	return v, ok
}

// JWTID retrieves claim "jti" per its type in
// https://tools.ietf.org/html/rfc7519#section-4.1.7
func (c Claims) JWTID() (string, bool) {
	v, ok := c.Get("jti").(string)
	return v, ok
}

// RemoveIssuer deletes claim "iss" from c.
func (c Claims) RemoveIssuer() { c.Del("iss") }

// RemoveSubject deletes claim "sub" from c.
func (c Claims) RemoveSubject() { c.Del("sub") }

// RemoveAudience deletes claim "aud" from c.
func (c Claims) RemoveAudience() { c.Del("aud") }

// RemoveExpiration deletes claim "exp" from c.
func (c Claims) RemoveExpiration() { c.Del("exp") }

// RemoveNotBefore deletes claim "nbf" from c.
func (c Claims) RemoveNotBefore() { c.Del("nbf") }

// RemoveIssuedAt deletes claim "iat" from c.
func (c Claims) RemoveIssuedAt() { c.Del("iat") }

// RemoveJWTID deletes claim "jti" from c.
func (c Claims) RemoveJWTID() { c.Del("jti") }

// SetIssuer sets claim "iss" per its type in
// https://tools.ietf.org/html/rfc7519#section-4.1.1
func (c Claims) SetIssuer(issuer string) {
	c.Set("iss", issuer)
}

// SetSubject sets claim "iss" per its type in
// https://tools.ietf.org/html/rfc7519#section-4.1.2
func (c Claims) SetSubject(subject string) {
	c.Set("sub", subject)
}

// SetAudience sets claim "aud" per its type in
// https://tools.ietf.org/html/rfc7519#section-4.1.3
func (c Claims) SetAudience(audience ...string) {
	if len(audience) == 1 {
		c.Set("aud", audience[0])
	} else {
		c.Set("aud", audience)
	}
}

// SetExpiration sets claim "exp" per its type in
// https://tools.ietf.org/html/rfc7519#section-4.1.4
func (c Claims) SetExpiration(expiration int64) {
	c.Set("exp", expiration)
}

// SetNotBefore sets claim "nbf" per its type in
// https://tools.ietf.org/html/rfc7519#section-4.1.5
func (c Claims) SetNotBefore(notBefore int64) {
	c.Set("nbf", notBefore)
}

// SetIssuedAt sets claim "iat" per its type in
// https://tools.ietf.org/html/rfc7519#section-4.1.6
func (c Claims) SetIssuedAt(issuedAt int64) {
	c.Set("iat", issuedAt)
}

// SetJWTID sets claim "jti" per its type in
// https://tools.ietf.org/html/rfc7519#section-4.1.7
func (c Claims) SetJWTID(uniqueID string) {
	c.Set("jti", uniqueID)
}

var (
	_ json.Marshaler   = (Claims)(nil)
	_ json.Unmarshaler = (*Claims)(nil)
)
