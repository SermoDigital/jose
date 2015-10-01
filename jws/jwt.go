package jws

import (
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jwt"
)

// Claims represents a set of JOSE Claims.
type Claims jwt.Claims

// NewJWT creates a new JWT with the given claims.
func NewJWT(claims Claims, method crypto.SigningMethod) jwt.JWT {
	j := New(claims, method)
	j.isJWT = true
	return j
}

// Serialize helps implements jwt.JWT.
func (j *JWS) Serialize(key interface{}) ([]byte, error) {
	if j.isJWT {
		return j.Compact(key)
	}
	return nil, ErrIsNotJWT
}

// Claims helps implements jwt.JWT.
func (j *JWS) Claims() jwt.Claims {
	if j.isJWT {
		if c, ok := j.payload.v.(Claims); ok {
			return jwt.Claims(c)
		}
	}
	return nil
}

// ParseJWT parses a serialized jwt.JWT into a physical jwt.JWT.
// If its payload isn't a set of claims (or able to be coerced into
// a set of claims) it'll return an error stating the
// JWT isn't a JWT.
func ParseJWT(encoded []byte) (jwt.JWT, error) {
	t, err := ParseCompact(encoded)
	if err != nil {
		return nil, err
	}
	c, ok := t.payload.v.(map[string]interface{})
	if !ok {
		return nil, ErrIsNotJWT
	}
	t.payload.v = Claims(c)
	t.isJWT = true
	return t, nil
}

// IsJWT returns true if the JWS is a JWT.
func (j *JWS) IsJWT() bool { return j.isJWT }

// Verify helps implement jwt.JWT.
func (j *JWS) Verify(key interface{}, m crypto.SigningMethod, o ...jwt.Opts) error {
	if j.isJWT {
		if err := j.Validate(key, m); err != nil {
			return err
		}
		c, ok := j.payload.v.(Claims)
		if ok {
			var p jwt.Opts
			if len(o) > 0 {
				p = o[0]
			}

			if p.Fn != nil {
				if err := p.Fn(jwt.Claims(c)); err != nil {
					return err
				}
			}
			return jwt.Claims(c).Validate(time.Now().Unix(), p.EXP, p.NBF)
		}
	}
	return ErrIsNotJWT
}

// Opts represents some of the validation options.
// It mimics jwt.Opts.
type Opts struct {
	EXP int64 // EXPLeeway
	NBF int64 // NBFLeeway
	Fn  func(Claims) error
	_   struct{}
}

// C is shorthand for Convert(fn).
func (o Opts) C() jwt.Opts { return o.Convert() }

// Convert converts Opts into jwt.Opts.
func (o Opts) Convert() jwt.Opts {
	p := jwt.Opts{
		EXP: o.EXP,
		NBF: o.NBF,
	}
	if o.Fn != nil {
		p.Fn = func(c jwt.Claims) error {
			return o.Fn(Claims(c))
		}
	}
	return p
}

var _ jwt.JWT = (*JWS)(nil)
