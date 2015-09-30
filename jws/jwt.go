package jws

import (
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

// ParseJWT parses a serialized JWT into a physical JWT.
func ParseJWT(encoded []byte) (JWT, error) {
	return ParseCompact(encoded)
}

// IsJWT returns true if the JWS is a JWT.
func (j *JWS) IsJWT() bool { return j.isJWT }

func (j *JWS) validateJWT(key interface{}, m crypto.SigningMethod) error {
	return nil
}

var _ jwt.JWT = (*JWS)(nil)
