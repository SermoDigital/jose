package jwt

import "errors"

var (
	// ErrTokenIsExpired is return when time.Now().Unix() is after
	// the token's "exp" claim.
	ErrTokenIsExpired = errors.New("token is expired")

	// ErrTokenNotYetValid is return when time.Now().Unix() is before
	// the token's "nbf" claim.
	ErrTokenNotYetValid = errors.New("token is not yet valid")
)
