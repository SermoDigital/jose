package jwt

import "errors"

var (
	ErrTokenIsExpired   = errors.New("token is expired")
	ErrTokenNotYetValid = errors.New("token is not yet valid")
)
