package jwt

import "github.com/SermoDigital/jose/crypto"

type JWT interface {
	// Claims returns the set of Claims.
	Claims() Claims

	// Validate returns an error describing any issues found while
	// validating the JWT.
	Validate(key interface{}, method crypto.SigningMethod) error

	// Serialize serializes the JWT into its on-the-wire
	// representation.
	Serialize(key interface{}) ([]byte, error)
}
