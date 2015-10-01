package jwt

import "github.com/SermoDigital/jose/crypto"

// Opts represents some of the validation options.
type Opts struct {
	EXP int64        // EXPLeeway
	NBF int64        // NBFLeeway
	Fn  ValidateFunc // See ValidateFunc for more information.
	_   struct{}
}

// JWT represents a JWT as per RFC 7519.
// It's described as an interface instead of a physical structure
// because both JWS and JWEs can be JWTs. So, in order to use either,
// import one of those two packages and use their "NewJWT" (and other)
// functions.
type JWT interface {
	// Claims returns the set of Claims.
	Claims() Claims

	// Verify returns an error describing any issues found while
	// validating the JWT. For info on the fn parameter, see the
	// comment on ValidateFunc.
	Verify(key interface{}, method crypto.SigningMethod, o ...Opts) error

	// Serialize serializes the JWT into its on-the-wire
	// representation.
	Serialize(key interface{}) ([]byte, error)
}

// ValidateFunc is a function that provides access to the JWT
// and allows for custom validation. Keep in mind that the Verify
// methods in the JWS/JWE sibling packages call ValidateFunc *after*
// validating the JWS/JWE, but *before* any validation per the JWT
// RFC. Therefore, the ValidateFunc can be used to short-circuit
// verification, but cannot be used to circumvent the RFC.
// Custom JWT implementations are free to abuse this, but it is
// not recommended.
type ValidateFunc func(Claims) error
