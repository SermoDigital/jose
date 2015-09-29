package jws

import "errors"

var (
	// ErrInvalidKey means the key argument passed to SigningMethod.Verify
	// was not the correct type.
	ErrInvalidKey = errors.New("key is invalid")

	// ErrNotEnoughMethods is returned if New was called _or_ the Flat/Compact
	// methods were called with 0 SigningMethods.
	ErrNotEnoughMethods = errors.New("not enough methods provided")

	// ErrCouldNotUnmarshal is returned when Parse's json.Unmarshaler
	// parameter returns an error.
	ErrCouldNotUnmarshal = errors.New("custom unmarshal failed")
)
