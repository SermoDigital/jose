package jws

import (
	"fmt"

	"github.com/SermoDigital/jose/crypto"
)

// VerifyCallback is a callback function that can be used to access header
// parameters to lookup needed information. For example, looking
// up the "kid" parameter.
// The return slice must be a slice of keys used in the verification
// of the JWS.
type VerifyCallback func(JWS) ([]interface{}, error)

// VerifyCallback validates the current JWS' signature as-is. It
// accepts a callback function that can be used to access header
// parameters to lookup needed information. For example, looking
// up the "kid" parameter.
// The return slice must be a slice of keys used in the verification
// of the JWS.
func (j *jws) VerifyCallback(fn VerifyCallback, methods []crypto.SigningMethod, o *SigningOpts) error {
	keys, err := fn(j)
	if err != nil {
		return err
	}
	return j.VerifyMulti(keys, methods, o)
}

// IsMultiError returns true if the given error is type MultiError.
func IsMultiError(err error) bool {
	_, ok := err.(MultiError)
	return ok
}

// MultiError is a slice of errors.
type MultiError []error

func (m MultiError) sanityCheck() error {
	if m == nil {
		return nil
	}
	return m
}

// Errors implements the error interface.
func (m MultiError) Error() string {
	s, n := "", 0
	for _, e := range m {
		if e != nil {
			if n == 0 {
				s = e.Error()
			}
			n++
		}
	}
	switch n {
	case 0:
		return "(0 errors)"
	case 1:
		return s
	case 2:
		return s + " (and 1 other error)"
	}
	return fmt.Sprintf("%s (and %d other errors)", s, n-1)
}

// Any means any of the JWS signatures need to verify.
// Refer to verifyMulti for more information.
const Any int = 0

// VerifyMulti verifies the current JWS as-is. Since it's meant to be
// called after parsing a stream of bytes into a JWS, it doesn't do any
// internal parsing like the Sign, Flat, Compact, or General methods do.
func (j *jws) VerifyMulti(keys []interface{}, methods []crypto.SigningMethod, o *SigningOpts) error {

	// Catch a simple mistake. Parameter o is irrelevant in this scenario.
	if len(keys) == 1 &&
		len(methods) == 1 &&
		len(j.sb) == 1 {
		return j.Verify(keys[0], methods[0])
	}

	if len(j.sb) != len(methods) {
		return ErrNotEnoughMethods
	}

	if len(keys) < 1 ||
		len(keys) > 1 && len(keys) != len(j.sb) {
		return ErrNotEnoughKeys
	}

	// TODO do this better.
	if len(keys) == 1 {
		k := keys[0]
		keys = make([]interface{}, len(methods))
		for i := range keys {
			keys[i] = k
		}
	}

	var o2 SigningOpts
	if o == nil {
		o = &SigningOpts{}
	}

	var m MultiError
	for i := range j.sb {
		err := j.sb[i].verify(j.plcache, keys[i], methods[i])
		if err != nil {
			m = append(m, err)
		} else {
			o2.Inc()
			if o.Needs(i) {
				o2.Append(i)
			}
		}
	}

	if err := o.Validate(&o2); err != nil {
		return err
	}
	return m.sanityCheck()
}

// SigningOpts is a struct which holds options for validating
// JWS signatures.
// Number represents the cumulative which signatures need to verify
// in order for the JWS to be considered valid.
// Leave 'Number' empty or set it to the constant 'Any' if any number of
// valid signatures (greater than one) should verify the JWS.
//
// Use the indices of the signatures that need to verify in order
// for the JWS to be considered valid if specific signatures need
// to verify in order for the JWS to be considered valid.
//
// Note:
//     The JWS spec requires *at least* one
//     signature to verify in order for the JWS to be considered valid.
type SigningOpts struct {
	// Minimum of signatures which need to verify.
	Number int

	// Indices of specific signatures which need to verify.
	Indices []int
	ptr     int

	_ struct{}
}

// Append appends x to s's Indices member.
func (s *SigningOpts) Append(x int) {
	s.Indices = append(s.Indices, x)
}

// Needs returns true if x resides inside s's Indices member
// for the given index. If true, it increments s's internal
// index. It's used to match two SigningOpts Indices members.
func (s *SigningOpts) Needs(x int) bool {
	if s.ptr < len(s.Indices) &&
		s.Indices[s.ptr] == x {
		s.ptr++
		return true
	}
	return false
}

// Inc increments s's Number member by one.
func (s *SigningOpts) Inc() { s.Number++ }

// Validate returns any errors found while validating the
// provided SigningOpts. The receiver validates the parameter `have`.
// It'll return an error if the passed SigningOpts' Number member is less
// than s's or if the passed SigningOpts' Indices slice isn't equal to s's.
func (s *SigningOpts) Validate(have *SigningOpts) error {
	if have.Number < s.Number ||
		(s.Indices != nil &&
			!eq(s.Indices, have.Indices)) {
		return ErrNotEnoughValidSignatures
	}
	return nil
}

func eq(a, b []int) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil || len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Verify verifies the current JWS as-is. Refer to verifyMulti
// for more information.
func (j *jws) Verify(key interface{}, method crypto.SigningMethod) error {
	if len(j.sb) < 1 {
		return ErrCannotValidate
	}
	return j.sb[0].verify(j.plcache, key, method)
}

func (s *sigHead) verify(pl []byte, key interface{}, method crypto.SigningMethod) error {
	if s.method != method {
		return ErrMismatchedAlgorithms
	}
	return method.Verify(format(s.Protected, pl), s.Signature, key)
}
