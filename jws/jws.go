package jws

import (
	"bytes"
	"encoding/json"

	"github.com/SermoDigital/jose"
	"github.com/SermoDigital/jose/crypto"
)

// JWS implements a JWS per RFC 7515.
type JWS interface {
	// Payload Returns the payload.
	Payload() interface{}

	// SetPayload sets the payload with the given value.
	SetPayload(interface{})

	// Protected returns the JWS' Protected Header.
	// i represents the index of the Protected Header.
	// Left empty, it defaults to 0.
	Protected(...int) jose.Protected

	// Header returns the JWS' unprotected Header.
	// i represents the index of the Protected Header.
	// Left empty, it defaults to 0.
	Header(...int) jose.Header

	// Verify validates the current JWS' signature as-is. Refer to
	// ValidateMulti for more information.
	Verify(key interface{}, method crypto.SigningMethod) error

	// ValidateMulti validates the current JWS' signature as-is. Since it's
	// meant to be called after parsing a stream of bytes into a JWS, it
	// shouldn't do any internal parsing like the Sign, Flat, Compact, or
	// General methods do.
	VerifyMulti(keys []interface{}, methods []crypto.SigningMethod, o *SigningOpts) error

	// VerifyCallback validates the current JWS' signature as-is. It
	// accepts a callback function that can be used to access header
	// parameters to lookup needed information. For example, looking
	// up the "kid" parameter.
	// The return slice must be a slice of keys used in the verification
	// of the JWS.
	VerifyCallback(fn VerifyCallback, methods []crypto.SigningMethod, o *SigningOpts) error

	// General serializes the JWS into its "general" form per
	// https://tools.ietf.org/html/rfc7515#section-7.2.1
	General(keys ...interface{}) ([]byte, error)

	// Flat serializes the JWS to its "flattened" form per
	// https://tools.ietf.org/html/rfc7515#section-7.2.2
	Flat(key interface{}) ([]byte, error)

	// Compact serializes the JWS into its "compact" form per
	// https://tools.ietf.org/html/rfc7515#section-7.1
	Compact(key interface{}) ([]byte, error)

	// IsJWT returns true if the JWS is a JWT.
	IsJWT() bool
}

// jws represents a specific jws.
type jws struct {
	payload *payload
	plcache rawBase64
	clean   bool

	sb []sigHead

	isJWT bool
}

// Payload returns the jws' payload.
func (j *jws) Payload() interface{} { return j.payload.v }

// SetPayload sets the jws' raw, unexported payload.
func (j *jws) SetPayload(val interface{}) { j.payload.v = val }

// Protected returns the JWS' Protected Header.
// i represents the index of the Protected Header.
// Left empty, it defaults to 0.
func (j *jws) Protected(i ...int) jose.Protected {
	if len(i) == 0 {
		return j.sb[0].protected
	}
	return j.sb[i[0]].protected
}

// Header returns the JWS' unprotected Header.
// i represents the index of the Protected Header.
// Left empty, it defaults to 0.
func (j *jws) Header(i ...int) jose.Header {
	if len(i) == 0 {
		return j.sb[0].unprotected
	}
	return j.sb[i[0]].unprotected
}

// sigHead represents the 'signatures' member of the jws' "general"
// serialization form per
// https://tools.ietf.org/html/rfc7515#section-7.2.1
//
// It's embedded inside the "flat" structure in order to properly
// create the "flat" jws.
type sigHead struct {
	Protected   rawBase64        `json:"protected,omitempty"`
	Unprotected rawBase64        `json:"header,omitempty"`
	Signature   crypto.Signature `json:"signature"`

	protected   jose.Protected
	unprotected jose.Header
	clean       bool

	method crypto.SigningMethod
}

func (s *sigHead) unmarshal() error {
	if err := s.protected.UnmarshalJSON(s.Protected); err != nil {
		return err
	}
	if err := s.unprotected.UnmarshalJSON(s.Unprotected); err != nil {
		return err
	}
	return nil
}

// New creates a JWS with the provided crypto.SigningMethods.
func New(content interface{}, methods ...crypto.SigningMethod) JWS {
	sb := make([]sigHead, len(methods))
	for i := range methods {
		sb[i] = sigHead{
			protected: jose.Protected{
				"alg": methods[i].Alg(),
			},
			unprotected: jose.Header{},
			method:      methods[i],
		}
	}
	return &jws{
		payload: &payload{v: content},
		sb:      sb,
	}
}

func (s *sigHead) assignMethod(p jose.Protected) error {
	alg, ok := p.Get("alg").(string)
	if !ok {
		return ErrNoAlgorithm
	}

	sm := GetSigningMethod(alg)
	if sm == nil {
		return ErrNoAlgorithm
	}

	s.method = sm
	return nil
}

type generic struct {
	Payload rawBase64 `json:"payload"`
	sigHead
	Signatures []sigHead `json:"signatures,omitempty"`
}

// Parse parses any of the three serialized jws forms into a physical
// jws per https://tools.ietf.org/html/rfc7515#section-5.2
//
// It accepts a json.Unmarshaler in order to properly parse
// the payload. In order to keep the caller from having to do extra
// parsing of the payload, a json.Unmarshaler can be passed
// which will be then to unmarshal the payload however the caller
// wishes. Do note that if json.Unmarshal returns an error the
// original payload will be used as if no json.Unmarshaler was
// passed.
//
// Internally, Parse applies some heuristics and then calls either
// ParseGeneral, ParseFlat, or ParseCompact.
// It should only be called if, for whatever reason, you do not
// know which form the serialized JWT is in.
func Parse(encoded []byte, u ...json.Unmarshaler) (JWS, error) {
	// Try and unmarshal into a generic struct that'll
	// hopefully hold either of the two JSON serialization
	// formats.s
	var g generic

	// Not valid JSON. Let's try compact.
	if err := json.Unmarshal(encoded, &g); err != nil {
		return ParseCompact(encoded, u...)
	}

	if g.Signatures == nil {
		return g.parseFlat(u...)
	}
	return g.parseGeneral(u...)
}

// ParseGeneral parses a jws serialized into its "general" form per
// https://tools.ietf.org/html/rfc7515#section-7.2.1
// into a physical jws per
// https://tools.ietf.org/html/rfc7515#section-5.2
//
// For information on the json.Unmarshaler parameter, see Parse.
func ParseGeneral(encoded []byte, u ...json.Unmarshaler) (JWS, error) {
	var g generic
	if err := json.Unmarshal(encoded, &g); err != nil {
		return nil, err
	}
	return g.parseGeneral(u...)
}

func (g *generic) parseGeneral(u ...json.Unmarshaler) (JWS, error) {

	var p payload
	if len(u) > 0 {
		p.u = u[0]
	}

	if err := p.UnmarshalJSON(g.Payload); err != nil {
		return nil, err
	}

	for i := range g.Signatures {
		if err := g.Signatures[i].unmarshal(); err != nil {
			return nil, err
		}
		if err := checkHeaders(jose.Header(g.Signatures[i].protected), g.Signatures[i].unprotected); err != nil {
			return nil, err
		}

		if err := g.Signatures[i].assignMethod(g.Signatures[i].protected); err != nil {
			return nil, err
		}

		g.clean = true
	}

	return &jws{
		payload: &p,
		plcache: g.Payload,
		clean:   true,
		sb:      g.Signatures,
	}, nil
}

// ParseFlat parses a jws serialized into its "flat" form per
// https://tools.ietf.org/html/rfc7515#section-7.2.2
// into a physical jws per
// https://tools.ietf.org/html/rfc7515#section-5.2
//
// For information on the json.Unmarshaler parameter, see Parse.
func ParseFlat(encoded []byte, u ...json.Unmarshaler) (JWS, error) {
	var g generic
	if err := json.Unmarshal(encoded, &g); err != nil {
		return nil, err
	}
	return g.parseFlat(u...)
}

func (g *generic) parseFlat(u ...json.Unmarshaler) (JWS, error) {

	var p payload
	if len(u) > 0 {
		p.u = u[0]
	}

	if err := p.UnmarshalJSON(g.Payload); err != nil {
		return nil, err
	}

	if err := g.sigHead.unmarshal(); err != nil {
		return nil, err
	}
	g.sigHead.clean = true

	if err := checkHeaders(jose.Header(g.sigHead.protected), g.sigHead.unprotected); err != nil {
		return nil, err
	}

	if err := g.sigHead.assignMethod(g.sigHead.protected); err != nil {
		return nil, err
	}

	return &jws{
		payload: &p,
		plcache: g.Payload,
		clean:   true,
		sb:      []sigHead{g.sigHead},
	}, nil
}

// ParseCompact parses a jws serialized into its "compact" form per
// https://tools.ietf.org/html/rfc7515#section-7.1
// into a physical jws per
// https://tools.ietf.org/html/rfc7515#section-5.2
//
// For information on the json.Unmarshaler parameter, see Parse.
func ParseCompact(encoded []byte, u ...json.Unmarshaler) (JWS, error) {
	return parseCompact(encoded, false)
}

func parseCompact(encoded []byte, jwt bool) (*jws, error) {

	// This section loosely follows
	// https://tools.ietf.org/html/rfc7519#section-7.2
	// because it's used to parse _both_ jws and JWTs.

	parts := bytes.Split(encoded, []byte{'.'})
	if len(parts) != 3 {
		return nil, ErrNotCompact
	}

	var p jose.Protected
	if err := p.UnmarshalJSON(parts[0]); err != nil {
		return nil, err
	}

	s := sigHead{
		protected: p,
		clean:     true,
	}

	if err := s.assignMethod(p); err != nil {
		return nil, err
	}

	j := jws{
		payload: &payload{},
		sb:      []sigHead{s},
		isJWT:   jwt,
	}

	if err := j.payload.UnmarshalJSON(parts[1]); err != nil {
		return nil, err
	}

	j.clean = true

	if err := j.sb[0].Signature.UnmarshalJSON(parts[2]); err != nil {
		return nil, err
	}

	// https://tools.ietf.org/html/rfc7519#section-7.2.8
	cty, ok := p.Get("cty").(string)
	if ok && cty == "JWT" {
		return &j, ErrHoldsJWE
	}
	return &j, nil
}

// IgnoreDupes should be set to true if the internal duplicate header key check
// should ignore duplicate Header keys instead of reporting an error when
// duplicate Header keys are found.
//
// Note:
//     Duplicate Header keys are defined in
//     https://tools.ietf.org/html/rfc7515#section-5.2
//     meaning keys that both the protected and unprotected
//     Headers possess.
var IgnoreDupes bool

// checkHeaders returns an error per the constraints described in
// IgnoreDupes' comment.
func checkHeaders(a, b jose.Header) error {
	if len(a)+len(b) == 0 {
		return ErrTwoEmptyHeaders
	}
	for key := range a {
		if b.Has(key) && !IgnoreDupes {
			return ErrDuplicateHeaderParameter
		}
	}
	return nil
}
