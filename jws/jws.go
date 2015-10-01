package jws

import (
	"bytes"
	"encoding/json"
	"sort"

	"github.com/SermoDigital/jose"
	"github.com/SermoDigital/jose/crypto"
)

// JWS represents a specific JWS.
type JWS struct {
	payload *payload
	plcache rawBase64
	clean   bool

	sb []sigHead

	isJWT bool
}

// Payload returns the JWS' payload.
func (j *JWS) Payload() interface{} { return j.payload.v }

// SetPayload sets the JWS' raw, unexported payload.
func (j *JWS) SetPayload(val interface{}) { j.payload.v = val }

// sigHead represents the 'signatures' member of the JWS' "general"
// serialization form per
// https://tools.ietf.org/html/rfc7515#section-7.2.1
//
// It's embedded inside the "flat" structure in order to properly
// create the "flat" JWS.
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

// New creates a new JWS with the provided crypto.SigningMethods.
func New(content interface{}, methods ...crypto.SigningMethod) *JWS {
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
	return &JWS{
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

// Parse parses any of the three serialized JWS forms into a physical
// JWS per https://tools.ietf.org/html/rfc7515#section-5.2
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
func Parse(encoded []byte, u ...json.Unmarshaler) (*JWS, error) {
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

// ParseGeneral parses a JWS serialized into its "general" form per
// https://tools.ietf.org/html/rfc7515#section-7.2.1
// into a physical JWS per
// https://tools.ietf.org/html/rfc7515#section-5.2
//
// For information on the json.Unmarshaler parameter, see Parse.
func ParseGeneral(encoded []byte, u ...json.Unmarshaler) (*JWS, error) {
	var g generic
	if err := json.Unmarshal(encoded, &g); err != nil {
		return nil, err
	}
	return g.parseGeneral(u...)
}

func (g *generic) parseGeneral(u ...json.Unmarshaler) (*JWS, error) {

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

	return &JWS{
		payload: &p,
		plcache: g.Payload,
		clean:   true,
		sb:      g.Signatures,
	}, nil
}

// ParseFlat parses a JWS serialized into its "flat" form per
// https://tools.ietf.org/html/rfc7515#section-7.2.2
// into a physical JWS per
// https://tools.ietf.org/html/rfc7515#section-5.2
//
// For information on the json.Unmarshaler parameter, see Parse.
func ParseFlat(encoded []byte, u ...json.Unmarshaler) (*JWS, error) {
	var g generic
	if err := json.Unmarshal(encoded, &g); err != nil {
		return nil, err
	}
	return g.parseFlat(u...)
}

func (g *generic) parseFlat(u ...json.Unmarshaler) (*JWS, error) {

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

	return &JWS{
		payload: &p,
		plcache: g.Payload,
		clean:   true,
		sb:      []sigHead{g.sigHead},
	}, nil
}

// ParseCompact parses a JWS serialized into its "compact" form per
// https://tools.ietf.org/html/rfc7515#section-7.1
// into a physical JWS per
// https://tools.ietf.org/html/rfc7515#section-5.2
//
// For information on the json.Unmarshaler parameter, see Parse.
func ParseCompact(encoded []byte, u ...json.Unmarshaler) (*JWS, error) {

	// This section loosely follows
	// https://tools.ietf.org/html/rfc7519#section-7.2
	// because it's used to parse _both_ JWS and JWTs.

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

	j := JWS{
		payload: &payload{},
		sb:      []sigHead{s},
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
// Note: Duplicate Header keys are defined in
// https://tools.ietf.org/html/rfc7515#section-5.2
// meaning keys that both the protected and unprotected
// Headers possess.
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

// Any means any of the JWS signatures need to validate.
// Refer to ValidateMulti for more information.
const Any int = -1

// ValidateMulti validates the current JWS as-is. Since it's meant to be
// called after parsing a stream of bytes into a JWS, it doesn't do any
// internal parsing like the Sign, Flat, Compact, or General methods do.
// idx represents which signatures need to validate
// in order for the JWS to be considered valid.
// Use the constant `Any` (-1) if *any* should validate the JWS. Otherwise,
// use the indexes of the signatures that need to validate in order
// for the JWS to be considered valid.
//
// Notes:
//     1.) If idx is omitted it defaults to requiring *all*
//         signatures validate
//     2.) The JWS spec requires *at least* one
//         signature to validate in order for the JWS to be considered valid.
func (j *JWS) ValidateMulti(keys []interface{}, methods []crypto.SigningMethod, idx ...int) error {

	if len(j.sb) != len(methods) {
		return ErrNotEnoughMethods
	}

	if len(keys) < 1 ||
		len(keys) > 1 && len(keys) != len(j.sb) {
		return ErrNotEnoughKeys
	}

	if len(keys) == 1 {
		k := keys[0]
		keys = make([]interface{}, len(methods))
		for i := range keys {
			keys[i] = k
		}
	}

	any := len(idx) == 1 && idx[0] == Any
	if !any {
		sort.Ints(idx)
	}

	rp := 0
	for i := range j.sb {
		if j.sb[i].validate(j.plcache, keys[i], methods[i]) == nil &&
			any || (rp < len(idx) && idx[rp] == i) {
			rp++
		}
	}

	if rp < len(idx) {
		return ErrDidNotValidate
	}
	return nil
}

// Validate validates the current JWS as-is. Refer to ValidateMulti
// for more information.
func (j *JWS) Validate(key interface{}, method crypto.SigningMethod) error {
	if len(j.sb) < 1 {
		return ErrCannotValidate
	}
	return j.sb[0].validate(j.plcache, key, method)
}

func (s *sigHead) validate(pl []byte, key interface{}, method crypto.SigningMethod) error {
	if s.method != method {
		return ErrMismatchedAlgorithms
	}
	return method.Verify(format(s.Protected, pl), s.Signature, key)
}

// SetProtected sets the protected Header with the given value.
// If i is provided, it'll assume the JWS is in the "general" format,
// and set the Header at index i (inside the signatures member) with
// the given value.
func (j *JWS) SetProtected(key string, val interface{}, i ...int) {
	k := 0
	if len(i) > 0 && len(i) < len(j.sb) && i[0] > -1 {
		k = i[0]
	}
	j.sb[k].protected.Set(key, val)
}

// RemoveProtected removes the value inside the protected Header that
// corresponds with the given key.
// For information on parameter i, see SetProtected.
func (j *JWS) RemoveProtected(key string, i ...int) {
	k := 0
	if len(i) > 0 && len(i) < len(j.sb) && i[0] > -1 {
		k = i[0]
	}
	j.sb[k].protected.Del(key)
}

// GetProtected retrieves the value inside the protected Header that
// corresponds with the given key.
// For information on parameter i, see SetProtected.
func (j *JWS) GetProtected(key string, i ...int) interface{} {
	k := 0
	if len(i) > 0 && len(i) < len(j.sb) && i[0] > -1 {
		k = i[0]
	}
	return j.sb[k].protected.Get(key)
}

// SetUnprotected sets the protected Header with the given value.
// If i is provided, it'll assume the JWS is in the "general" format,
// and set the Header at index i (inside the signatures member) with
// the given value.
func (j *JWS) SetUnprotected(key string, val interface{}, i ...int) {
	k := 0
	if len(i) > 0 && len(i) < len(j.sb) && i[0] > -1 {
		k = i[0]
	}
	j.sb[k].unprotected.Set(key, val)
}

// RemoveUnprotected removes the value inside the unprotected Header that
// corresponds with the given key.
// For information on parameter i, see SetUnprotected.
func (j *JWS) RemoveUnprotected(key string, i ...int) {
	k := 0
	if len(i) > 0 && len(i) < len(j.sb) && i[0] > -1 {
		k = i[0]
	}
	j.sb[k].unprotected.Del(key)
}

// GetUnprotected retrieves the value inside the protected Header that
// corresponds with the given key.
// For information on parameter i, see SetUnprotected.
func (j *JWS) GetUnprotected(key string, i ...int) interface{} {
	k := 0
	if len(i) > 0 && len(i) < len(j.sb) && i[0] > -1 {
		k = i[0]
	}
	return j.sb[k].unprotected.Get(key)
}
