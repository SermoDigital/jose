package jws

import (
	"encoding/json"
	"fmt"

	"github.com/SermoDigital/jose"
)

// JWS represents a specific JWS.
type JWS struct {
	payload *payload
	plcache rawBase64
	clean   bool

	sb      []sigHead
	methods []SigningMethod
}

// sigHead represents the 'signatures' member of the JWS' "general"
// serialization form per
// https://tools.ietf.org/html/rfc7515#section-7.2.1
//
// It's embedded inside the "flat" structure in order to properly
// create the "flat" JWS.
type sigHead struct {
	Protected   rawBase64 `json:"protected,omitempty"`
	Unprotected rawBase64 `json:"header,omitempty"`
	Signature   Signature `json:"signature"`

	protected   jose.Protected `json:"-"`
	unprotected jose.Header    `json:"-"`
	clean       bool           `json:"-"`
}

// New creates a new JWS with the provided SigningMethods.
func New(content interface{}, methods ...SigningMethod) *JWS {
	sb := make([]sigHead, len(methods))
	for i := range methods {
		sb[i] = sigHead{
			protected: jose.Protected{
				"alg": methods[i].Alg(),
			},
			unprotected: make(jose.Header),
		}
	}
	return &JWS{
		payload: &payload{v: content},
		sb:      sb,
		methods: methods,
	}
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
// the payload. The reason for this is sometimes the payload
// might implement the json.Marshaler interface, and since
// the JWS' payload member is an interface{}, a simple
// json.Unmarshal call cannot magically identify the original
// type. So, in order to keep the caller from having to do extra
// parsing of the payload, the a json.Unmarshaler can be passed
// which will be called to unmarshal the payload however the caller
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

	var (
		p   payload
		err error
	)

	if len(u) > 0 {
		if k := u[0]; k.UnmarshalJSON(g.Payload) != nil {
			p.v = u
			err = ErrCouldNotUnmarshal
		}
	}

	if err != nil {
		fmt.Println(string(g.Payload))
		if err := json.Unmarshal(g.Payload, &p); err != nil {
			return nil, err
		}
	}

	return &JWS{
		payload: &p,
		sb:      g.Signatures,
	}, err
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

	return &JWS{
		payload: &p,
		sb:      []sigHead{g.sigHead},
	}, nil
}

// ParseCompact parses a JWS serialized into its "compact" form per
// https://tools.ietf.org/html/rfc7515#section-7.1
// into a physical JWS per
// https://tools.ietf.org/html/rfc7515#section-5.2//
// For information on the json.Unmarshaler parameter, see Parse.
func ParseCompact(encoded []byte, u ...json.Unmarshaler) (*JWS, error) {
	return nil, nil
}
