package jose

import "encoding/json"

// Header implements a JOSE Header with the addition of some helper
// methods, similar to net/url.Values.
type Header map[string]interface{}

// Get retrieves the value corresponding with key from the Header.
func (h Header) Get(key string) interface{} {
	if h == nil {
		return nil
	}
	return h[key]
}

// Set sets Claims[key] = val. It'll overwrite without warning.
func (h Header) Set(key string, val interface{}) {
	h[key] = val
}

// Del removes the value that corresponds with key from the Header.
func (h Header) Del(key string) {
	delete(h, key)
}

// Has returns true if a value for the given key exists inside the Header.
func (h Header) Has(key string) bool {
	_, ok := h[key]
	return ok
}

// MarshalJSON implements json.Marshaler for Header.
func (h Header) MarshalJSON() ([]byte, error) {
	if h == nil || len(h) == 0 {
		return nil, nil
	}
	b, err := json.Marshal(map[string]interface{}(h))
	if err != nil {
		return nil, err
	}
	return EncodeEscape(b), nil
}

// Base64 implements the Encoder interface.
func (h Header) Base64() ([]byte, error) {
	return h.MarshalJSON()
}

// UnmarshalJSON implements json.Unmarshaler for Header.
func (h *Header) UnmarshalJSON(b []byte) error {
	if b == nil {
		return nil
	}

	b, err := DecodeEscaped(b)
	if err != nil {
		return err
	}

	// Since json.Unmarshal calls UnmarshalJSON,
	// calling json.Unmarshal on *p would be infinitely recursive
	// A temp variable is needed because &map[string]interface{}(*p) is
	// invalid Go.

	tmp := map[string]interface{}(*h)
	if err = json.Unmarshal(b, &tmp); err != nil {
		return err
	}
	*h = Header(tmp)
	return nil
}

// Protected Headers are base64-encoded after they're marshaled into
// JSON.
type Protected Header

// Get retrieves the value corresponding with key from the Protected Header.
func (p Protected) Get(key string) interface{} {
	if p == nil {
		return nil
	}
	return p[key]
}

// Set sets Protected[key] = val. It'll overwrite without warning.
func (p Protected) Set(key string, val interface{}) {
	p[key] = val
}

// Del removes the value that corresponds with key from the Protected Header.
func (p Protected) Del(key string) {
	delete(p, key)
}

// Has returns true if a value for the given key exists inside the Protected
// Header.
func (p Protected) Has(key string) bool {
	_, ok := p[key]
	return ok
}

// MarshalJSON implements json.Marshaler for Protected.
func (p Protected) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(map[string]interface{}(p))
	if err != nil {
		return nil, err
	}
	return EncodeEscape(b), nil
}

// Base64 implements the Encoder interface.
func (p Protected) Base64() ([]byte, error) {
	b, err := json.Marshal(map[string]interface{}(p))
	if err != nil {
		return nil, err
	}
	return Base64Encode(b), nil
}

// UnmarshalJSON implements json.Unmarshaler for Protected.
func (p *Protected) UnmarshalJSON(b []byte) error {
	var h Header
	h.UnmarshalJSON(b)
	*p = Protected(h)
	return nil
}

var (
	_ json.Marshaler   = (Protected)(nil)
	_ json.Unmarshaler = (*Protected)(nil)
)
