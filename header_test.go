package jose

import (
	"encoding/json"
	"testing"
)

func TestMarshalProtectedHeader(t *testing.T) {
	p := Protected{
		"alg": "HM256",
	}

	b, err := json.Marshal(p)
	if err != nil {
		t.Error(err)
	}

	var p2 Protected

	if json.Unmarshal(b, &p2); err != nil {
		t.Error(err)
	}

	if p2["alg"] != p["alg"] {
		Error(t, p["alg"], p2["alg"])
	}
}
