package crypto_test

import (
	"bytes"
	"crypto/ecdsa"
	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"io/ioutil"
	"reflect"
	"testing"
)

var ecdsaTestData = []struct {
	name        string
	privateKey string
	publicKey string
	token []byte
	alg         string
	claims      map[string]interface{}
	valid       bool
}{
	{
		"Basic ES256",
		"test/ec256-private.pem",
		"test/ec256-public.pem",
		[]byte("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.UoApcIZYA-JxziseSIOdNmeK8jnbr59jOwy0-8c3XzqC9DLTMUNe4bA6-J0dxKJsfyjEHl6Acu5ndHRD15xgbg"),
		"ES256",
		map[string]interface{}{"foo": "bar"},
		true,
	},
	{
		"Basic ES384",
		"test/ec384-private.pem",
		"test/ec384-public.pem",
		[]byte("eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.xDqjI2iKGHvBb7X63XkYREckFA-HRTvsBk2rF4RE5jRg5hA4GItIFqjigWaaCPfyUTQrx5Vq2MevmViZJwQ7uLEqjXE2_sGkuLQjms8E0VCVvOnedKnzaChpgqZEx6qa"),
		"ES384",
		map[string]interface{}{"foo": "bar"},
		true,
	},
	{
		"Basic ES512",
		"test/ec512-private.pem",
		"test/ec512-public.pem",
		[]byte("eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.AXsshZfG4rvln8KmY-4bBix9bwZM45BAmhvgydohuxAPZm4HpPcejtoTRobfmxr0Y3bP1fxPa2A3BSXFikSgOIjbAa3xrjFR0aJfuTYmg6Mxyw68hyDybsZTelb3E7b8Emt64Hh4U3bBx7Ka6XwG_7gRQgkzbdr0RgXqqHseDn_Un9pm"),
		"ES512",
		map[string]interface{}{"foo": "bar"},
		true,
	},
	{
		"basic ES256 invalid: foo => bar",
		"test/ec256-private.pem",
		"test/ec256-public.pem",
		[]byte("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.MEQCIHoSJnmGlPaVQDqacx_2XlXEhhqtWceVopjomc2PJLtdAiAUTeGPoNYxZw0z8mgOnnIcjoxRuNDVZvybRZF3wR1l8W"),
		"ES256",
		map[string]interface{}{"foo": "bar"},
		false,
	},
}

func TestECDSAVerify(t *testing.T) {
	for _, data := range ecdsaTestData {
		ecdsaPublicKey := loadEcdsaPublicKey(t, data.publicKey)
		parts := bytes.Split(data.token, []byte("."))
		var sig crypto.Signature
		err := sig.UnmarshalJSON(parts[2])
		if err != nil {
			t.Fatal(err)
		}
		method := jws.GetSigningMethod(data.alg)
		err = method.Verify(bytes.Join(parts[0:2], []byte(".")), sig, ecdsaPublicKey)
		if data.valid && err != nil {
			t.Errorf("[%v] Error while verifying key: %v", data.name, err)
		}
		if !data.valid && err == nil {
			t.Errorf("[%v] Invalid key passed validation", data.name)
		}
	}
}

func TestECDSASign(t *testing.T) {
	for _, data := range ecdsaTestData {
		ecdsaPrivateKey := loadEcdsaPrivateKey(t, data.privateKey)
		ecdsaPublicKey := loadEcdsaPublicKey(t, data.publicKey)

		if data.valid {
			parts := bytes.Split(data.token, []byte("."))
			method := jws.GetSigningMethod(data.alg)
			payload := bytes.Join(parts[0:2], []byte("."))
			sig, err := method.Sign(payload, ecdsaPrivateKey)
			if err != nil {
				t.Errorf("[%v] Error signing token: %v", data.name, err)
			}
			base64Sig, err := sig.Base64()
			if err != nil {
				t.Fatal(err)
			}
			// Should be different...
			if reflect.DeepEqual(base64Sig, parts[2]) {
				t.Errorf("[%v] Identical signatures\nbefore:\n%v\nafter:\n%v", data.name, string(parts[2]), string(base64Sig))
			}
			// Verify new signature.
			err = method.Verify(payload,sig, ecdsaPublicKey)
			if err != nil {
				t.Errorf("[%v] Error while verifying key: %v", data.name, err)
			}
		}
	}
}

func loadEcdsaPublicKey(t *testing.T, path string) *ecdsa.PublicKey {
	t.Helper()
	key, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var ecdsaKey *ecdsa.PublicKey
	if ecdsaKey, err = crypto.ParseECPublicKeyFromPEM(key); err != nil {
		t.Fatalf("Unable to parse ECDSA public key: %v", err)
	}
	return ecdsaKey
}


func loadEcdsaPrivateKey(t *testing.T, path string) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read keys data: %s", path)
	}

	var ecdsaPrivateKey *ecdsa.PrivateKey
	if ecdsaPrivateKey, err = crypto.ParseECPrivateKeyFromPEM(key); err != nil {
		t.Errorf("Unable to parse ECDSA private key: %v", err)
	}
	return ecdsaPrivateKey
}