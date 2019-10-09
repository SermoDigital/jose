package jws

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"
)

func Error(t *testing.T, want, got interface{}) {
	format := "\nWanted: %s\nGot: %s"

	switch want.(type) {
	case []byte, string, nil, rawBase64, easy:
	default:
		format = fmt.Sprintf(format, "%v", "%v")
	}

	t.Errorf(format, want, got)
}

func ErrorTypes(t *testing.T, want, got interface{}) {
	t.Errorf("\nWanted: %T\nGot: %T", want, got)
}

var (
	rsaPriv   *rsa.PrivateKey
	rsaPub    interface{}
)

func init() {
	derBytes, err := ioutil.ReadFile(filepath.Join("test", "sample_key.pub"))
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(derBytes)

	rsaPub, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	der, err := ioutil.ReadFile(filepath.Join("test", "sample_key.priv"))
	if err != nil {
		panic(err)
	}
	block2, _ := pem.Decode(der)

	rsaPriv, err = x509.ParsePKCS1PrivateKey(block2.Bytes)
	if err != nil {
		panic(err)
	}
}
