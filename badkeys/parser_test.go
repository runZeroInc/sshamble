package badkeys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/pem"
	"testing"

	"github.com/runZeroInc/excrypto/crypto/rsa"
	"github.com/runZeroInc/excrypto/crypto/x509"
	cases "github.com/runZeroInc/sshamble/badkeys/tests"
	"go.yaml.in/yaml/v3"
)

func getTests() []testCase {
	files, err := cases.TestData.ReadDir(".")
	if err != nil {
		panic("readdir: " + err.Error())
	}
	var testCases []testCase
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		data, err := cases.TestData.ReadFile(f.Name())
		if err != nil {
			panic(err)
		}
		tc, err := parseTestCase(f.Name(), data)
		if err != nil {
			panic(err)
		}
		testCases = append(testCases, tc)
	}
	return testCases
}

func parseTestCase(name string, data []byte) (testCase, error) {
	tc := testCase{}
	err := yaml.Unmarshal(data, &tc)
	tc.File = name
	return tc, err
}

type testCase struct {
	File    string `yaml:"-"`
	Name    string `yaml:"name"`
	KeyType string `yaml:"keyType"`
	Comment string `yaml:"comment"`
	Key     string `yaml:"key"`
}

func TestSuite(t *testing.T) {
	testCases := getTests()
	for _, tc := range testCases {
		t.Run(tc.File, func(t *testing.T) {
			runTestCase(t, tc)
		})
	}
}

func runTestCase(t *testing.T, tc testCase) {
	t.Logf("running test case: %s (%s)", tc.Name, tc.File)
	b, _ := pem.Decode([]byte(tc.Key))
	if b == nil {
		t.Fatalf("failed to decode pem: no block in %s", tc.Key)
	}

	var ktype string
	decodeErrs := []string{}
	var privateKey, publicKey any
	var priOK, pubOK bool

	privateKey, err := x509.ParsePKCS1PrivateKey(b.Bytes)
	if err != nil {
		decodeErrs = append(decodeErrs, "priv-pkcs1: "+err.Error())
		privateKey, err = x509.ParsePKCS8PrivateKey(b.Bytes)
		if err != nil {
			decodeErrs = append(decodeErrs, "priv-pkcs8: "+err.Error())
		} else {
			priOK = true
		}
	} else {
		priOK = true
	}
	switch pk := privateKey.(type) {
	case *rsa.PrivateKey:
		ktype = "rsa"
		publicKey = &pk.PublicKey
		privateKey = pk
		pubOK = true
	case *ecdsa.PrivateKey:
		ktype = "ecdsa"
		publicKey = &pk.PublicKey
		privateKey = pk
		pubOK = true
	case *ed25519.PrivateKey:
		ktype = "ed25519"
		publicKey = pk.Public()
		privateKey = pk
		pubOK = true
	}

	if !pubOK {
		publicKey, err = x509.ParsePKIXPublicKey(b.Bytes)
		if err != nil {
			decodeErrs = append(decodeErrs, "pub-pkix: "+err.Error())
			publicKey, err = x509.ParsePKCS1PublicKey(b.Bytes)
			if err != nil {
				decodeErrs = append(decodeErrs, "pub-pkcs1: "+err.Error())
			}
		} else {
			pubOK = true
		}
	} else {
		pubOK = true
	}

	switch pk := publicKey.(type) {
	case *rsa.PublicKey:
		ktype = "rsa"
		publicKey = pk
	case *ecdsa.PublicKey:
		ktype = "ecdsa"
		publicKey = pk
	case *ed25519.PublicKey:
		ktype = "ed25519"
		publicKey = pk
	}

	t.Logf("pub:%v, priv:%v, type:%v, priv:%v, pub:%v", pubOK, priOK, ktype, privateKey, publicKey)

	if !pubOK {
		for _, e := range decodeErrs {
			t.Logf("decode: %s", e)
		}
		t.Fatalf("failed to parse public key, errors: %+v", decodeErrs)
	}

	if ktype != tc.KeyType {
		t.Fatalf("key type mismatch: got %v, want %v", ktype, tc.KeyType)
	}

	k, err := PrefixFromPublicKey(publicKey)
	if err != nil {
		t.Fatalf("failed to parse key: %v", err)
	}
	t.Logf("key prefix: %s", k)
}
