package auth

import (
	"slices"
	"testing"

	"github.com/runZeroInc/excrypto/x/crypto/ssh"
)

func TestKeyExchangesIncludeMLKEM(t *testing.T) {
	if len(KeyExchanges) == 0 {
		t.Fatal("KeyExchanges must not be empty")
	}
	if got := KeyExchanges[0]; got != ssh.KeyExchangeMLKEM768X25519 {
		t.Fatalf("first key exchange = %q, want %q", got, ssh.KeyExchangeMLKEM768X25519)
	}
	if !slices.Contains(KeyExchanges, ssh.KeyExchangeMLKEM768X25519) {
		t.Fatalf("KeyExchanges does not include %q", ssh.KeyExchangeMLKEM768X25519)
	}
}

func TestKeyExchangesAreSupported(t *testing.T) {
	supported := map[string]struct{}{
		"curve25519-sha256@libssh.org": {},
	}
	for _, kex := range ssh.SupportedAlgorithms().KeyExchanges {
		supported[kex] = struct{}{}
	}
	for _, kex := range ssh.InsecureAlgorithms().KeyExchanges {
		supported[kex] = struct{}{}
	}

	for _, kex := range KeyExchanges {
		if _, ok := supported[kex]; !ok {
			t.Fatalf("unsupported configured key exchange: %q", kex)
		}
	}
}
