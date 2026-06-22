package auth

import "testing"

func TestSupportsPubKeyType(t *testing.T) {
	const modern = "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256"
	const legacy = "ssh-ed25519,rsa-sha2-256,rsa-sha2-512,ssh-rsa"

	cases := []struct {
		sigAlgs string
		keyType string
		want    bool
	}{
		{modern, "ssh-rsa", true},
		{modern, "ssh-ed25519", true},
		{legacy, "ssh-rsa", true},
		{"ssh-ed25519", "ssh-rsa", false},
		{modern, "ecdsa-sha2-nistp521", false},
	}

	for _, tc := range cases {
		r := &AuthResult{Extensions: map[string]string{"server-sig-algs": tc.sigAlgs}}
		if got := r.SupportsPubKeyType(tc.keyType); got != tc.want {
			t.Errorf("SupportsPubKeyType(%q) with %q = %v, want %v", tc.keyType, tc.sigAlgs, got, tc.want)
		}
	}
}
