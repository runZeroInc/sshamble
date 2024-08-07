package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/runZeroInc/sshamble/crypto/ssh"
)

type HalfSignerBogus struct {
	PubKey   ssh.PublicKey
	Accepted bool
	Format   string
	Blob     []byte
	PriKey   *rsa.PrivateKey
}

func HalfSignerBogusFromPubkey(pub ssh.PublicKey) *HalfSignerBogus {
	// Create a private key with the same type to handle the signature blobs
	pri, _ := rsa.GenerateKey(rand.Reader, 4096)
	return &HalfSignerBogus{PubKey: pub, PriKey: pri}
}

func (s *HalfSignerBogus) PublicKey() ssh.PublicKey {
	return s.PubKey
}

func (s *HalfSignerBogus) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	if s.PriKey == nil {
		return nil, fmt.Errorf("no private key")
	}
	s.Accepted = true
	blob, err := s.PriKey.Sign(rand, data, crypto.SHA512)
	_ = err
	if err != nil {
		return nil, err
	}
	return &ssh.Signature{
		Format: "ssh-rsa",
		Blob:   blob,
	}, nil
}

type noHasher struct{}

func (h *noHasher) HashFunc() crypto.Hash {
	return crypto.Hash(0)
}
