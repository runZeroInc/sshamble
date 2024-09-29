package auth

import (
	"errors"
	"io"

	"github.com/runZeroInc/excrypto/x/crypto/ssh"
)

var ErrHalfAuth = errors.New("half-auth")

type HalfSigner struct {
	PubKey   ssh.PublicKey
	SignData []byte
	Accepted bool
}

func HalfSignerFromPubkey(pub ssh.PublicKey) *HalfSigner {
	return &HalfSigner{PubKey: pub}
}

func (s *HalfSigner) PublicKey() ssh.PublicKey {
	return s.PubKey
}

func (s *HalfSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	s.Accepted = true
	s.SignData = make([]byte, len(data))
	copy(s.SignData, data)
	return nil, ErrHalfAuth
}
