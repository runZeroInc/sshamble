package ssh

import "crypto/rsa"

func (r *rsaPublicKey) ToRSAPublicKey() *rsa.PublicKey {
	return &rsa.PublicKey{
		N: r.N,
		E: r.E,
	}
}

type RSAPublicKey interface {
	ToRSAPublicKey() *rsa.PublicKey
}
