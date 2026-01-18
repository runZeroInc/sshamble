package badkeys

import (
	stddsa "crypto/dsa"
	stdecdh "crypto/ecdh"
	stdecdsa "crypto/ecdsa"
	stded25519 "crypto/ed25519"
	stdrsa "crypto/rsa"
	"fmt"

	"github.com/runZeroInc/excrypto/crypto/dsa"
	"github.com/runZeroInc/excrypto/crypto/ecdh"
	"github.com/runZeroInc/excrypto/crypto/ecdsa"
	"github.com/runZeroInc/excrypto/crypto/ed25519"
	"github.com/runZeroInc/excrypto/crypto/rsa"
	"github.com/runZeroInc/excrypto/crypto/sha256"
	"github.com/runZeroInc/excrypto/crypto/x509"
	"github.com/runZeroInc/excrypto/x/crypto/ssh"
	stdssh "golang.org/x/crypto/ssh"
)

// PrefixFromPublicKey implements the badkeys `blocklistmaker` hashing method
func PrefixFromPublicKey(pub any) ([]byte, error) {
	var rawb []byte
	switch pub := pub.(type) {

	case ssh.PublicKey:
		if cpk, ok := pub.(ssh.CryptoPublicKey); ok {
			return PrefixFromPublicKey(cpk.CryptoPublicKey())
		}
		return nil, fmt.Errorf("unsupported excrypto ssh public key: %v", pub.Type())
	case stdssh.PublicKey:
		if cpk, ok := pub.(stdssh.CryptoPublicKey); ok {
			return PrefixFromPublicKey(cpk.CryptoPublicKey())
		}
		return nil, fmt.Errorf("unsupported stdlib ssh public key: %v", pub.Type())

	case *rsa.PublicKey:
		rawb = pub.N.Bytes()
	case *stdrsa.PublicKey:
		rawb = pub.N.Bytes()

	case *ecdsa.PublicKey:
		rawb = pub.X.Bytes()
	case *stdecdsa.PublicKey:
		rawb = pub.X.Bytes()

	case ed25519.PublicKey:
		rawb = pub
	case stded25519.PublicKey:
		rawb = pub

	case x509.X25519PublicKey:
		rawb = pub
	/*
		// Not defined by stdlib
		case stdx509.X25519PublicKey:
		rawb = pub
	*/

	case *ecdh.PublicKey:
		rawb = pub.Bytes() // Verify
	case *stdecdh.PublicKey:
		rawb = pub.Bytes() // Verify

	case *dsa.PublicKey:
		rawb = pub.Y.Bytes()
	case *stddsa.PublicKey:
		rawb = pub.Y.Bytes()

	case nil:
		return nil, fmt.Errorf("unsupported nil key")
	default:
		return nil, fmt.Errorf("unsupported key: %T", pub)
	}
	sha256sum := sha256.Sum256(rawb)
	return sha256sum[0:15], nil
}
