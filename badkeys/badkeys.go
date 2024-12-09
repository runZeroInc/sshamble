package badkeys

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/runZeroInc/excrypto/crypto/dsa"
	"github.com/runZeroInc/excrypto/crypto/ecdh"
	"github.com/runZeroInc/excrypto/crypto/ecdsa"
	"github.com/runZeroInc/excrypto/crypto/ed25519"
	"github.com/runZeroInc/excrypto/crypto/rsa"
	"github.com/runZeroInc/excrypto/crypto/sha256"
	"github.com/runZeroInc/excrypto/crypto/x509"
	"github.com/runZeroInc/excrypto/x/crypto/ssh"
)

const BadKeysMetaURL = "https://update.badkeys.info/v0/badkeysdata.json"

// PrefixFromPublicKey implements the badkeys `blocklistmaker` hashing method
func PrefixFromPublicKey(pub any) ([]byte, error) {
	var rawb []byte
	switch pub := pub.(type) {
	case ssh.PublicKey:
		if cpk, ok := pub.(ssh.CryptoPublicKey); ok {
			return PrefixFromPublicKey(cpk.CryptoPublicKey())
		}
		return nil, fmt.Errorf("unsupported ssh public key: %v", pub.Type())
	case *rsa.PublicKey:
		rawb = pub.N.Bytes()
	case *ecdsa.PublicKey:
		rawb = pub.X.Bytes()
	case ed25519.PublicKey:
		rawb = pub
	case x509.X25519PublicKey:
		rawb = pub
	case *ecdh.PublicKey:
		rawb = pub.Bytes() // Verify
	case *dsa.PublicKey:
		rawb = pub.Y.Bytes()
	case nil:
		return nil, fmt.Errorf("unsupported nil key")
	default:
		return nil, fmt.Errorf("unsupported key: %T", pub)
	}
	sha256sum := sha256.Sum256(rawb)
	return sha256sum[0:15], nil
}

// GetExecutablePath returns the full path to the running binary
func GetExecutablePath() string {
	filename, _ := os.Executable()
	filename, _ = filepath.Abs(filename)
	return filename
}

// GetExecutableDir returns the full path to the running binary's directory
func GetExecutableDir() string {
	return filepath.Dir(GetExecutablePath())
}

func ReadBadKeysManifest(r io.Reader) (*Meta, error) {
	meta := &Meta{}
	jdec := json.NewDecoder(r)
	if err := jdec.Decode(meta); err != nil {
		return meta, fmt.Errorf("decode: %v", err)
	}
	return meta, nil
}
