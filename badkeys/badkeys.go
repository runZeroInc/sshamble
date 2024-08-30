package badkeys

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/runZeroInc/sshamble/crypto/ssh"
)

const BadKeysMetaURL = "https://update.badkeys.info/v0/badkeysdata.json"

func PrefixFromPublicKey(pub ssh.PublicKey) ([]byte, error) {
	var res []byte
	switch pub.Type() {
	case ssh.KeyAlgoRSA:
		pk, ok := pub.(ssh.RSAPublicKey)
		if !ok {
			return nil, fmt.Errorf("%s doesn't implement RSAPublicKey", pub.Type())
		}
		res = pk.ToRSAPublicKey().N.Bytes()
	default:
		res = pub.Marshal()
	}
	hash := sha256.Sum256(res)
	return hash[0:15], nil
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
