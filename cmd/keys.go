package cmd

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"

	"github.com/runZeroInc/sshamble/crypto/ssh"
)

func generateTestKeys(conf *ScanConfig) {
	// Generate RSA keys
	for _, rsaSize := range TestKeyRSASizes {
		privateKeyRSA, err := rsa.GenerateKey(rand.Reader, rsaSize)
		if err != nil {
			conf.Logger.Fatalf("could not create RSA %d key: %v", rsaSize, err)
		}
		privateKeyRSABuf := bytes.Buffer{}
		privateKeyRSAPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKeyRSA)}
		if err := pem.Encode(&privateKeyRSABuf, privateKeyRSAPEM); err != nil {
			conf.Logger.Fatalf("could not encode RSA %d key: %v", rsaSize, err)
		}
		signerRSA, err := ssh.ParsePrivateKey(privateKeyRSABuf.Bytes())
		if err != nil {
			conf.Logger.Fatalf("failed to parse RSA %d private key: %v", rsaSize, err)
		}
		switch rsaSize {
		case 1024:
			conf.TestKeyRSA1024 = signerRSA
		case 2048:
			conf.TestKeyRSA2048 = signerRSA
		case 4096:
			conf.TestKeyRSA4096 = signerRSA
		}
	}

	// Generate a ED25519 key
	_, privateKeyED, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		conf.Logger.Fatalf("could not create ED key: %v", err)
	}
	privateKeyEDBuf := bytes.Buffer{}
	privateKeyEDPEM, err := ssh.MarshalPrivateKey(crypto.PrivateKey(privateKeyED), "")
	if err != nil {
		conf.Logger.Fatalf("could not marshal ED key: %v", err)
	}
	if err := pem.Encode(&privateKeyEDBuf, privateKeyEDPEM); err != nil {
		conf.Logger.Fatalf("could not encode ED key: %v", err)
	}
	signerED, err := ssh.ParsePrivateKey(privateKeyEDBuf.Bytes())
	if err != nil {
		conf.Logger.Fatalf("failed to parse ED private key: %v", err)
	}
	conf.TestKeyED25519 = signerED
}

func processPrivateKeyFile(conf *ScanConfig) (ssh.Signer, error) {
	rawb, err := os.ReadFile(gPrivateKeyFile)
	if err != nil {
		conf.Logger.Fatalf("failed to open private key file '%s': %v", gPrivateKeyFile, err)
	}
	if gPrivateKeyPassphrase == "" {
		return ssh.ParsePrivateKey(rawb)
	}
	return ssh.ParsePrivateKeyWithPassphrase(rawb, []byte(gPrivateKeyPassphrase))
}
