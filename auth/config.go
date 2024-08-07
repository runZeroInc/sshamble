package auth

import (
	"github.com/runZeroInc/sshamble/crypto/ssh"
)

const (
	MaxTargetLine = 1024
	MaxPubKeyLine = 32768
)

var (
	HostKeyAlgorithms = []string{
		ssh.KeyAlgoRSA,
		ssh.KeyAlgoDSA,
		ssh.KeyAlgoECDSA256,
		ssh.KeyAlgoSKECDSA256,
		ssh.KeyAlgoECDSA384,
		ssh.KeyAlgoECDSA521,
		ssh.KeyAlgoED25519,
		ssh.KeyAlgoSKED25519,
		ssh.CertAlgoRSAv01,
		ssh.CertAlgoDSAv01,
		ssh.CertAlgoECDSA256v01,
		ssh.CertAlgoECDSA384v01,
		ssh.CertAlgoECDSA521v01,
		ssh.CertAlgoSKECDSA256v01,
		ssh.CertAlgoED25519v01,
		ssh.CertAlgoSKED25519v01,
		ssh.KeyAlgoRSASHA256,
		ssh.KeyAlgoRSASHA512,
	}

	HostKeyAlgorithmsRSA = []string{
		ssh.KeyAlgoRSA,
		ssh.CertAlgoRSAv01,
		ssh.KeyAlgoRSASHA256,
		ssh.KeyAlgoRSASHA512,
	}

	HostKeyAlgorithmsDSA = []string{
		ssh.KeyAlgoDSA,
		ssh.CertAlgoDSAv01,
	}

	HostKeyAlgorithmsECDSA = []string{
		ssh.KeyAlgoECDSA256,
		ssh.KeyAlgoSKECDSA256,
		ssh.KeyAlgoECDSA384,
		ssh.KeyAlgoECDSA521,
		ssh.CertAlgoECDSA256v01,
		ssh.CertAlgoECDSA384v01,
		ssh.CertAlgoECDSA521v01,
		ssh.CertAlgoSKECDSA256v01,
	}

	HostKeyAlgorithmsED25519 = []string{
		ssh.KeyAlgoED25519,
		ssh.KeyAlgoSKED25519,
		ssh.CertAlgoED25519v01,
		ssh.CertAlgoSKED25519v01,
	}

	HostKeyTypeMap = map[string][]string{
		"rsa":     HostKeyAlgorithmsRSA,
		"dsa":     HostKeyAlgorithmsDSA,
		"ecdsa":   HostKeyAlgorithmsECDSA,
		"ed25519": HostKeyAlgorithmsED25519,
	}

	KeyExchanges = []string{
		"curve25519-sha256",
		"curve25519-sha256@libssh.org",
		"diffie-hellman-group-exchange-sha256",
		"ecdh-sha2-nistp256",
		"ecdh-sha2-nistp384",
		"ecdh-sha2-nistp521",
		"diffie-hellman-group14-sha256",
		"diffie-hellman-group16-sha512",
		"diffie-hellman-group14-sha1",
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group-exchange-sha256",
		"diffie-hellman-group-exchange-sha1",
	}

	KexMACs = []string{
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512-etm@openssh.com",
		"hmac-sha2-256",
		"hmac-sha2-512",
		"hmac-sha1",
		"hmac-sha1-96",
	}

	KexCiphers = []string{
		"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
		"chacha20-poly1305@openssh.com",
		"aes128-ctr", "aes192-ctr", "aes256-ctr",
		"arcfour256", "arcfour128", "arcfour",
		"aes128-cbc",
		"3des-cbc",
	}
)
