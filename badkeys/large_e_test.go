package badkeys

import (
	"math/big"
	"testing"

	"github.com/runZeroInc/excrypto/crypto/rsa"
	"github.com/runZeroInc/excrypto/crypto/x509"
	"github.com/runZeroInc/excrypto/x/crypto/ssh"
)

// TestLargeRSAExponentChain verifies that an RSA public key with a very large
// public exponent (> 2^31, here ~1397 bits) can round-trip through every layer
// sshamble relies on: x509 PKIX marshal/parse, SSH wire-format marshal/parse,
// and the badkeys fingerprinting helper.
//
// Companion fixture: badkeys/tests/rsa_2048_large_e.yml.
// Upstream: https://github.com/runZeroInc/excrypto/pull/78,
// https://github.com/zmap/zgrab2/pull/714.
func TestLargeRSAExponentChain(t *testing.T) {
	// Real 2048-bit modulus paired with a deliberately oversized public exponent
	// (matches the fixture in badkeys/tests/rsa_2048_large_e.yml).
	const nDec = "18546553133979686295706754998899930900284384519884436022491634865630824361571989091727223217760704713562088617769642972778706810069040146840815408068924221304482467411754327717732219383528142044820647352015027973435620587096945826941424583339838200914868370389431967066469883816302332032037291718905474557496674201134355854318405776150935618480911797504314370087472798726795714549286504512398139371824841363689318200316196228724354062568227493421963401085883965211168501435120756253842277566370639741145538747372187952581380944184780911614372327720305137590972683248723463443042150650954101508292155326597597151852727"
	const eDec = "180551674620205768325404188012693994494974589455798193523634712608811452174151879339798865932167024867098385482983633145471353137270073888488487188773259587111887661299046218807614426891874011840094262739842776840031222130852779463045751206192002039235899666579777076498654001351987196402428277588714906438364535810862902900704632084301624950750661275401550586885487965175176824611882045496694270842154131510904790726769"

	n, ok := new(big.Int).SetString(nDec, 10)
	if !ok {
		t.Fatalf("invalid N literal")
	}
	e, ok := new(big.Int).SetString(eDec, 10)
	if !ok {
		t.Fatalf("invalid E literal")
	}
	if e.BitLen() <= 32 {
		t.Fatalf("test E is not large enough: bitlen=%d", e.BitLen())
	}

	pub := &rsa.PublicKey{N: n, E: e}

	// 1. x509 PKIX round-trip.
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	rpub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("ParsePKIXPublicKey returned %T, want *rsa.PublicKey", parsed)
	}
	if rpub.E.Cmp(e) != 0 || rpub.N.Cmp(n) != 0 {
		t.Fatalf("x509 round-trip mismatch: got N.bits=%d E.bits=%d, want N.bits=%d E.bits=%d",
			rpub.N.BitLen(), rpub.E.BitLen(), n.BitLen(), e.BitLen())
	}

	// 2. SSH wire-format round-trip (parseRSA used to reject E.BitLen() > 24).
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	sshWire := sshPub.Marshal()
	reparsed, err := ssh.ParsePublicKey(sshWire)
	if err != nil {
		t.Fatalf("ssh.ParsePublicKey: %v", err)
	}
	cpk, ok := reparsed.(ssh.CryptoPublicKey)
	if !ok {
		t.Fatalf("ssh.ParsePublicKey result is not CryptoPublicKey: %T", reparsed)
	}
	rsshPub, ok := cpk.CryptoPublicKey().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("ssh re-parse returned %T, want *rsa.PublicKey", cpk.CryptoPublicKey())
	}
	if rsshPub.E.Cmp(e) != 0 || rsshPub.N.Cmp(n) != 0 {
		t.Fatalf("ssh wire round-trip mismatch for large E: got E.bits=%d, want %d", rsshPub.E.BitLen(), e.BitLen())
	}

	// 3. badkeys fingerprint helper consumes the result.
	prefix, err := PrefixFromPublicKey(reparsed)
	if err != nil {
		t.Fatalf("PrefixFromPublicKey: %v", err)
	}
	if len(prefix) != 15 {
		t.Fatalf("unexpected prefix length: %d", len(prefix))
	}
	t.Logf("large-E badkeys prefix: %s (E bitlen=%d)", PrefixToString(prefix), e.BitLen())
}
