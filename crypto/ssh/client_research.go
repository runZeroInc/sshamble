package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

type ExpAuthResult int

const (
	AuthResultFailure ExpAuthResult = iota
	AuthResultPartialSuccess
	AuthResultSuccess
	AuthResultError
)

func (r ExpAuthResult) String() string {
	switch r {
	case AuthResultFailure:
		return "auth-failed"
	case AuthResultPartialSuccess:
		return "auth-partial"
	case AuthResultSuccess:
		return "auth-success"
	case AuthResultError:
		return "auth-error"
	}
	return "unknown-" + strconv.Itoa(int(r))
}

func None() AuthMethod {
	return AuthMethod(new(noneAuth))
}

type ExpKexInitMsg struct {
	Cookie                  [16]byte `sshtype:"20" json:"-"`
	KexAlgos                []string `json:"kexAlgos,omitempty"`
	ServerHostKeyAlgos      []string `json:"hostKeyAlgos,omitempty"`
	CiphersClientServer     []string `json:"cipherC2S,omitempty"`
	CiphersServerClient     []string `json:"cipherS2C,omitempty"`
	MACsClientServer        []string `json:"macC2S,omitempty"`
	MACsServerClient        []string `json:"macS2C,omitempty"`
	CompressionClientServer []string `json:"compC2S,omitempty"`
	CompressionServerClient []string `json:"compS2C,omitempty"`
	LanguagesClientServer   []string `json:"langC2S,omitempty"`
	LanguagesServerClient   []string `json:"langS2C,omitempty"`
	FirstKexFollows         bool     `json:"firstKeyFollows,omitempty"`
	Reserved                uint32   `json:"reserved,omitempty"`
}

type UnauthClientConn struct {
	c             *connection
	Config        *ClientConfig
	ServerKexInit ExpKexInitMsg
	HostKeyType   string
	HostKey       []byte
	Banner        string
}

func NewUnauthClientConn(c net.Conn, addr string, config *ClientConfig) (*UnauthClientConn, error) {
	fullConf := *config
	fullConf.SetDefaults()

	uac := &UnauthClientConn{
		c: &connection{
			sshConn: sshConn{
				conn: c,
				user: fullConf.User,
			},
		},
		Config: &fullConf,
	}

	if fullConf.HostKeyCallback == nil {
		fullConf.HostKeyCallback = func(hostname string, remote net.Addr, key PublicKey) error {
			uac.HostKeyType = key.Type()
			uac.HostKey = key.Marshal()
			return nil
		}
	}

	if fullConf.BannerCallback == nil {
		fullConf.BannerCallback = func(message string) error {
			uac.Banner = message
			return nil
		}
	}

	if err := uac.clientHandshakeUnauth(addr); err != nil {
		c.Close()
		return uac, fmt.Errorf("ssh: handshake failed: %w", err)
	}
	return uac, nil
}

func (uac *UnauthClientConn) clientHandshakeUnauth(dialAddress string) error {
	c := uac.c
	config := uac.Config
	if config.ClientVersion != "" {
		c.clientVersion = []byte(config.ClientVersion)
	} else {
		c.clientVersion = []byte(packageVersion)
	}
	var err error
	c.serverVersion, err = exchangeVersions(c.sshConn.conn, c.clientVersion)
	if err != nil {
		return err
	}

	// Exchange keys and establish a session (trigger HostKey & Banner callbacks as appropriate)
	ct := newTransport(c.sshConn.conn, config.Rand, true /* is client */)
	c.transport = newClientTransport(ct, c.clientVersion, c.serverVersion, config, dialAddress, c.sshConn.RemoteAddr())
	if err := c.transport.waitSession(); err != nil {
		return err
	}

	c.sessionID = c.transport.getSessionID()

	// Store the server's Kex Init message for additional analysis
	if c.transport.otherInitMsg != nil {
		uac.ServerKexInit = ExpKexInitMsg(*c.transport.otherInitMsg)
	}

	return nil
}

func (uac *UnauthClientConn) RequestUserAuth() (map[string][]byte, error) {
	c := uac.c
	extensions := make(map[string][]byte)

	// initiate user auth session
	if err := c.transport.writePacket(Marshal(&serviceRequestMsg{serviceUserAuth})); err != nil {
		return extensions, err
	}
	packet, err := c.transport.readPacket()
	if err != nil {
		return extensions, err
	}
	// The server may choose to send a SSH_MSG_EXT_INFO at this point (if we
	// advertised willingness to receive one, which we always do) or not. See
	// RFC 8308, Section 2.4.
	if len(packet) > 0 && packet[0] == msgExtInfo {
		var extInfo extInfoMsg
		if err := Unmarshal(packet, &extInfo); err != nil {
			return extensions, err
		}
		payload := extInfo.Payload
		for i := uint32(0); i < extInfo.NumExtensions; i++ {
			name, rest, ok := parseString(payload)
			if !ok {
				return extensions, parseError(msgExtInfo)
			}
			value, rest, ok := parseString(rest)
			if !ok {
				return extensions, parseError(msgExtInfo)
			}
			extensions[string(name)] = value
			payload = rest
		}
		packet, err = c.transport.readPacket()
		if err != nil {
			return extensions, err
		}
	}
	var serviceAccept serviceAcceptMsg
	if err := Unmarshal(packet, &serviceAccept); err != nil {
		return extensions, err
	}
	return extensions, nil
}

func (uac *UnauthClientConn) Authenticate(authMethod AuthMethod, extensions map[string][]byte) (ExpAuthResult, []string, error) {
	c := uac.c
	config := uac.Config
	sessionID := c.transport.getSessionID()
	ares, methods, err := authMethod.auth(sessionID, config.User, c.transport, config.Rand, extensions)
	return ExpAuthResult(ares), methods, err
}

func (uac *UnauthClientConn) Mux() (Conn, <-chan NewChannel, <-chan *Request) {
	uac.c.mux = newMux(uac.c.transport)
	uac.c.mux.timeout = uac.Config.Timeout
	return uac.c, uac.c.mux.incomingChannels, uac.c.mux.incomingRequests
}

func (uac *UnauthClientConn) MuxError() error {
	if uac.c == nil {
		return nil
	}
	return uac.c.mux.err
}

func (uac *UnauthClientConn) ServerVersion() string {
	if uac.c == nil {
		return ""
	}
	return string(uac.c.ServerVersion())
}

func (uac *UnauthClientConn) WriteMsgUserAuthSuccess() error {
	c := uac.c
	if err := c.transport.writePacket([]byte{msgUserAuthSuccess}); err != nil {
		return err
	}
	_, err := c.transport.readPacket()
	if err != nil {
		return err
	}
	return nil
}

// Setenv sets an environment variable that will be applied to any
// command executed by Shell or Run.
func (s *Session) SetenvNoReply(name, value string) error {
	msg := setenvRequest{
		Name:  name,
		Value: value,
	}
	_, err := s.ch.SendRequest("env", false, Marshal(&msg))
	return err
}

// RequestPty requests the association of a pty with the session on the remote host.
func (s *Session) RequestPtyNoReply(term string, h, w int, termmodes TerminalModes) error {
	var tm []byte
	for k, v := range termmodes {
		kv := struct {
			Key byte
			Val uint32
		}{k, v}

		tm = append(tm, Marshal(&kv)...)
	}
	tm = append(tm, tty_OP_END)
	req := ptyRequestMsg{
		Term:     term,
		Columns:  uint32(w),
		Rows:     uint32(h),
		Width:    uint32(w * 8),
		Height:   uint32(h * 8),
		Modelist: string(tm),
	}
	_, err := s.ch.SendRequest("pty-req", false, Marshal(&req))
	return err
}

// Shell starts a login shell on the remote host. A Session only
// accepts one call to Run, Start, Shell, Output, or CombinedOutput.
func (s *Session) ShellNoReply() error {
	if s.started {
		return errors.New("ssh: session already started")
	}
	_, err := s.ch.SendRequest("shell", false, nil)
	if err != nil {
		return err
	}
	return s.start()
}

func (s *Session) ChannelRequestNoReply(t string) error {
	_, err := s.ch.SendRequest(t, false, nil)
	return err
}

func (s *Session) Started() bool {
	return s.started
}

func (s *Session) Closed() bool {
	return s.closed
}

// passwordChangeCallback is an AuthMethod that fetches the current and new password
type passwordChangeCallback func() (cpass string, npass string, err error)

func (cb passwordChangeCallback) auth(session []byte, user string, c packetConn, rand io.Reader, _ map[string][]byte) (authResult, []string, error) {
	type passwordAuthMsg struct {
		User        string `sshtype:"50"`
		Service     string
		Method      string
		Reply       bool
		Password    string
		NewPassword string
	}

	cpass, npass, err := cb()
	if err != nil {
		return authFailure, nil, err
	}

	if err := c.writePacket(Marshal(&passwordAuthMsg{
		User:        user,
		Service:     serviceSSH,
		Method:      cb.method(),
		Reply:       true,
		Password:    cpass,
		NewPassword: npass,
	})); err != nil {
		return authFailure, nil, err
	}

	return handleAuthResponse(c)
}

func (cb passwordChangeCallback) method() string {
	return "passwordChange"
}

// PasswordChange returns an AuthMethod using the given current and new password.
func PasswordChange(cpass, npass string) AuthMethod {
	return passwordChangeCallback(func() (string, string, error) { return cpass, npass, nil })
}

// PasswordChangeCallback returns an AuthMethod that uses a callback for
// fetching the current and new password.
func PasswordChangeCallback(prompt func() (cpass string, npass string, err error)) AuthMethod {
	return passwordChangeCallback(prompt)
}

const ServiceSSH = serviceSSH

// "custom" authentication
type customAuth struct {
	User    string
	Service string
	Method  string
	Payload []byte
}

func (n *customAuth) auth(session []byte, user string, c packetConn, rand io.Reader, _ map[string][]byte) (authResult, []string, error) {
	if err := c.writePacket(Marshal(&userAuthRequestMsg{
		User:    n.User,
		Service: n.Service,
		Method:  n.Method,
		Payload: n.Payload,
	})); err != nil {
		return authFailure, nil, err
	}

	return handleAuthResponse(c)
}

func (n *customAuth) method() string {
	return n.Method
}

func CustomAuth(user, service, method string, payload []byte) AuthMethod {
	return &customAuth{
		User:    user,
		Service: service,
		Method:  method,
		Payload: payload,
	}
}

// badSigPublicKeyCallback is an AuthMethod that uses a set of key
// pairs for authentication with an intentionally corrupted signature
type badSigPublicKeyCallback func() ([]Signer, int, []byte, error)

func (cb badSigPublicKeyCallback) method() string {
	return "publickey"
}

func (cb badSigPublicKeyCallback) auth(session []byte, user string, c packetConn, rand io.Reader, extensions map[string][]byte) (authResult, []string, error) {
	// Authentication is performed by sending an enquiry to test if a key is
	// acceptable to the remote. If the key is acceptable, the client will
	// attempt to authenticate with the valid key.  If not the client will repeat
	// the process with the remaining keys.

	signers, corruptIndex, corruptBytes, err := cb()
	if err != nil {
		return authFailure, nil, err
	}
	var methods []string
	var errSigAlgo error

	origSignersLen := len(signers)
	for idx := 0; idx < len(signers); idx++ {
		signer := signers[idx]
		pub := signer.PublicKey()
		as, algo, err := pickSignatureAlgorithm(signer, extensions)
		if err != nil && errSigAlgo == nil {
			// If we cannot negotiate a signature algorithm store the first
			// error so we can return it to provide a more meaningful message if
			// no other signers work.
			errSigAlgo = err
			continue
		}
		ok, err := validateKey(pub, algo, user, c)
		if err != nil {
			return authFailure, nil, err
		}
		// OpenSSH 7.2-7.7 advertises support for rsa-sha2-256 and rsa-sha2-512
		// in the "server-sig-algs" extension but doesn't support these
		// algorithms for certificate authentication, so if the server rejects
		// the key try to use the obtained algorithm as if "server-sig-algs" had
		// not been implemented if supported from the algorithm signer.
		if !ok && idx < origSignersLen && isRSACert(algo) && algo != CertAlgoRSAv01 {
			if contains(as.Algorithms(), KeyAlgoRSA) {
				// We retry using the compat algorithm after all signers have
				// been tried normally.
				signers = append(signers, &multiAlgorithmSigner{
					AlgorithmSigner:     as,
					supportedAlgorithms: []string{KeyAlgoRSA},
				})
			}
		}
		if !ok {
			continue
		}

		pubKey := pub.Marshal()
		data := buildDataSignedForAuth(session, userAuthRequestMsg{
			User:    user,
			Service: serviceSSH,
			Method:  cb.method(),
		}, algo, pubKey)

		if corruptIndex+len(corruptBytes) > len(data) {
			return authFailure, nil, fmt.Errorf("index too big")
		}

		if bytes.HasPrefix(data[corruptIndex:], corruptBytes) {
			return authFailure, nil, fmt.Errorf("no change")
		}

		// fmt.Printf("Corrupting index %d from %.2x to %.2x\n", corruptIndex, data[corruptIndex], corruptByte)

		for i := 0; i < len(corruptBytes); i++ {
			data[corruptIndex+i] = corruptBytes[i]
		}

		sign, err := as.SignWithAlgorithm(rand, data, underlyingAlgo(algo))
		if err != nil {
			return authFailure, nil, err
		}

		// manually wrap the serialized signature in a string
		s := Marshal(sign)
		sig := make([]byte, stringLength(len(s)))
		marshalString(sig, s)
		msg := publickeyAuthMsg{
			User:     user,
			Service:  serviceSSH,
			Method:   cb.method(),
			HasSig:   true,
			Algoname: algo,
			PubKey:   pubKey,
			Sig:      sig,
		}
		p := Marshal(&msg)
		if err := c.writePacket(p); err != nil {
			return authFailure, nil, err
		}
		var success authResult
		success, methods, err = handleAuthResponse(c)
		if err != nil {
			return authFailure, nil, err
		}

		// If authentication succeeds or the list of available methods does not
		// contain the "publickey" method, do not attempt to authenticate with any
		// other keys.  According to RFC 4252 Section 7, the latter can occur when
		// additional authentication methods are required.
		if success == authSuccess || !contains(methods, cb.method()) {
			return success, methods, err
		}
	}

	return authFailure, methods, errSigAlgo
}

// badSigPublicKeys returns an AuthMethod that uses the given key
// pairs.
func BadSigPublicKeys(signers ...Signer) AuthMethod {
	return badSigPublicKeyCallback(func() ([]Signer, int, []byte, error) { return signers, 0, []byte{0}, nil })
}

// BadSigPublicKeysCallback returns an AuthMethod that runs the given
// function to obtain a list of key pairs.
func BadSigPublicKeysCallback(getSigners func() (signers []Signer, idx int, c []byte, err error)) AuthMethod {
	return badSigPublicKeyCallback(getSigners)
}
