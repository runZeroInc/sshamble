package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/runZeroInc/excrypto/x/crypto/ssh"
)

type AuthHandler func(*ssh.UnauthClientConn, map[string][]byte, *AuthResult) error

func SSHAuthNone(addr string, options *Options) *AuthResult {
	noneHandler := SSHAuthHandlerSingle(ssh.None())
	res := SSHAuth(addr, options, noneHandler)
	if res.Stage == "session" {
		options.Logger.Warnf("%s %s allows sessions with 'none' authentication", addr, "auth-none")
		res.SessionMethod = "none"
		res.SessionAuth = ssh.None()
	}
	return res
}

func SSHAuthHandlerSingle(authMethod ssh.AuthMethod) AuthHandler {
	return func(uac *ssh.UnauthClientConn, extensions map[string][]byte, res *AuthResult) error {
		ares, methods, err := uac.Authenticate(authMethod, extensions)
		res.Result = ares.String()
		res.Methods = methods
		for k, vb := range extensions {
			res.Extensions[k] = string(vb)
		}
		if err == nil && ares != ssh.AuthResultSuccess {
			err = fmt.Errorf("authentication failed: %d", ares)
		}
		return err
	}
}

func SSHAuth(addr string, options *Options, AuthHandler AuthHandler) *AuthResult {
	authDoneCtx, authDoneCancel := context.WithCancel(context.Background())
	defer authDoneCancel()

	res := NewAuthResult()
	res.Host = options.Host
	res.Port = options.Port
	res.User = options.Username

	// Track elapsed processing time
	stime := time.Now()
	defer func() {
		res.Elapsed = time.Since(stime)
	}()

	// Configure the SSH connection
	conf := &ssh.ClientConfig{
		Config: ssh.Config{
			Ciphers:      KexCiphers,
			MACs:         KexMACs,
			KeyExchanges: KeyExchanges,
		},
		ClientVersion:     "SSH-2.0-" + options.ClientVersion,
		User:              options.Username,
		Timeout:           options.Timeout,
		HostKeyAlgorithms: options.HostKeyAlgs,
	}

	// Connect to the service
	d := net.Dialer{
		Timeout: conf.Timeout,
	}
	tries := uint(1)

RetryConnection:
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		if tries <= options.Retries && retryableError(err) {
			time.Sleep(time.Second)
			tries++
			goto RetryConnection
		}
		options.Logger.Tracef("%s connection failed: %v", addr, err)
		res.Error = err.Error()
		return res
	}

	options.Logger.Tracef("%s connection established", addr)
	defer func() {
		options.Logger.Tracef("%s connection completed", addr)
	}()

	// Force a connection close at exit
	defer conn.Close()

	res.Stage = "connect"
	options.Logger.Tracef("%s connection established %v", addr, conn.RemoteAddr())

	if options.StopStage == res.Stage {
		return res
	}

	// Force a socket close at a fixed timeout to prevent hangs in OpenChannel()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				options.Logger.Errorf("panic: ssh close handler for %s %v", addr, r)
			}
		}()
		CloseAfterTimeout(authDoneCtx, options.Timeout*10, addr, conn)
	}()

	// Prevent stalls during version exchange and kex
	_ = conn.SetDeadline(time.Now().Add(options.Timeout))

	// Capture the banner at any stage
	conf.BannerCallback = func(banner string) error {
		res.Banner = banner
		return nil
	}

	// Complete the version and key exchange
	uac, err := ssh.NewUnauthClientConn(conn, addr, conf)
	if uac != nil {
		res.Version = uac.ServerVersion()
	}

	if err != nil {
		// Look for temporary errors tied to MaxStartups and similar
		if tries <= options.Retries && retryableError(err) {
			options.Logger.Debugf("%s kex failed with temporary error: %v", addr, err)
			time.Sleep(time.Second)
			tries++
			goto RetryConnection
		}

		res.Error = err.Error()
		return res
	}
	res.HostKeys[uac.HostKeyType] = base64.StdEncoding.EncodeToString(uac.HostKey)
	res.KexInit = &uac.ServerKexInit
	res.Stage = "kex"
	options.Logger.Tracef("%s kex completed", addr)

	if options.StopStage == res.Stage {
		return res
	}

	// Extend the deadline again for the ssh-userauth request
	_ = conn.SetDeadline(time.Now().Add(options.Timeout))

	exts := make(map[string][]byte)
	if !options.SkipStage("ssh-userauth") {
		options.Logger.Tracef("%s sending ssh-userauth", addr)

		// Request the ssh-userauth service
		exts, err = uac.RequestUserAuth()
		if err != nil {
			res.Error = err.Error()
			return res
		}
	}
	res.Stage = "ssh-userauth"
	if options.StopStage == res.Stage {
		return res
	}

	// Use a multiple of the timeout for the authentication handler
	_ = conn.SetDeadline(time.Now().Add(options.Timeout * 3))

	if !options.SkipStage("auth") {
		options.Logger.Tracef("%s sending auth", addr)

		// Authenticate using the callback
		err = AuthHandler(uac, exts, res)
		if err != nil {
			res.Error = err.Error()
			if !options.IgnoreAuthError {
				return res
			}
		}
	}
	res.Stage = "auth"
	if options.StopStage == res.Stage {
		return res
	}

	// Use a multiple of the timeout for the authentication handler
	_ = conn.SetDeadline(time.Now().Add(options.Timeout * 3))

	if options.postAuthHandler != nil {
		// The postAuthHandler must complete within the above deadline
		// and is covered by the socket close handler.
		if err = options.postAuthHandler(conn, uac, res); err != nil {
			res.Error = err.Error()
			return res
		}
	}

	// The server accepted our authentication
	sconn, sshChans, sshReqs := uac.Mux(options.ignoreChannelOpenReply)
	defer sconn.Close()

	// Use a multiple of the timeout for the session handler
	_ = conn.SetDeadline(time.Now().Add(options.Timeout * 3))

	// NewSession (and open channel) can stall, setup a cancelable timer that closes the socket
	defer sconn.Close()

	// Create a session client on top of this connection
	sclient := ssh.NewClient(sconn, sshChans, sshReqs)

	// Force a socket close at a fixed timeout to prevent hangs in OpenChannel()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				options.Logger.Errorf("panic: ssh close handler for %s %v", addr, r)
			}
		}()
		CloseAfterTimeout(authDoneCtx, options.Timeout*10, addr, conn, sconn, sclient)
	}()

	options.Logger.Tracef("%s opening session", addr)

	// Open a session
	res.Stage = "open-session"
	ses, err := sclient.NewSession()
	if err != nil {
		options.Logger.Tracef("%s session error %v", addr, err)
		res.Error = err.Error()
		if merr := uac.MuxError(); merr != nil {
			res.Error = fmt.Sprintf("%v (mux: %v)", err, merr)
		}
		return res
	}
	defer ses.Close()
	res.Stage = "session"
	if options.StopStage == res.Stage {
		return res
	}

	// Run a custom session handler and let the caller set any timeouts
	if options.sessionHandler != nil {

		options.Logger.Tracef("%s session handler running", addr)

		// Disable the automatic socket close for custom session handlers
		authDoneCancel()

		// Disable the socket deadline
		_ = conn.SetDeadline(time.Time{})

		// Session handlers need to enforce their own timeouts
		if err := options.sessionHandler(conn, sclient, ses, res); err != nil {
			res.Error = err.Error()
		}
		return res
	}

	// Use a multiple of the timeout for the default shell session handler
	_ = conn.SetDeadline(time.Now().Add((options.Timeout * 3)))

	// Buffer stdout/stderr to mutex-protected byte array
	stdOut := NewSyncByteBuffer(1024 * 16)
	stdErr := NewSyncByteBuffer(1024 * 16)
	ses.Stdout = stdOut
	ses.Stderr = stdErr
	stdIn, err := ses.StdinPipe()
	if err != nil {
		options.Logger.Errorf("%s failed to open stdin pipe: %v", addr, err)
	}

	// Request a pty and don't ask for a reply, this helps with the next call to Shell()
	if err := ses.RequestPtyNoReply("xterm", 20, 80, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		options.Logger.Errorf("%s pty request failed: %v", addr, err)
	}

	// Try to open the standard shell
	err = ses.Shell()
	if err != nil {
		options.Logger.Errorf("%s shell command returned error: %v", addr, err)

		// Fallback to running "sh"
		err = ses.Start("sh")
		if err != nil {
			options.Logger.Errorf("%s exec command returned error: %v", addr, err)
		}
	}

	// Wait a second if we successfully started a shell
	if err == nil {
		time.Sleep(time.Second)
	}

	// Prod the session for more output if stdin is enabled
	if stdIn != nil {
		// Send input likely to trigger useful replies:
		_, err := stdIn.Write([]byte(options.SessionPoke))
		if err != nil {
			options.Logger.Errorf("%s stdin write returned error: %v", addr, err)
		}

		// Give the session a second to produce any output
		time.Sleep(time.Second)

		// Peek at the buffered output to determine what other input to send
		peek := stdOut.Peek()
		peek = append(peek, stdErr.Peek()...)

		lcVersion := strings.ToLower(res.Version)

		// Poke telnet-in-ssh specifically by trying to use the shell escape
		if bytes.Contains(peek, []byte("scape character is")) {
			_, err := stdIn.Write([]byte("\x1d!id||uname||sh\r\n"))
			if err != nil {
				options.Logger.Errorf("%s stdin write returned error: %v", addr, err)
			} else {
				time.Sleep(time.Second)
			}
		}

		// Poke various network devices with "show version\r\n" to get better proof data
		if strings.Contains(lcVersion, "cisco") || strings.Contains(lcVersion, "raisecom") {
			_, err := stdIn.Write([]byte("show version\r\n"))
			if err != nil {
				options.Logger.Errorf("%s stdin write returned error: %v", addr, err)
			} else {
				time.Sleep(time.Second)
			}
		}

		stdIn.Close()
	}

	// Close the session
	ses.Close()

	// Wait one second for any slow session output
	time.Sleep(time.Second)

	// Append any remaining data
	data := stdOut.Dump()
	data = append(data, stdErr.Dump()...)

	// Report the result if any data was received
	if len(data) > 0 {
		res.SessionOutput = CleanSessionOutput(data)
	}

	return res
}

func CloseAfterTimeout(ctx context.Context, d time.Duration, addr string, c ...SSHCloser) {
	t := time.NewTimer(d)
	select {
	case <-t.C:
		for _, cl := range c {
			cl.Close()
		}

	case <-ctx.Done():
		// The correct usage should be to check the return of Stop() and drain the channel
		// if false, but this can lead to a stuck goroutine. Go 1.23 is smarter about timer
		// GC and a plain Stop() should be safe.
		/*
			if !t.Stop() {
				<-t.C
			}
		*/
		t.Stop()
	}
}

func ScrapeSession(options *Options, prefix string, res *AuthResult, ses *ssh.Session) error {
	// Buffer stdout/stderr to mutex-protected byte array
	stdOut := NewSyncByteBuffer(1024 * 16)
	stdErr := NewSyncByteBuffer(1024 * 16)
	ses.Stdout = stdOut
	ses.Stderr = stdErr
	stdIn, err := ses.StdinPipe()
	if err != nil {
		options.Logger.Errorf("%s failed to open stdin pipe: %v", prefix, err)
	}

	// Try to open the standard shell
	err = ses.Shell()
	if err != nil {
		options.Logger.Errorf("%s shell command returned error: %v", prefix, err)

		// Fallback to running "sh"
		err = ses.Start("sh")
		if err != nil {
			options.Logger.Errorf("%s exec command returned error: %v", prefix, err)
		}
	}

	// Wait a second if we successfully started a shell
	if err == nil {
		time.Sleep(time.Second)
	}

	if stdIn != nil {
		_, err := stdIn.Write([]byte(options.SessionPoke))
		if err != nil {
			options.Logger.Errorf("%s stdin write returned error: %v", prefix, err)
		}
	}

	// Give the session a second to produce any output
	time.Sleep(time.Second)

	// Peek at the buffered output to determine what other input to send
	peek := stdOut.Peek()
	peek = append(peek, stdErr.Peek()...)

	res.SessionOutput = CleanSessionOutput(peek)
	return err
}

func ScrapeExec(options *Options, prefix string, res *AuthResult, ses *ssh.Session, cmd string) error {
	// Buffer stdout/stderr to mutex-protected byte array
	stdOut := NewSyncByteBuffer(1024 * 16)
	stdErr := NewSyncByteBuffer(1024 * 16)
	ses.Stdout = stdOut
	ses.Stderr = stdErr
	stdIn, err := ses.StdinPipe()
	if err != nil {
		options.Logger.Errorf("%s failed to open stdin pipe: %v", prefix, err)
	}

	// Try to run the specific command
	err = ses.Start(cmd)
	if err != nil {
		options.Logger.Errorf("%s exec command returned error: %v", prefix, err)
	}

	// Give the server a second to process the command
	if err == nil {
		time.Sleep(time.Second)
	}

	if stdIn != nil {
		_, err := stdIn.Write([]byte(options.SessionPoke))
		if err != nil {
			options.Logger.Errorf("%s stdin write returned error: %v", prefix, err)
		}
	}

	// Give the session a second to produce any output
	time.Sleep(time.Second)

	// Peek at the buffered output to determine what other input to send
	peek := stdOut.Peek()
	peek = append(peek, stdErr.Peek()...)

	res.SessionOutput = CleanSessionOutput(peek)
	return err
}

var retryableErrorStrings = []string{
	"connection refused",
	"read tcp",
	"write tcp",
	"invalid version:",
	"MaxStartups",
	"listen",
}

func retryableError(err error) bool {
	estr := err.Error()
	for _, s := range retryableErrorStrings {
		if strings.Contains(estr, s) {
			return true
		}
	}
	return false
}

// SyncByteBuffer is a mutex-protected bytes.Buffer used to avoid
// data races with SSH stdout/stderr output.
type SyncByteBuffer struct {
	m     sync.Mutex
	limit uint64
	buff  bytes.Buffer
}

func NewSyncByteBuffer(limit uint64) *SyncByteBuffer {
	return &SyncByteBuffer{
		limit: limit,
	}
}

func (b *SyncByteBuffer) Write(data []byte) (int, error) {
	b.m.Lock()
	defer b.m.Unlock()
	rem := b.limit - uint64(b.buff.Len())
	if rem <= 0 {
		return len(data), nil
	} else if rem < uint64(len(data)) {
		data = data[0:rem]
	}
	_, _ = b.buff.Write(data)
	return len(data), nil
}

func (b *SyncByteBuffer) Dump() []byte {
	b.m.Lock()
	defer b.m.Unlock()
	res := make([]byte, b.limit)
	n, _ := b.buff.Read(res)
	res = res[0:n]
	return res
}

func (b *SyncByteBuffer) Peek() []byte {
	b.m.Lock()
	defer b.m.Unlock()
	cur := b.buff.Bytes()
	res := make([]byte, len(cur))
	copy(res, cur)
	return res
}

type SSHCloser interface {
	Close() error
}

func CleanSessionOutput(inp []byte) string {
	return strings.TrimSpace(string(SanitizeBytes(inp)))
}

// SanitizeBytes scrubs a given byte array of invalid UTF8 and nulls
func SanitizeBytes(s []byte) []byte {
	// Loop until all invalid bytes are scrubbed
	plen := len(s)
	for {
		// Remove invalid UTF-8 sequences and return a new array
		s = bytes.ToValidUTF8(s, []byte{})
		// Remove null bytes that break PostgreSQL jsonb
		s = bytes.ReplaceAll(s, []byte{0}, []byte{})
		// remove null bytes unicode sequence
		s = bytes.ReplaceAll(s, []byte{92, 117, 48, 48, 48, 48}, []byte{})
		if len(s) == plen {
			break
		}
		plen = len(s)
	}
	return s
}
