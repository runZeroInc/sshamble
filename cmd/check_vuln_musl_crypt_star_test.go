package cmd

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"crypto/rand"
	"github.com/runZeroInc/excrypto/crypto/ed25519"
	"github.com/runZeroInc/excrypto/x/crypto/ssh"
	"github.com/runZeroInc/sshamble/auth"
	"github.com/sirupsen/logrus"
)

func TestMuslCryptStarVersion(t *testing.T) {
	cases := []struct {
		version string
		want    [3]int
		ok      bool
	}{
		{version: "SSH-2.0-OpenSSH_9.7", want: [3]int{9, 7, 0}, ok: true},
		{version: "SSH-2.0-OpenSSH_9.7p1", want: [3]int{9, 7, 1}, ok: true},
		{version: "SSH-2.0-OpenSSH_10.6p2", want: [3]int{10, 6, 2}, ok: true},
		{version: "SSH-2.0-OpenSSH_10.6p2-hpn14v15", want: [3]int{10, 6, 2}, ok: true},
		{version: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10", want: [3]int{8, 9, 1}, ok: true},
		{version: "SSH-1.99-OpenSSH_4.3", want: [3]int{4, 3, 0}, ok: true},
		{version: "SSH-2.0-OpenSSH_for_Windows_9.5", ok: false},
		{version: "SSH-2.0-OpenSSH", ok: false},
		{version: "SSH-2.0-dropbear_2022.83", ok: false},
		{version: "SSH-2.0-Go", ok: false},
		{version: "", ok: false},
	}
	for _, tc := range cases {
		got, ok := muslCryptStarVersion(tc.version)
		if ok != tc.ok {
			t.Errorf("muslCryptStarVersion(%q) ok = %v, want %v", tc.version, ok, tc.ok)
			continue
		}
		if ok && got != tc.want {
			t.Errorf("muslCryptStarVersion(%q) = %v, want %v", tc.version, got, tc.want)
		}
	}
}

func TestMuslCryptStarConfirmed(t *testing.T) {
	cases := []struct {
		stage         string
		sessionOpened bool
		want          bool
	}{
		{stage: "session", sessionOpened: true, want: true},
		{stage: "session", sessionOpened: false, want: false},
		{stage: "open-session", sessionOpened: false, want: false},
		{stage: "auth", sessionOpened: true, want: false},
		{stage: "auth", sessionOpened: false, want: false},
		{stage: "kex", sessionOpened: false, want: false},
		{stage: "", sessionOpened: false, want: false},
	}
	for _, tc := range cases {
		if got := muslCryptStarConfirmed(tc.stage, tc.sessionOpened); got != tc.want {
			t.Errorf("muslCryptStarConfirmed(%q, %v) = %v, want %v", tc.stage, tc.sessionOpened, got, tc.want)
		}
	}
}

func TestMuslCryptStarExecRan(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status string
		ran    bool
	}{
		{name: "nil", err: nil, status: "0", ran: true},
		{name: "exit-missing", err: &ssh.ExitMissingError{}, status: "", ran: true},
		{name: "other", err: errors.New("ssh: unexpected packet"), status: "", ran: false},
		{name: "eof", err: io.EOF, status: "", ran: false},
	}
	for _, tc := range cases {
		status, ran := muslCryptStarExecRan(tc.err)
		if ran != tc.ran || status != tc.status {
			t.Errorf("%s: muslCryptStarExecRan = (%q, %v), want (%q, %v)", tc.name, status, ran, tc.status, tc.ran)
		}
	}
}

func TestMuslCryptStarVulnerableVersion(t *testing.T) {
	cases := []struct {
		version string
		want    bool
	}{
		{version: "SSH-2.0-OpenSSH_7.4", want: true},
		{version: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10", want: true},
		{version: "SSH-2.0-OpenSSH_9.7", want: true},
		{version: "SSH-2.0-OpenSSH_9.7p1", want: true},
		{version: "SSH-2.0-OpenSSH_10.5", want: true},
		{version: "SSH-2.0-OpenSSH_10.6", want: true},
		{version: "SSH-2.0-OpenSSH_10.6p1", want: true},
		{version: "SSH-2.0-OpenSSH_10.6p2", want: false},
		{version: "SSH-2.0-OpenSSH_10.6p3", want: false},
		{version: "SSH-2.0-OpenSSH_10.7", want: false},
		{version: "SSH-2.0-OpenSSH_11.0", want: false},
		{version: "SSH-2.0-OpenSSH", want: false},
		{version: "SSH-2.0-dropbear_2022.83", want: false},
		{version: "SSH-2.0-Go", want: false},
		{version: "", want: false},
	}
	for _, tc := range cases {
		if got := muslCryptStarVulnerableVersion(tc.version); got != tc.want {
			t.Errorf("muslCryptStarVulnerableVersion(%q) = %v, want %v", tc.version, got, tc.want)
		}
	}
}

// muslTestServer is a minimal SSH server that accepts passwords according to
// a predicate and answers exec requests with fixed output, standing in for an
// sshd with the musl crypt(3) behavior.
type muslTestServer struct {
	addr     string
	conns    atomic.Int64
	listener net.Listener
	config   *ssh.ServerConfig
}

// newMuslTestServer starts a server announcing the given banner. accept
// decides which passwords authenticate.
func newMuslTestServer(t *testing.T, banner string, accept func(password []byte) bool) *muslTestServer {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("host key signer: %v", err)
	}

	s := &muslTestServer{}
	s.config = &ssh.ServerConfig{
		ServerVersion: banner,
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if accept(password) {
				return nil, nil
			}
			return nil, errors.New("permission denied")
		},
	}
	s.config.AddHostKey(signer)

	s.listener, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s.addr = s.listener.Addr().String()
	t.Cleanup(func() { s.listener.Close() })

	go func() {
		for {
			c, err := s.listener.Accept()
			if err != nil {
				return
			}
			s.conns.Add(1)
			go s.handle(c)
		}
	}()
	return s
}

func (s *muslTestServer) handle(c net.Conn) {
	defer c.Close()
	_, chans, reqs, err := ssh.NewServerConn(c, s.config)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			return
		}
		go s.session(ch, chReqs)
	}
}

func (s *muslTestServer) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
		switch req.Type {
		case "exec":
			_ = req.Reply(true, nil)
			_, _ = io.WriteString(ch, "uid=1000(alice) gid=1000(alice) groups=1000(alice)\n")
			_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
			return
		case "pty-req", "env", "shell":
			_ = req.Reply(true, nil)
			if req.Type == "shell" {
				_, _ = io.WriteString(ch, "$ ")
			}
		default:
			_ = req.Reply(false, nil)
		}
	}
}

// muslTestHarness builds the scan configuration, options, and root result
// that GetSession would hand to the check for the given server.
func muslTestHarness(t *testing.T, s *muslTestServer, enabled bool) (*ScanConfig, *auth.Options, *auth.AuthResult) {
	t.Helper()

	logger := logrus.New()
	logger.SetOutput(io.Discard)

	conf := &ScanConfig{
		EnabledChecks: map[string]struct{}{},
		Logger:        logger,
	}
	if enabled {
		conf.EnabledChecks[checkVulnMuslCryptStar] = struct{}{}
	}

	host, portStr, _ := net.SplitHostPort(s.addr)
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	options := &auth.Options{
		Host:          host,
		Port:          port,
		Username:      "alice",
		HostKeyAlgs:   auth.HostKeyAlgorithms,
		Timeout:       5 * time.Second,
		Logger:        logger,
		ClientVersion: "OpenSSH_9.8p1",
	}

	root := auth.SSHAuthNone(s.addr, options)
	if root.Stage != "ssh-userauth" {
		t.Fatalf("none auth probe reached stage %q: %s", root.Stage, root.Error)
	}
	if !root.SupportsAuth("password") {
		t.Fatalf("server did not advertise password auth: %v", root.Methods)
	}
	return conf, options, root
}

func muslAcceptLong(password []byte) bool { return len(password) > 256 }
func muslAcceptNone(password []byte) bool { return false }
func muslAcceptAny(password []byte) bool  { return true }

func TestMuslCryptStarCheckReportsVulnerableServer(t *testing.T) {
	s := newMuslTestServer(t, "SSH-2.0-OpenSSH_9.7p1", muslAcceptLong)
	conf, options, root := muslTestHarness(t, s, true)

	res := sshCheckVulnMuslCryptStar(s.addr, conf, options, root)
	if res == nil {
		t.Fatal("check returned nil against a vulnerable server")
	}
	if res.Stage != "session" {
		t.Fatalf("result stage = %q, want session", res.Stage)
	}
	if len(root.Vulns) != 1 || root.Vulns[0].ID != checkVulnMuslCryptStar {
		t.Fatalf("root vulns = %+v, want one %s entry", root.Vulns, checkVulnMuslCryptStar)
	}
	if root.SessionMethod != checkVulnMuslCryptStar || res.SessionMethod != checkVulnMuslCryptStar {
		t.Fatalf("session method = %q / %q, want %s", root.SessionMethod, res.SessionMethod, checkVulnMuslCryptStar)
	}
	if len(root.SessionSecret) != muslCryptStarPasswordLen {
		t.Fatalf("session secret length = %d, want %d", len(root.SessionSecret), muslCryptStarPasswordLen)
	}
	if !strings.Contains(root.SessionOutput, "uid=1000(alice)") {
		t.Fatalf("session output = %q, want id output", root.SessionOutput)
	}
	if root.ExitStatus != "0" {
		t.Fatalf("exit status = %q, want 0", root.ExitStatus)
	}
	if root.SessionAuth == nil {
		t.Fatal("root.SessionAuth is nil; interaction cannot reuse the credential")
	}
}

// TestMuslCryptStarCheckSessionAuthReusable mirrors StartInteract: the cached
// auth method must open a fresh session that can run commands.
func TestMuslCryptStarCheckSessionAuthReusable(t *testing.T) {
	s := newMuslTestServer(t, "SSH-2.0-OpenSSH_9.7p1", muslAcceptLong)
	conf, options, root := muslTestHarness(t, s, true)

	if res := sshCheckVulnMuslCryptStar(s.addr, conf, options, root); res == nil {
		t.Fatal("check returned nil against a vulnerable server")
	}

	ran := false
	handler := func(c net.Conn, sclient *ssh.Client, ses *ssh.Session, res *auth.AuthResult) error {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		out, err := ses.CombinedOutput("id")
		if err != nil {
			return err
		}
		res.SessionOutput = auth.CleanSessionOutput(out)
		ran = true
		return nil
	}
	o := options.WithSessionHandler(handler).WithSessionPoke("").WithRetries(10)
	res := auth.SSHAuth(s.addr, o, auth.SSHAuthHandlerSingle(root.SessionAuth))
	if res.Stage != "session" || !ran {
		t.Fatalf("reusing SessionAuth reached stage %q (ran=%v): %s", res.Stage, ran, res.Error)
	}
	if !strings.Contains(res.SessionOutput, "uid=1000(alice)") {
		t.Fatalf("reused session output = %q, want id output", res.SessionOutput)
	}
}

func TestMuslCryptStarCheckRejectsPatchedServer(t *testing.T) {
	s := newMuslTestServer(t, "SSH-2.0-OpenSSH_9.7p1", muslAcceptNone)
	conf, options, root := muslTestHarness(t, s, true)

	if res := sshCheckVulnMuslCryptStar(s.addr, conf, options, root); res != nil {
		t.Fatalf("check returned %+v against a server that rejects long passwords", res)
	}
	if len(root.Vulns) != 0 {
		t.Fatalf("root vulns = %+v, want none", root.Vulns)
	}
	if root.SessionMethod != "" || root.SessionAuth != nil {
		t.Fatalf("session state set without a session: method=%q auth=%v", root.SessionMethod, root.SessionAuth)
	}
}

func TestMuslCryptStarCheckSkipsPasswordAnyServer(t *testing.T) {
	s := newMuslTestServer(t, "SSH-2.0-OpenSSH_9.7p1", muslAcceptAny)
	conf, options, root := muslTestHarness(t, s, true)

	before := s.conns.Load()
	if res := sshCheckVulnMuslCryptStar(s.addr, conf, options, root); res != nil {
		t.Fatalf("check returned %+v against a server that accepts any password", res)
	}
	if len(root.Vulns) != 0 {
		t.Fatalf("root vulns = %+v, want none", root.Vulns)
	}
	if got := s.conns.Load() - before; got != 1 {
		t.Fatalf("check made %d connections, want only the control attempt", got)
	}
}

func TestMuslCryptStarCheckSkipsByVersion(t *testing.T) {
	cases := []struct {
		name   string
		banner string
	}{
		{name: "fixed release", banner: "SSH-2.0-OpenSSH_10.6p2"},
		{name: "newer release", banner: "SSH-2.0-OpenSSH_11.0"},
		{name: "non-openssh", banner: "SSH-2.0-dropbear_2022.83"},
		{name: "go", banner: "SSH-2.0-Go"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newMuslTestServer(t, tc.banner, muslAcceptLong)
			conf, options, root := muslTestHarness(t, s, true)

			before := s.conns.Load()
			if res := sshCheckVulnMuslCryptStar(s.addr, conf, options, root); res != nil {
				t.Fatalf("check returned %+v for banner %q", res, tc.banner)
			}
			if len(root.Vulns) != 0 {
				t.Fatalf("root vulns = %+v, want none", root.Vulns)
			}
			if got := s.conns.Load() - before; got != 0 {
				t.Fatalf("check made %d connections for banner %q, want none", got, tc.banner)
			}
		})
	}
}

func TestMuslCryptStarCheckDisabled(t *testing.T) {
	s := newMuslTestServer(t, "SSH-2.0-OpenSSH_9.7p1", muslAcceptLong)
	conf, options, root := muslTestHarness(t, s, false)

	before := s.conns.Load()
	if res := sshCheckVulnMuslCryptStar(s.addr, conf, options, root); res != nil {
		t.Fatalf("disabled check returned %+v", res)
	}
	if got := s.conns.Load() - before; got != 0 {
		t.Fatalf("disabled check made %d connections, want none", got)
	}
}

func TestMuslCryptStarEnabledByDefault(t *testing.T) {
	for _, c := range Checks {
		if c.Name == checkVulnMuslCryptStar {
			if !c.Enabled {
				t.Fatalf("%s is registered but not enabled by default", checkVulnMuslCryptStar)
			}
			if c.Category != "vuln" {
				t.Fatalf("%s category = %q, want vuln", checkVulnMuslCryptStar, c.Category)
			}
			return
		}
	}
	t.Fatalf("%s is not registered", checkVulnMuslCryptStar)
}
