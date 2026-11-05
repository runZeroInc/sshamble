package cmd

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/runZeroInc/excrypto/crypto/ed25519"
	"github.com/runZeroInc/excrypto/x/crypto/ssh"
	"github.com/runZeroInc/sshamble/auth"
	"github.com/sirupsen/logrus"
)

func TestCoreOSPamPermitAffectedVersion(t *testing.T) {
	cases := []struct {
		version string
		want    bool
	}{
		{version: "SSH-2.0-OpenSSH_7.2", want: true},
		{version: "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10", want: false},
		{version: "SSH-2.0-OpenSSH_7.2 FreeBSD-20160310", want: false},
		{version: "SSH-2.0-OpenSSH_7.2p2", want: false},
		{version: "SSH-2.0-OpenSSH_7.1", want: false},
		{version: "SSH-2.0-OpenSSH_7.3", want: false},
		{version: "SSH-2.0-OpenSSH_7.20", want: false},
		{version: "SSH-2.0-OpenSSH_9.7", want: false},
		{version: "SSH-2.0-dropbear_2022.83", want: false},
		{version: "", want: false},
	}
	for _, tc := range cases {
		if got := coreosPamPermitAffectedVersion(tc.version); got != tc.want {
			t.Errorf("coreosPamPermitAffectedVersion(%q) = %v, want %v", tc.version, got, tc.want)
		}
	}
}

func TestCoreOSPamPermitCandidateUsers(t *testing.T) {
	cases := []struct {
		configured string
		want       []string
	}{
		{configured: "root", want: []string{"root", "core", "operator"}},
		{configured: "core", want: []string{"core", "operator"}},
		{configured: "operator", want: []string{"operator", "core"}},
		{configured: "", want: []string{"core", "operator"}},
	}
	for _, tc := range cases {
		got := coreosPamPermitCandidateUsers(tc.configured)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("coreosPamPermitCandidateUsers(%q) = %v, want %v", tc.configured, got, tc.want)
		}
	}
}

func TestCoreOSPamPermitConfirmed(t *testing.T) {
	cases := []struct {
		stage         string
		sessionOpened bool
		want          bool
	}{
		{stage: "session", sessionOpened: true, want: true},
		{stage: "session", sessionOpened: false, want: false},
		{stage: "open-session", sessionOpened: false, want: false},
		{stage: "auth", sessionOpened: true, want: false},
		{stage: "ssh-userauth", sessionOpened: false, want: false},
		{stage: "", sessionOpened: false, want: false},
	}
	for _, tc := range cases {
		if got := coreosPamPermitConfirmed(tc.stage, tc.sessionOpened); got != tc.want {
			t.Errorf("coreosPamPermitConfirmed(%q, %v) = %v, want %v", tc.stage, tc.sessionOpened, got, tc.want)
		}
	}
}

func TestCoreOSPamPermitExecRan(t *testing.T) {
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
		status, ran := coreosPamPermitExecRan(tc.err)
		if ran != tc.ran || status != tc.status {
			t.Errorf("%s: coreosPamPermitExecRan = (%q, %v), want (%q, %v)", tc.name, status, ran, tc.status, tc.ran)
		}
	}
}

// coreosTestServer is a minimal SSH server that authenticates according to a
// per-user predicate over keyboard-interactive and/or password, and answers
// exec requests with fixed output. It stands in for a CoreOS sshd.
type coreosTestServer struct {
	addr     string
	conns    atomic.Int64
	listener net.Listener
	config   *ssh.ServerConfig
}

// coreosAcceptFunc decides whether a user and password combination logs in.
type coreosAcceptFunc func(user string, password []byte) bool

// newCoreOSTestServer starts a server announcing the given banner. kbd and
// pass select which auth methods the server offers.
func newCoreOSTestServer(t *testing.T, banner string, kbd, pass bool, accept coreosAcceptFunc) *coreosTestServer {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("host key signer: %v", err)
	}

	s := &coreosTestServer{}
	s.config = &ssh.ServerConfig{ServerVersion: banner}
	if kbd {
		s.config.KeyboardInteractiveCallback = func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			answers, err := client("", "", []string{"Password: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(answers) == 1 && accept(conn.User(), []byte(answers[0])) {
				return nil, nil
			}
			return nil, errors.New("permission denied")
		}
	}
	if pass {
		s.config.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if accept(conn.User(), password) {
				return nil, nil
			}
			return nil, errors.New("permission denied")
		}
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

func (s *coreosTestServer) handle(c net.Conn) {
	defer c.Close()
	sc, chans, reqs, err := ssh.NewServerConn(c, s.config)
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
		go s.session(sc.User(), ch, chReqs)
	}
}

func (s *coreosTestServer) session(user string, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
		switch req.Type {
		case "exec":
			_ = req.Reply(true, nil)
			_, _ = fmt.Fprintf(ch, "uid=500(%s) gid=500(%s) groups=500(%s)\n", user, user, user)
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

// coreosTestHarness builds the scan configuration, options, and root result
// that GetSession would hand to the check for the given server and user.
func coreosTestHarness(t *testing.T, s *coreosTestServer, user string, enabled bool) (*ScanConfig, *auth.Options, *auth.AuthResult) {
	t.Helper()

	logger := logrus.New()
	logger.SetOutput(io.Discard)

	conf := &ScanConfig{
		EnabledChecks: map[string]struct{}{},
		Logger:        logger,
	}
	if enabled {
		conf.EnabledChecks[checkVulnCoreOSPamPermit] = struct{}{}
	}

	host, portStr, _ := net.SplitHostPort(s.addr)
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	options := &auth.Options{
		Host:          host,
		Port:          port,
		Username:      user,
		HostKeyAlgs:   auth.HostKeyAlgorithms,
		Timeout:       5 * time.Second,
		Logger:        logger,
		ClientVersion: "OpenSSH_9.8p1",
	}

	root := auth.SSHAuthNone(s.addr, options)
	if root.Stage != "ssh-userauth" {
		t.Fatalf("none auth probe reached stage %q: %s", root.Stage, root.Error)
	}
	return conf, options, root
}

// coreosAcceptNonRoot mirrors the vulnerable CoreOS stack: PAM permits any
// password for any account, but sshd refuses root before PAM runs.
func coreosAcceptNonRoot(user string, password []byte) bool { return user != "root" }

func coreosAcceptNone(user string, password []byte) bool { return false }

func TestCoreOSPamPermitCheckFallsBackToCoreUser(t *testing.T) {
	s := newCoreOSTestServer(t, "SSH-2.0-OpenSSH_7.2", true, false, coreosAcceptNonRoot)
	conf, options, root := coreosTestHarness(t, s, "root", true)

	res := sshCheckVulnCoreOSPamPermit(s.addr, conf, options, root)
	if res == nil {
		t.Fatal("check returned nil against a vulnerable server")
	}
	if res.Stage != "session" {
		t.Fatalf("result stage = %q, want session", res.Stage)
	}
	if len(root.Vulns) != 1 || root.Vulns[0].ID != checkVulnCoreOSPamPermit {
		t.Fatalf("root vulns = %+v, want one %s entry", root.Vulns, checkVulnCoreOSPamPermit)
	}
	if !strings.Contains(root.Vulns[0].Proof, "for core via keyboard-interactive") {
		t.Fatalf("proof = %q, want core via keyboard-interactive", root.Vulns[0].Proof)
	}
	if root.SessionMethod != checkVulnCoreOSPamPermit || root.SessionUser != "core" {
		t.Fatalf("session method/user = %q/%q, want %s/core", root.SessionMethod, root.SessionUser, checkVulnCoreOSPamPermit)
	}
	if !strings.Contains(root.SessionOutput, "uid=500(core)") {
		t.Fatalf("session output = %q, want id output for core", root.SessionOutput)
	}
	if root.ExitStatus != "0" {
		t.Fatalf("exit status = %q, want 0", root.ExitStatus)
	}
	if root.SessionAuth == nil || root.SessionSecret == "" {
		t.Fatal("session credential was not cached for interaction")
	}
}

func TestCoreOSPamPermitCheckConfiguredUser(t *testing.T) {
	s := newCoreOSTestServer(t, "SSH-2.0-OpenSSH_7.2", true, true, coreosAcceptNonRoot)
	conf, options, root := coreosTestHarness(t, s, "operator", true)

	before := s.conns.Load()
	res := sshCheckVulnCoreOSPamPermit(s.addr, conf, options, root)
	if res == nil {
		t.Fatal("check returned nil against a vulnerable server")
	}
	if root.SessionUser != "operator" {
		t.Fatalf("session user = %q, want operator", root.SessionUser)
	}
	if got := s.conns.Load() - before; got != 1 {
		t.Fatalf("check made %d connections, want 1 for the configured user", got)
	}
}

func TestCoreOSPamPermitCheckPasswordOnly(t *testing.T) {
	s := newCoreOSTestServer(t, "SSH-2.0-OpenSSH_7.2", false, true, coreosAcceptNonRoot)
	conf, options, root := coreosTestHarness(t, s, "core", true)

	res := sshCheckVulnCoreOSPamPermit(s.addr, conf, options, root)
	if res == nil {
		t.Fatal("check returned nil against a vulnerable password-only server")
	}
	if !strings.Contains(root.Vulns[0].Proof, "for core via password") {
		t.Fatalf("proof = %q, want core via password", root.Vulns[0].Proof)
	}
}

// TestCoreOSPamPermitCheckSessionAuthReusable mirrors StartInteract: the
// cached auth method and session user must open a fresh session that runs
// commands.
func TestCoreOSPamPermitCheckSessionAuthReusable(t *testing.T) {
	s := newCoreOSTestServer(t, "SSH-2.0-OpenSSH_7.2", true, false, coreosAcceptNonRoot)
	conf, options, root := coreosTestHarness(t, s, "root", true)

	if res := sshCheckVulnCoreOSPamPermit(s.addr, conf, options, root); res == nil {
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
	o := options.WithUsername(root.SessionUser).WithSessionHandler(handler).WithSessionPoke("").WithRetries(10)
	res := auth.SSHAuth(s.addr, o, auth.SSHAuthHandlerSingle(root.SessionAuth))
	if res.Stage != "session" || !ran {
		t.Fatalf("reusing SessionAuth reached stage %q (ran=%v): %s", res.Stage, ran, res.Error)
	}
	if !strings.Contains(res.SessionOutput, "uid=500(core)") {
		t.Fatalf("reused session output = %q, want id output for core", res.SessionOutput)
	}
}

func TestCoreOSPamPermitCheckRejectsPatchedServer(t *testing.T) {
	s := newCoreOSTestServer(t, "SSH-2.0-OpenSSH_7.2", true, false, coreosAcceptNone)
	conf, options, root := coreosTestHarness(t, s, "root", true)

	before := s.conns.Load()
	if res := sshCheckVulnCoreOSPamPermit(s.addr, conf, options, root); res != nil {
		t.Fatalf("check returned %+v against a server that rejects every password", res)
	}
	if len(root.Vulns) != 0 {
		t.Fatalf("root vulns = %+v, want none", root.Vulns)
	}
	if root.SessionMethod != "" || root.SessionUser != "" || root.SessionAuth != nil {
		t.Fatalf("session state set without a session: method=%q user=%q", root.SessionMethod, root.SessionUser)
	}
	if got := s.conns.Load() - before; got != 3 {
		t.Fatalf("check made %d connections, want one per candidate user", got)
	}
}

func TestCoreOSPamPermitCheckSkipsByVersion(t *testing.T) {
	cases := []struct {
		name   string
		banner string
	}{
		{name: "ubuntu 7.2p2", banner: "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10"},
		{name: "freebsd 7.2", banner: "SSH-2.0-OpenSSH_7.2 FreeBSD-20160310"},
		{name: "openssh 7.3", banner: "SSH-2.0-OpenSSH_7.3"},
		{name: "openssh 7.1", banner: "SSH-2.0-OpenSSH_7.1"},
		{name: "dropbear", banner: "SSH-2.0-dropbear_2022.83"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newCoreOSTestServer(t, tc.banner, true, true, coreosAcceptNonRoot)
			conf, options, root := coreosTestHarness(t, s, "core", true)

			before := s.conns.Load()
			if res := sshCheckVulnCoreOSPamPermit(s.addr, conf, options, root); res != nil {
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

func TestCoreOSPamPermitCheckDisabled(t *testing.T) {
	s := newCoreOSTestServer(t, "SSH-2.0-OpenSSH_7.2", true, false, coreosAcceptNonRoot)
	conf, options, root := coreosTestHarness(t, s, "core", false)

	before := s.conns.Load()
	if res := sshCheckVulnCoreOSPamPermit(s.addr, conf, options, root); res != nil {
		t.Fatalf("disabled check returned %+v", res)
	}
	if got := s.conns.Load() - before; got != 0 {
		t.Fatalf("disabled check made %d connections, want none", got)
	}
}

func TestCoreOSPamPermitEnabledByDefault(t *testing.T) {
	for _, c := range Checks {
		if c.Name == checkVulnCoreOSPamPermit {
			if !c.Enabled {
				t.Fatalf("%s is registered but not enabled by default", checkVulnCoreOSPamPermit)
			}
			if c.Category != "vuln" {
				t.Fatalf("%s category = %q, want vuln", checkVulnCoreOSPamPermit, c.Category)
			}
			return
		}
	}
	t.Fatalf("%s is not registered", checkVulnCoreOSPamPermit)
}
