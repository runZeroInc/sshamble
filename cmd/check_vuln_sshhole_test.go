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

func TestSSHHoleVersion(t *testing.T) {
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
		got, ok := sshholeVersion(tc.version)
		if ok != tc.ok {
			t.Errorf("sshholeVersion(%q) ok = %v, want %v", tc.version, ok, tc.ok)
			continue
		}
		if ok && got != tc.want {
			t.Errorf("sshholeVersion(%q) = %v, want %v", tc.version, got, tc.want)
		}
	}
}

func TestSSHHoleVulnerableVersion(t *testing.T) {
	cases := []struct {
		version string
		want    bool
	}{
		{version: "SSH-2.0-OpenSSH_7.4", want: true},
		{version: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10", want: true},
		{version: "SSH-2.0-OpenSSH_9.7", want: true},
		{version: "SSH-2.0-OpenSSH_9.7p1", want: true},
		{version: "SSH-2.0-OpenSSH_10.3p1", want: true},
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
		if got := sshholeVulnerableVersion(tc.version); got != tc.want {
			t.Errorf("sshholeVulnerableVersion(%q) = %v, want %v", tc.version, got, tc.want)
		}
	}
}

func TestSSHHolePasswords(t *testing.T) {
	pws := sshholePasswords()
	want := append([]int{sshholeControlLen}, sshholeTriggerLens...)
	if len(pws) != len(want) {
		t.Fatalf("sshholePasswords() returned %d passwords, want %d", len(pws), len(want))
	}
	for i, pw := range pws {
		if len(pw) != want[i] {
			t.Errorf("password %d is %d bytes, want %d", i, len(pw), want[i])
		}
		if strings.ContainsRune(pw, 0) {
			t.Errorf("password %d contains a NUL byte", i)
		}
	}
	if pws[1] == sshholePasswords()[1] {
		t.Errorf("trigger passwords repeat across calls")
	}
}

func TestSSHHoleClassify(t *testing.T) {
	fail := ssh.AuthResultFailure
	ok := ssh.AuthResultSuccess
	partial := ssh.AuthResultPartialSuccess
	cases := []struct {
		name    string
		results []ssh.ExpAuthResult
		want    int
	}{
		{"no attempts", nil, -1},
		{"control accepted", []ssh.ExpAuthResult{ok}, -1},
		{"control partial", []ssh.ExpAuthResult{partial}, -1},
		{"first trigger accepted", []ssh.ExpAuthResult{fail, ok}, 1},
		{"first trigger partial", []ssh.ExpAuthResult{fail, partial}, 1},
		{"second trigger accepted", []ssh.ExpAuthResult{fail, fail, ok}, 2},
		{"all rejected", []ssh.ExpAuthResult{fail, fail, fail}, -1},
		{"disconnected after control", []ssh.ExpAuthResult{fail}, -1},
		{"disconnected after first trigger", []ssh.ExpAuthResult{fail, fail}, -1},
	}
	for _, tc := range cases {
		got, reason := sshholeClassify(tc.results)
		if got != tc.want {
			t.Errorf("%s: sshholeClassify() = %d (%s), want %d", tc.name, got, reason, tc.want)
		}
		if got < 0 && reason == "" {
			t.Errorf("%s: no reason given for a negative result", tc.name)
		}
	}
}

func TestSSHHoleMaxAuthTries(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("ssh: disconnect, reason 2: Too many authentication failures"), true},
		{errors.New("ssh: disconnect, reason 2: too many authentication failures"), true},
		{errors.New("ssh: disconnect, reason 2: too many authentication attempts"), false},
		{io.EOF, false},
	}
	for _, tc := range cases {
		if got := sshholeMaxAuthTries(tc.err); got != tc.want {
			t.Errorf("sshholeMaxAuthTries(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

func TestSSHHoleExecRan(t *testing.T) {
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
		status, ran := sshholeExecRan(tc.err)
		if ran != tc.ran || status != tc.status {
			t.Errorf("%s: sshholeExecRan = (%q, %v), want (%q, %v)", tc.name, status, ran, tc.status, tc.ran)
		}
	}
}

// muslAcceptFunc decides whether a password authenticates. attempt is the
// 1-based count of password attempts on the current connection.
type muslAcceptFunc func(attempt int, password []byte) bool

// muslTestServer is a minimal SSH server that accepts passwords according to
// a predicate and answers exec requests with fixed output, standing in for an
// sshd with the musl crypt(3) behavior.
type muslTestServer struct {
	addr         string
	conns        atomic.Int64
	listener     net.Listener
	banner       string
	signer       ssh.Signer
	accept       muslAcceptFunc
	maxAuthTries int
}

// newMuslTestServer starts a server announcing the given banner.
func newMuslTestServer(t *testing.T, banner string, accept muslAcceptFunc) *muslTestServer {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("host key signer: %v", err)
	}

	s := &muslTestServer{banner: banner, signer: signer, accept: accept}
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

// config builds a per-connection server configuration so the attempt
// counter starts at zero for every connection, as a forked sshd does.
func (s *muslTestServer) config() *ssh.ServerConfig {
	attempts := 0
	conf := &ssh.ServerConfig{
		ServerVersion: s.banner,
		MaxAuthTries:  s.maxAuthTries,
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			attempts++
			if s.accept(attempts, password) {
				return nil, nil
			}
			return nil, errors.New("permission denied")
		},
	}
	conf.AddHostKey(s.signer)
	return conf
}

func (s *muslTestServer) handle(c net.Conn) {
	defer c.Close()
	_, chans, reqs, err := ssh.NewServerConn(c, s.config())
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
		conf.EnabledChecks[checkVulnSSHHole] = struct{}{}
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

// muslAcceptLong models the bug as sshd reads /etc/passwd directly: any
// password over 256 bytes matches "*" on the first attempt.
func muslAcceptLong(_ int, password []byte) bool {
	return len(password) > 256 && len(password) <= 1024
}

// muslAcceptLongAfterFailure models the bug with /etc/shadow present: the
// first attempt on a connection always fails because pick_salt() clobbers
// musl's static getspnam() buffer, and later long passwords match "*".
func muslAcceptLongAfterFailure(attempt int, password []byte) bool {
	return attempt > 1 && muslAcceptLong(attempt, password)
}

func muslAcceptNone(int, []byte) bool { return false }
func muslAcceptAny(int, []byte) bool  { return true }

func muslRequireVuln(t *testing.T, s *muslTestServer, res *auth.AuthResult, root *auth.AuthResult) {
	t.Helper()
	if res == nil {
		t.Fatal("check returned nil against a vulnerable server")
	}
	if res.Stage != "session" {
		t.Fatalf("result stage = %q, want session", res.Stage)
	}
	if len(root.Vulns) != 1 || root.Vulns[0].ID != checkVulnSSHHole {
		t.Fatalf("root vulns = %+v, want one %s entry", root.Vulns, checkVulnSSHHole)
	}
	if root.SessionMethod != checkVulnSSHHole || res.SessionMethod != checkVulnSSHHole {
		t.Fatalf("session method = %q / %q, want %s", root.SessionMethod, res.SessionMethod, checkVulnSSHHole)
	}
	if len(root.SessionSecret) != sshholeTriggerLens[0] {
		t.Fatalf("session secret length = %d, want %d", len(root.SessionSecret), sshholeTriggerLens[0])
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
	if got := s.conns.Load(); got != 3 {
		t.Fatalf("server saw %d connections, want 3 (none probe, trigger run, reuse check)", got)
	}
}

func TestSSHHoleCheckReportsVulnerableServer(t *testing.T) {
	s := newMuslTestServer(t, "SSH-2.0-OpenSSH_9.7p1", muslAcceptLongAfterFailure)
	conf, options, root := muslTestHarness(t, s, true)

	res := sshCheckVulnSSHHole(s.addr, conf, options, root)
	muslRequireVuln(t, s, res, root)
	if !strings.Contains(root.Vulns[0].Proof, "on attempt 2") {
		t.Fatalf("proof = %q, want the reuse check to need a second attempt", root.Vulns[0].Proof)
	}
}

func TestSSHHoleCheckReportsFirstAttemptServer(t *testing.T) {
	s := newMuslTestServer(t, "SSH-2.0-OpenSSH_9.7p1", muslAcceptLong)
	conf, options, root := muslTestHarness(t, s, true)

	res := sshCheckVulnSSHHole(s.addr, conf, options, root)
	muslRequireVuln(t, s, res, root)
	if !strings.Contains(root.Vulns[0].Proof, "on attempt 1") {
		t.Fatalf("proof = %q, want the reuse check to succeed on the first attempt", root.Vulns[0].Proof)
	}
}

func TestSSHHoleCheckReportsAtMaxAuthTries(t *testing.T) {
	s := newMuslTestServer(t, "SSH-2.0-OpenSSH_9.7p1", muslAcceptLongAfterFailure)
	s.maxAuthTries = 2
	conf, options, root := muslTestHarness(t, s, true)

	res := sshCheckVulnSSHHole(s.addr, conf, options, root)
	muslRequireVuln(t, s, res, root)
}

// TestSSHHoleCheckSessionAuthReusable mirrors StartInteract: the cached
// auth method must open a fresh session that can run commands, even though
// the first password attempt on every connection fails.
func TestSSHHoleCheckSessionAuthReusable(t *testing.T) {
	s := newMuslTestServer(t, "SSH-2.0-OpenSSH_9.7p1", muslAcceptLongAfterFailure)
	conf, options, root := muslTestHarness(t, s, true)

	if res := sshCheckVulnSSHHole(s.addr, conf, options, root); res == nil {
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

func TestSSHHoleCheckRejectsPatchedServer(t *testing.T) {
	for _, maxAuthTries := range []int{0, 2} {
		t.Run(fmt.Sprintf("maxAuthTries=%d", maxAuthTries), func(t *testing.T) {
			s := newMuslTestServer(t, "SSH-2.0-OpenSSH_9.7p1", muslAcceptNone)
			s.maxAuthTries = maxAuthTries
			conf, options, root := muslTestHarness(t, s, true)

			before := s.conns.Load()
			if res := sshCheckVulnSSHHole(s.addr, conf, options, root); res != nil {
				t.Fatalf("check returned %+v against a server that rejects long passwords", res)
			}
			if len(root.Vulns) != 0 {
				t.Fatalf("root vulns = %+v, want none", root.Vulns)
			}
			if root.SessionMethod != "" || root.SessionAuth != nil {
				t.Fatalf("session state set without a session: method=%q auth=%v", root.SessionMethod, root.SessionAuth)
			}
			if got := s.conns.Load() - before; got != 1 {
				t.Fatalf("check made %d connections, want 1", got)
			}
		})
	}
}

func TestSSHHoleCheckSkipsPasswordAnyServer(t *testing.T) {
	s := newMuslTestServer(t, "SSH-2.0-OpenSSH_9.7p1", muslAcceptAny)
	conf, options, root := muslTestHarness(t, s, true)

	before := s.conns.Load()
	if res := sshCheckVulnSSHHole(s.addr, conf, options, root); res != nil {
		t.Fatalf("check returned %+v against a server that accepts any password", res)
	}
	if len(root.Vulns) != 0 {
		t.Fatalf("root vulns = %+v, want none", root.Vulns)
	}
	if got := s.conns.Load() - before; got != 1 {
		t.Fatalf("check made %d connections, want only the control attempt", got)
	}
}

func TestSSHHoleCheckSkipsByVersion(t *testing.T) {
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
			s := newMuslTestServer(t, tc.banner, muslAcceptLongAfterFailure)
			conf, options, root := muslTestHarness(t, s, true)

			before := s.conns.Load()
			if res := sshCheckVulnSSHHole(s.addr, conf, options, root); res != nil {
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

func TestSSHHoleCheckDisabled(t *testing.T) {
	s := newMuslTestServer(t, "SSH-2.0-OpenSSH_9.7p1", muslAcceptLongAfterFailure)
	conf, options, root := muslTestHarness(t, s, false)

	before := s.conns.Load()
	if res := sshCheckVulnSSHHole(s.addr, conf, options, root); res != nil {
		t.Fatalf("disabled check returned %+v", res)
	}
	if got := s.conns.Load() - before; got != 0 {
		t.Fatalf("disabled check made %d connections, want none", got)
	}
}

func TestSSHHoleEnabledByDefault(t *testing.T) {
	for _, c := range Checks {
		if c.Name == checkVulnSSHHole {
			if !c.Enabled {
				t.Fatalf("%s is registered but not enabled by default", checkVulnSSHHole)
			}
			if c.Category != "vuln" {
				t.Fatalf("%s category = %q, want vuln", checkVulnSSHHole, c.Category)
			}
			return
		}
	}
	t.Fatalf("%s is not registered", checkVulnSSHHole)
}
