package cmd

import (
	"encoding/base64"
	"time"

	"crypto/rand"

	"github.com/runZeroInc/excrypto/x/crypto/ssh"
	"github.com/runZeroInc/sshamble/auth"
)

func genRandomPassword() string {
	buff := make([]byte, 8)
	_, _ = rand.Read(buff)
	return base64.StdEncoding.EncodeToString(buff)
}

func sshCheckPasswordHelper(addr string, tname string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult, testPass string) *auth.AuthResult {
	if !conf.IsCheckEnabled(tname) {
		return nil
	}

	conf.Logger.Debugf("%s %s is running for user %s", addr, tname, options.Username)

	am := ssh.AuthMethod(ssh.PasswordCallback(func() (string, error) {
		return testPass, nil
	}))

	res := auth.SSHAuth(addr, options, auth.SSHAuthHandlerSingle(am))
	if res.Stage != "session" {
		conf.Logger.Debugf("%s %s rejected password in stage %s: %v", addr, tname, res.Stage, res.Error)
		return nil
	}

	conf.Logger.Warnf("%s %s accepted auth with password '%s'", addr, tname, testPass)
	res.SessionMethod = tname
	root.SessionMethod = tname
	root.SessionOutput = res.SessionOutput
	root.SessionSecret = testPass
	root.ExitStatus = res.ExitStatus
	root.SessionAuth = am
	return res
}

func sshCheckPasswordChangeHelper(addr string, tname string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult, curPass string, newPass string) *auth.AuthResult {
	if !conf.IsCheckEnabled(tname) {
		return nil
	}

	conf.Logger.Debugf("%s %s is running for user %s", addr, tname, options.Username)

	am := ssh.AuthMethod(ssh.PasswordChangeCallback(func() (string, string, error) {
		return curPass, newPass, nil
	}))

	res := auth.SSHAuth(addr, options, auth.SSHAuthHandlerSingle(am))
	if res.Stage != "session" {
		conf.Logger.Debugf("%s %s rejected password in stage %s: %v", addr, tname, res.Stage, res.Error)
		return nil
	}

	conf.Logger.Warnf("%s %s accepted auth with password change from '%s' to '%s'", addr, tname, curPass, newPass)
	res.SessionMethod = tname
	root.SessionMethod = tname
	root.SessionOutput = res.SessionOutput
	root.SessionSecret = newPass
	root.ExitStatus = res.ExitStatus

	// If the password was changed, the old password may no longer work (!)
	root.SessionAuth = am
	return res
}

const checkPasswordEmpty = "password-empty"

func sshCheckPasswordEmpty(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	return sshCheckPasswordHelper(addr, checkPasswordEmpty, conf, options, root, "")
}

const checkPasswordAny = "password-any"

func sshCheckPasswordAny(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	return sshCheckPasswordHelper(addr, checkPasswordAny, conf, options, root, genRandomPassword())
}

const checkPasswordNull = "password-null"

func sshCheckPasswordNull(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	return sshCheckPasswordHelper(addr, checkPasswordNull, conf, options, root, "\x00")
}

const checkPasswordUser = "password-user"

func sshCheckPasswordUser(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkPasswordUser
	var lastRes *auth.AuthResult

	tryPassword := func(password string) *auth.AuthResult {
		return sshCheckPasswordHelper(addr, tname, conf, options, root, password)
	}

	if gPassword != "" {
		lastRes = tryPassword(gPassword)
		if lastRes != nil && lastRes.SessionMethod != "" {
			return lastRes
		}
	}

	if gPasswordFile != "" {
		pf := auth.NewPasswordFile(gPasswordFile, conf.Logger)
		if err := pf.Open(); err != nil {
			conf.Logger.Fatalf("%s %s failed to read password file '%s': %v", addr, tname, gPasswordFile, err)
		}
		defer pf.Close()

		stime := time.Now()
		lastStatus := stime
		cnt := 0
		for {
			lines, err := pf.Read(1)
			if err != nil {
				conf.Logger.Errorf("%s %s failed to read password from %s: %v'", addr, tname, gPasswordFile, err)
				break
			}
			if len(lines) == 0 {
				break
			}
			line := lines[0]
			conf.Logger.Tracef("%s %s is testing user %s with password '%s'", addr, tname, options.Username, line)
			lastRes = tryPassword(line)
			cnt++
			if lastRes != nil && lastRes.SessionMethod != "" {
				return lastRes
			}
			if time.Since(lastStatus) > (time.Second * 5) {
				conf.Logger.Infof("%s %s tested %d passwords for user %s in %ds", addr, tname, cnt, options.Username, uint(time.Since(stime)/time.Second))
				lastStatus = time.Now()
			}
		}
		conf.Logger.Infof("%s %s completed %d passwords for user %s in %ds", addr, tname, cnt, options.Username, uint(time.Since(stime)/time.Second))
	}
	return nil
}

const checkPasswordChangeEmpty = "password-change-empty"

func sshCheckPasswordChangeEmpty(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	return sshCheckPasswordChangeHelper(addr, checkPasswordChangeEmpty, conf, options, root, "", "")
}

const checkPasswordChangeNull = "password-change-null"

func sshCheckPasswordChangeNull(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	return sshCheckPasswordChangeHelper(addr, checkPasswordChangeNull, conf, options, root, "\x00", "\x00")
}

func initPasswordChecks() {
	registerCheck(checkPasswordAny, "password", false, true)
	registerCheck(checkPasswordEmpty, "password", false, true)
	registerCheck(checkPasswordNull, "password", false, true)
	registerCheck(checkPasswordUser, "password", false, true)
	registerCheck(checkPasswordChangeEmpty, "password", false, true)
	registerCheck(checkPasswordChangeNull, "password", false, true)
}
