package cmd

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/runZeroInc/excrypto/x/crypto/ssh"
	"github.com/runZeroInc/sshamble/auth"
)

const checkVulnExecSkipUserAuth = "vuln-exec-skip-userauth"

func sshCheckVulnExecSkipUserAuth(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkVulnExecSkipUserAuth
	return sshCheckVulnExecHelper(tname, addr, conf, options, root, []string{"ssh-userauth", "auth"})
}

const checkVulnExecSkipAuth = "vuln-exec-skip-auth"

func sshCheckVulnExecSkipAuth(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkVulnExecSkipUserAuth
	conf.Logger.Debugf("%s %s is running for user %s", addr, tname, options.Username)
	return sshCheckVulnExecHelper(tname, addr, conf, options, root, []string{"auth"})
}

func sshCheckVulnExecHelper(tname string, addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult, skipStages []string) *auth.AuthResult {
	if !conf.IsCheckEnabled(tname) {
		return nil
	}
	conf.Logger.Debugf("%s %s is running for user %s", addr, tname, options.Username)

	/*
		This test identifies cases where the server processes the channel open and exec commands
		but does not send a reply to either request (ex: Erlang-SSHD). The theory is that non-vulnerable
		servers will either reply with an error or close the socket.
	*/
	var maxWaitSeconds = 5
	options = options.
		WithSkipStages(skipStages...).
		WithIgnoreChannelOpenReply(true).
		WithSessionHandler(func(c net.Conn, sclient *ssh.Client, ses *ssh.Session, r *auth.AuthResult) error {
			_ = c.SetDeadline(time.Now().Add(time.Second * time.Duration(maxWaitSeconds)))
			stime := time.Now()
			err := ses.Start(`help`)
			if err == nil {
				conf.Logger.Debugf("%s %s completed exec without error", addr, tname)
				return nil
			}
			if err == io.EOF && time.Since(stime) > time.Second*time.Duration(maxWaitSeconds-1) {
				conf.Logger.Debugf("%s %s completed exec with timeout", addr, tname)
				return nil
			}
			conf.Logger.Debugf("%s %s unlikely exec error %v after %s", addr, tname, err, time.Since(stime))
			return err
		})

	res := auth.SSHAuth(addr, options, auth.SSHAuthHandlerSingle(ssh.None()))
	if bypassAtInterestingStage(tname, addr, conf, res) {
		var proof = root.SessionOutput
		if res.SessionOutput == "" {
			proof = "timeout reached"
		}
		root.AddVuln(auth.VulnResult{
			ID:    tname,
			Ref:   "https://www.openwall.com/lists/oss-security/2025/04/16/2",
			Proof: fmt.Sprintf("exec may have been processed: %s (skipped stages: %v)", proof, strings.Join(skipStages, ",")),
		})
		return res
	}

	// An alternate implementation using raw messages instead
	/*
		cb := func(c net.Conn, uac *ssh.UnauthClientConn, r *auth.AuthResult) error {
			_ = c.SetDeadline(time.Now().Add(time.Second * 15))
			raw := uac.BuildChannelOpen(0, "session", nil)
			uac.WriteRaw(raw, false)
			raw = uac.BuildChannelRequestString(0, "exec", "id", true)
			uac.WriteRaw(raw, false)
			for {
				reply, err := uac.ReadRaw()
				if err != nil {
					conf.Logger.Warnf("%s %s got error %#v", addr, tname, err)
					break
				}

			}
			return nil
		}
		options = options.WithSkipStages("ssh-userauth", "auth").WithIgnoreAuthError().WithPostAuthHandler(cb)
	*/

	// Note: For Erlang-SSHD, the payload `ssh:stop().` kills the service
	return nil
}
