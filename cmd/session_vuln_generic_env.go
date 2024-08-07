package cmd

import (
	"fmt"
	"net"
	"regexp"
	"time"

	"github.com/runZeroInc/sshamble/auth"
	"github.com/runZeroInc/sshamble/crypto/ssh"
)

const checkVulnGenericEnv = "vuln-generic-env"

type envTest struct {
	Name    string
	Value   string
	Pattern *regexp.Regexp
}

var vulnGenericEnvSeeds = []envTest{
	{"LD_DEBUG", "all", regexp.MustCompile(`binding file |find library=`)},
	{"LD_PRELOAD", "/", regexp.MustCompile(`ERROR: ld\.so|cannot be preloaded`)},
	{"LD_AUDIT", "/", regexp.MustCompile(`ERROR: ld\.so|cannot be loaded as audit interface`)},
	{"GODEBUG", "inittrace=1", regexp.MustCompile(`init .* @\d+ ms\.*\d+ allocs`)},
}

// sshCheckVulnGenericEnv tries stuffing various environment variables into a session before opening a shell
func sshCheckVulnGenericEnv(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkVulnGenericEnv
	if !conf.IsCheckEnabled(tname) {
		conf.Logger.Debugf("%s %s is not enabled", addr, tname)
		return nil
	}

	conf.Logger.Debugf("%s %s is running for user %s", addr, tname, options.Username)

	if root.SessionAuth == nil {
		conf.Logger.Errorf("%s %s is missing cached session auth, skipping", addr, tname)
		return nil
	}

	cb := func(c net.Conn, _ *ssh.Client, ses *ssh.Session, res *auth.AuthResult) error {
		c.SetDeadline(time.Now().Add(time.Second * 15))

		for _, seed := range vulnGenericEnvSeeds {
			_ = ses.Setenv(seed.Name, seed.Value)
		}

		if err := ses.RequestPtyNoReply("xterm", 20, 80, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
			conf.Logger.Errorf("%s %s pty request failed: %v", addr, tname, err)
		}

		return auth.ScrapeSession(options, addr+" "+tname, res, ses)
	}

	res := auth.SSHAuth(addr, options.WithSessionHandler(cb), auth.SSHAuthHandlerSingle(root.SessionAuth))

	// Failed to open session
	if res.Stage != "session" {
		conf.Logger.Errorf("%s %s failed to re-open session using %s: %v", addr, tname, root.SessionMethod, res.Error)
		return res
	}

	found := ""
	for _, seed := range vulnGenericEnvSeeds {
		if seed.Pattern.MatchString(res.SessionOutput) {
			found = seed.Name + "=" + seed.Value
			break
		}
	}

	if found == "" {
		conf.Logger.Infof("%s %s received no interesting output %#v", addr, tname, res.SessionOutput)
		return res
	}

	conf.Logger.Infof("%s %s identified a vulnerable response for %s: %#v", addr, tname, found, res.SessionOutput)

	root.AddVuln(auth.VulnResult{
		ID:    checkVulnGenericEnv,
		Ref:   "https://cwe.mitre.org/data/definitions/454.html",
		Proof: fmt.Sprintf("vulnerable to %s: %s", found, res.SessionOutput),
	})

	return res
}
