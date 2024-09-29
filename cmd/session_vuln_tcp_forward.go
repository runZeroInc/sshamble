package cmd

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/runZeroInc/excrypto/x/crypto/ssh"
	"github.com/runZeroInc/sshamble/auth"
)

type fwdTest struct {
	Host string
	Port uint16
}

var vulnTCPForwardTests = []fwdTest{
	{"127.0.0.1", 22},
	{"127.1.1.1", 22},
	{"127.0.0.1", 443},
	{"8.8.8.8", 53},
	{"1.1.1.1", 53},
	{"1.1.1.1", 443},
}

const checkVulnTCPForward = "vuln-tcp-forward"

// sshCheckVulnTCPForward tries stuffing various environment variables into a session before opening a shell
func sshCheckVulnTCPForward(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkVulnTCPForward
	if !conf.IsCheckEnabled(tname) {
		conf.Logger.Debugf("%s %s is not enabled", addr, tname)
		return nil
	}

	conf.Logger.Debugf("%s %s is running for user %s", addr, tname, options.Username)

	if root.SessionAuth == nil {
		conf.Logger.Errorf("%s %s is missing cached session auth, skipping", addr, tname)
		return nil
	}

	accepted := ""
	cb := func(c net.Conn, sclient *ssh.Client, ses *ssh.Session, res *auth.AuthResult) error {
		c.SetDeadline(time.Now().Add(time.Second * 30))
		for _, t := range vulnTCPForwardTests {
			tcpAddr := net.JoinHostPort(t.Host, strconv.FormatUint(uint64(t.Port), 10))
			conf.Logger.Debugf("%s %s connecting to %s...", addr, tname, tcpAddr)
			c, err := sclient.Dial("tcp", tcpAddr)
			if err != nil {
				conf.Logger.Infof("%s %s failed to connect to %s: %v", addr, tname, tcpAddr, err)
				continue
			}
			conf.Logger.Warnf("successfully connected to %s:%d", t.Host, t.Port)
			accepted = tcpAddr
			c.Close()
			break
		}
		return nil
	}

	res := auth.SSHAuth(addr, options.WithSessionHandler(cb), auth.SSHAuthHandlerSingle(root.SessionAuth))

	// Failed to open session
	if res.Stage != "session" {
		conf.Logger.Errorf("%s %s failed to re-open session using %s: %v", addr, tname, root.SessionMethod, res.Error)
		return res
	}
	if accepted == "" {
		conf.Logger.Infof("%s %s refused to forward any ports", addr, tname)
		return res
	}

	conf.Logger.Warnf("%s %s forwarded a connection to %s", addr, tname, accepted)

	root.AddVuln(auth.VulnResult{
		ID:    checkVulnTCPForward,
		Ref:   "https://cwe.mitre.org/data/definitions/183.html",
		Proof: fmt.Sprintf("vulnerable to port forwarding (%s)", accepted),
	})

	return res
}
