package cmd

import (
	"io"

	"github.com/runZeroInc/sshamble/auth"
	"github.com/runZeroInc/sshamble/crypto/ssh"
)

func sessionGetSTDIO(ses *ssh.Session) (*auth.SyncByteBuffer, *auth.SyncByteBuffer, io.WriteCloser, error) {
	stdOut := auth.NewSyncByteBuffer(1024 * 16)
	stdErr := auth.NewSyncByteBuffer(1024 * 16)
	ses.Stdout = stdOut
	ses.Stderr = stdErr
	stdIn, err := ses.StdinPipe()
	return stdOut, stdErr, stdIn, err
}

func initSessionChecks() {
	// Register vulnerability checks
	registerCheck(checkVulnGogsEnv, "vuln", true, true)
	registerCheck(checkVulnRuckusPasswordEscape, "vuln", true, true)
	registerCheck(checkVulnSoftServe, "vuln", true, true)
	registerCheck(checkVulnGenericEnv, "vuln", true, true)
	registerCheck(checkVulnTCPForward, "vuln", true, true)
}
