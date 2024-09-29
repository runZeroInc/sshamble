package cmd

import (
	"github.com/runZeroInc/excrypto/x/crypto/ssh"
	"github.com/runZeroInc/sshamble/auth"
)

// TODO: Complete implementation
func sshCheckGSSAPIHelper(addr string, tname string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult, gac ssh.GSSAPIClient, target string) *auth.AuthResult {
	if !conf.IsCheckEnabled(tname) {
		return nil
	}

	conf.Logger.Debugf("%s %s is running for user %s", addr, tname, options.Username)

	// unknown mech-code 0 for mech 1 2 840 113554 1 2 2

	am := ssh.GSSAPIWithMICAuthMethod(gac, target)
	res := auth.SSHAuth(addr, options, auth.SSHAuthHandlerSingle(am))

	if res.Stage != "session" {
		conf.Logger.Debugf("%s %s rejected gssapi in stage %s: %v", addr, tname, res.Stage, res.Error)
		return res
	}

	conf.Logger.Warnf("%s %s accepted auth with gssapi", addr, tname)
	res.SessionMethod = tname
	root.SessionMethod = tname
	root.SessionOutput = res.SessionOutput
	root.ExitStatus = res.ExitStatus
	root.SessionAuth = am
	return res
}

type gssapiClient struct {
	Addr  string
	TName string
}

func NewGSSAPIClient(addr string, tname string) *gssapiClient {
	return &gssapiClient{Addr: addr, TName: tname}
}

// InitSecContext initiates the establishment of a security context for GSS-API between the
// ssh client and ssh server.
func (gac *gssapiClient) InitSecContext(target string, token []byte, isGSSDelegCreds bool) (outputToken []byte, needContinue bool, err error) {
	// Initially the token parameter should be specified as nil.
	// The routine may return a outputToken which should be transferred to
	// the ssh server, where the ssh server will present it to
	// AcceptSecContext. If no token need be sent, InitSecContext will indicate this by setting
	// needContinue to false. To complete the context
	// establishment, one or more reply tokens may be required from the ssh
	// server;if so, InitSecContext will return a needContinue which is true.
	// In this case, InitSecContext should be called again when the
	// reply token is received from the ssh server, passing the reply
	// token to InitSecContext via the token parameters.
	// See RFC 2743 section 2.2.1 and RFC 4462 section 3.4.

	// TODO: Implement
	//conf.Logger.Errorf("%s %s GSSAPI InitSecContext() for target '%s' with token %s (delegated:%v)", gac.Addr, gac.TName, target, hex.EncodeToString(token), isGSSDelegCreds)
	return nil, true, nil
}

// GetMIC generates a cryptographic MIC for the SSH2 message, and places
// the MIC in a token for transfer to the ssh server.
func (gac *gssapiClient) GetMIC(micField []byte) ([]byte, error) {
	// The contents of the MIC field are obtained by calling GSS_GetMIC()
	// over the following, using the GSS-API context that was just
	// established:
	//
	//	string    session identifier
	//	byte      SSH_MSG_USERAUTH_REQUEST
	//	string    user name
	//	string    service
	//	string    "gssapi-with-mic"
	//
	// See RFC 2743 section 2.3.1 and RFC 4462 3.5.

	// TODO: Implement
	// conf.Logger.Errorf("%s %s GSSAPI GetMIC() with MIC %s", gac.Addr, gac.TName, hex.EncodeToString(micField))
	return nil, nil
}

func (gac *gssapiClient) DeleteSecContext() error {
	// Whenever possible, it should be possible for
	// DeleteSecContext() calls to be successfully processed even
	// if other calls cannot succeed, thereby enabling context-related
	// resources to be released.
	// In addition to deleting established security contexts,
	// gss_delete_sec_context must also be able to delete "half-built"
	// security contexts resulting from an incomplete sequence of
	// InitSecContext()/AcceptSecContext() calls.
	// See RFC 2743 section 2.2.3.

	// TODO: Implement
	// conf.Logger.Debugf("%s %s GSSAPI DeleteSecContext()", gac.Addr, gac.TName)
	return nil
}

const checkGSSAPIAny = "gssapi-any"

func sshCheckGSSAPIAny(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	target := addr
	gac := NewGSSAPIClient(addr, checkGSSAPIAny)
	return sshCheckGSSAPIHelper(addr, checkGSSAPIAny, conf, options, root, gac, target)
}

func initGSSAPIChecks() {
	registerCheck(checkGSSAPIAny, "gssapi", false, true)
}
