package cmd

import (
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/runZeroInc/excrypto/x/crypto/ssh"
	"github.com/runZeroInc/sshamble/auth"
)

const checkPubkeyAny = "pubkey-any"

func sshCheckPubKeyAny(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkPubkeyAny
	if !conf.IsCheckEnabled(tname) {
		return nil
	}

	testKeys := []ssh.Signer{}
	if root.SupportsPubKeyType("ssh-rsa") {
		testKeys = append(testKeys, conf.TestKeyRSA2048, conf.TestKeyRSA4096, conf.TestKeyRSA1024)
	}
	if root.SupportsPubKeyType("ssh-ed25519") {
		testKeys = append(testKeys, conf.TestKeyED25519)
	}

	// No compatible test keys for this target
	if len(testKeys) == 0 {
		return nil
	}

	conf.Logger.Debugf("%s %s is running with %d keys", addr, tname, len(testKeys))

	// Build "half-auth" signers for our test keys
	testHalfKeys := []ssh.Signer{}
	for _, tk := range testKeys {
		testHalfKeys = append(testHalfKeys, auth.HalfSignerFromPubkey(tk.PublicKey()))
	}

	pubAccepted := map[string]string{}
	pubAcceptedTypes := map[string]struct{}{}

	cnt := 0
	for _, tk := range testHalfKeys {
		tk := tk
		kt := tk.PublicKey().Type()
		cnt++
		res := auth.SSHAuth(addr, options.WithStopStage("auth"), auth.SSHAuthHandlerSingle(ssh.AuthMethod(
			ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
				return []ssh.Signer{tk}, nil
			}),
		)))
		if res.Stage != "kex" && res.Stage != "ssh-userauth" && res.Stage != "auth" { // auth should be impossible to reach, but cover it
			conf.Logger.Infof("%s %s pubkey rejected at stage %s with half-auth key %d (%s): %v", addr, tname, res.Stage, cnt, kt, res.Error)
			// Consider ending early for connection errors and similar
			continue
		}
		half, ok := tk.(*auth.HalfSigner)
		if !ok {
			conf.Logger.Errorf("%s %s does not have a half-auth signer for key %d (%s): %#v", addr, tname, cnt, kt, tk)
			continue
		}
		if half.Accepted {
			conf.Logger.Infof("%s %s accepted half-auth with key %d (%s)", addr, tname, cnt, kt)
			pubAccepted[base64.StdEncoding.EncodeToString(half.PubKey.Marshal())] = kt
			pubAcceptedTypes[kt] = struct{}{}
			root.PubKeyAnyHalfKey = half
			break
		}
		conf.Logger.Debugf("%s %s rejected half-auth with key %d (%s)", addr, tname, cnt, kt)
	}

	// No key types accepted
	if len(pubAccepted) == 0 {
		return nil
	}

	// Test to see if any full key is accepted
	cnt = 0
	for _, tk := range testKeys {
		tk := tk
		if _, ok := pubAccepted[base64.StdEncoding.EncodeToString(tk.PublicKey().Marshal())]; !ok {
			// Skip full key tests where the half key was not accepted
			continue
		}
		kt := tk.PublicKey().Type()

		cnt++

		am := ssh.AuthMethod(ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
			return []ssh.Signer{tk}, nil
		}))

		res := auth.SSHAuth(addr, options, auth.SSHAuthHandlerSingle(am))
		if res.Stage != "session" {
			conf.Logger.Debugf("%s %s rejected full auth with key %d (%s) in stage %s: %v", addr, tname, cnt, kt, res.Stage, res.Error)
			continue
		}
		conf.Logger.Warnf("%s %s accepted full auth with key %d (%s)", addr, tname, cnt, kt)
		root.PubKeyAnyFullKey = tk

		res.SessionMethod = tname
		root.SessionMethod = tname
		root.SessionOutput = res.SessionOutput
		root.SessionSecret = auth.PubKeyToString(tk.PublicKey())
		root.ExitStatus = res.ExitStatus
		root.SessionAuth = am

		return res
	}
	return nil
}

const checkPubkeyHunt = "pubkey-hunt"

func sshCheckPubKeyHunt(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkPubkeyHunt
	if !conf.IsCheckEnabled(tname) {
		return nil
	}

	hf := auth.NewPubKeyFile(gPubKeyHuntFile, conf.Logger)
	if err := hf.Open(); err != nil {
		conf.Logger.Errorf("%s %s failed to open key file %s: %v", addr, tname, gPubKeyHuntFile, err)
		return nil
	}
	defer hf.Close()

	conf.Logger.Debugf("%s %s is running", addr, tname)

	stime := time.Now()
	perSlice := int(gPubKeyHuntConnLimit)

RestartBatches:
	cnt := 0
	batch := 0
	lastCnt := 0

	logStatus := func() {
		elapsed := time.Since(stime)
		kps := float64(cnt) / (float64(elapsed) / float64(time.Second))
		conf.Logger.Infof("%s %s completed %d keys in %d batches for %s after %s (%.2f/s)", addr, tname, cnt, batch, options.Username, elapsed, kps)
		lastCnt = cnt
	}

	origTimeout := options.Timeout

	for {

		testKeys, err := hf.Read(perSlice)
		if err != nil {
			conf.Logger.Infof("%s %s failed to read pubkeys: %s", addr, tname, err)
			return nil
		}
		batchKeys := make([]ssh.Signer, 0, len(testKeys))
		for _, k := range testKeys {
			if !root.SupportsPubKeyType(k.Algo) {
				continue
			}
			batchKeys = append(batchKeys, auth.HalfSignerFromPubkey(k.PubKey))
		}

		if len(batchKeys) == 0 {
			break
		}

		// conf.Logger.Infof("%s %s is testing %d keys in batch %d [%v]", addr, tname, len(batchKeys), batch, batchKeys[0])

		// Increase timeouts by one second for every 10k keys. This avoids false negatives
		// when using very large key batches on slow servers.
		extraSeconds := len(batchKeys) / 10000
		if extraSeconds > 0 {
			options = options.WithTimeout(origTimeout + (time.Second * time.Duration(extraSeconds)))
			conf.Logger.Tracef("%s %s increased timeout from %ds to %ds for large batch size %d",
				addr, tname, origTimeout/time.Second, options.Timeout/time.Second, len(batchKeys),
			)
		}

		res := auth.SSHAuth(addr, options.WithStopStage("auth"), auth.SSHAuthHandlerSingle(ssh.AuthMethod(
			ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
				return batchKeys, nil
			}),
		)))

		// Look for a disconnect message, reduce batch size, and try again
		// ("ssh: disconnect, reason %d: %s", d.Reason, d.Message)
		if strings.Contains(res.Error, "ssh: disconnect, reason 2:") && perSlice > 1 {
			perSlice = perSlice / 2

			// Optimize for the OpenSSH default limit of 5
			if perSlice < 15 && perSlice > 5 {
				perSlice = 5
			}

			conf.Logger.Debugf("%s %s failed with stage %s for hunted key batch %d: %v (reducing batch size to %d)", addr, tname, res.Stage, batch, res.Error, perSlice)

			// Reopen the hunt key file for the new batch size
			if err := hf.Open(); err != nil {
				conf.Logger.Errorf("%s %s failed to open key file %s: %v", addr, tname, gPubKeyHuntFile, err)
				return nil
			}
			// The initial `defer hf.Close()` is still sufficient
			goto RestartBatches
		}

		if res.Stage != "kex" && res.Stage != "ssh-userauth" && res.Stage != "auth" { // auth should be impossible to reach, but cover it
			conf.Logger.Errorf("%s %s failed with stage %s for hunted key batch %d: %v", addr, tname, res.Stage, batch, res.Error)
			// Consider ending early for connection errors and similar
			continue
		}

		if res.Error != "" && !(strings.Contains(res.Error, "authentication failed: 0") ||
			strings.Contains(res.Error, "half-auth")) {
			// Report errors here as these can be triggered by EOF and timeouts and will lead to false negatives
			conf.Logger.Errorf("%s %s failed with stage %s for hunted key batch %d: %v", addr, tname, res.Stage, batch, res.Error)
		}

		failed := 0
		batch++
		for _, tk := range batchKeys {
			cnt++
			half, ok := tk.(*auth.HalfSigner)
			if !ok {
				conf.Logger.Errorf("%s %s does not have a half-auth signer for hunted key batch %d", addr, tname, batch)
				continue
			}
			if half.Accepted {
				logStatus()
				found := auth.PubKeyToString(half.PublicKey()) + " " + options.Username
				conf.Logger.Warnf("%s %s accepted hunted half-auth for %s with key %s", addr, tname, options.Username, found)
				root.PubKeyHuntResults = append(root.PubKeyHuntResults, found)
				return res
			}
			failed++
		}
		conf.Logger.Tracef("%s %s rejected %d hunted half-auth keys in batch %d", addr, tname, failed, batch)
		if cnt-lastCnt > 100 {
			logStatus()
		}
	}

	if lastCnt != cnt {
		logStatus()
	}

	return nil
}

const checkPubkeyBulkHalf = "pubkey-bulkhalf"

func sshCheckPubKeyBulkHalf(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkPubkeyBulkHalf
	if !conf.IsCheckEnabled(tname) {
		return nil
	}

	testKeys := []ssh.Signer{}
	if root.SupportsPubKeyType("ssh-rsa") {
		testKeys = append(testKeys, conf.TestKeyRSA2048, conf.TestKeyRSA4096, conf.TestKeyRSA1024)
	}
	if root.SupportsPubKeyType("ssh-ed25519") {
		testKeys = append(testKeys, conf.TestKeyED25519)
	}

	// No compatible test keys for this target
	if len(testKeys) == 0 {
		return nil
	}

	conf.Logger.Debugf("%s %s is running with %d source keys and %d attempts", addr, tname, len(testKeys), gPubKeyBulkLimit)

	// Build "half-auth" signers for our test keys
	testHalfKeys := []ssh.Signer{}
	for _, tk := range testKeys {
		testHalfKeys = append(testHalfKeys, auth.HalfSignerFromPubkey(tk.PublicKey()))
	}

	bulkHandler := func(uac *ssh.UnauthClientConn, extensions map[string][]byte, res *auth.AuthResult) error {
		for i := range int(gPubKeyBulkLimit) {
			tk := testHalfKeys[i%len(testHalfKeys)]
			authMethod := ssh.AuthMethod(
				ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
					return []ssh.Signer{tk}, nil
				}))
			ares, methods, err := uac.Authenticate(authMethod, extensions)
			res.Result = ares.String()
			res.Methods = methods
			for k, vb := range extensions {
				res.Extensions[k] = string(vb)
			}
			if err != nil && (err == io.EOF ||
				strings.Contains(err.Error(), "ssh: disconnect")) {
				root.PubKeyHalfAuthLimit = i
				conf.Logger.Infof("%s %s completed on iteration %d with result %s (%v)", addr, tname, i, ares.String(), err)
				return err
			} else if err != nil {
				conf.Logger.Infof("%s %s completed on iteration %d with result %s (%v)", addr, tname, i, ares.String(), err)
			} else {
				conf.Logger.Debugf("%s %s iteration %d has result %s", addr, tname, i, ares.String())
			}
		}
		// No limits on pubkey half auth
		root.PubKeyHalfAuthLimit = -1
		return fmt.Errorf("completed")
	}

	res := auth.SSHAuth(addr, options.WithStopStage("auth"), bulkHandler)
	return res
}

const checkUserKey = "pubkey-user"

func sshCheckUserKey(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkUserKey
	if !conf.IsCheckEnabled(tname) {
		return nil
	}

	if options.PrivateKey == nil {
		return nil
	}

	conf.Logger.Debugf("%s %s is running for user %s", addr, tname, options.Username)

	am := ssh.AuthMethod(ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
		return []ssh.Signer{options.PrivateKey}, nil
	}))

	res := auth.SSHAuth(addr, options, auth.SSHAuthHandlerSingle(am))

	if res.Stage != "session" {
		conf.Logger.Infof("%s %s rejected user key in stage %s: %v", addr, tname, res.Stage, res.Error)
		return nil
	}
	conf.Logger.Warnf("%s %s opened session with user key", addr, tname)
	root.PubKeyAnyFullKey = options.PrivateKey

	res.SessionMethod = tname
	root.SessionMethod = tname
	root.SessionOutput = res.SessionOutput
	root.SessionSecret = auth.PubKeyToString(options.PrivateKey.PublicKey())
	root.ExitStatus = res.ExitStatus
	root.SessionAuth = am
	return res
}

func initPubkeyChecks() {
	registerCheck(checkPubkeyAny, "pubkey", false, true)
	registerCheck(checkPubkeyHunt, "pubkey", false, true)
	registerCheck(checkPubkeyBulkHalf, "pubkey", false, true)
	registerCheck(checkUserKey, "pubkey", false, true)

	// TODO: Add check to send pubkey with valid signature without waiting for PK_OK
}
