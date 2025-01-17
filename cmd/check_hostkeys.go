package cmd

import (
	"encoding/base64"
	"encoding/hex"
	"strconv"

	"github.com/runZeroInc/excrypto/x/crypto/ssh"
	"github.com/runZeroInc/sshamble/auth"
	"github.com/runZeroInc/sshamble/badkeys"
)

const checkBadKeysBlocklist = "badkeys-blocklist"

func sshCheckBadKeysBlocklist(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkBadKeysBlocklist
	if !conf.IsCheckEnabled(tname) {
		return nil
	}
	if conf.BadKeyCache == nil {
		return nil
	}

	for hkt, hkv := range root.HostKeys {
		raw, err := base64.StdEncoding.DecodeString(hkv)
		if err != nil {
			continue
		}
		pk, err := ssh.ParsePublicKey(raw)
		if err != nil {
			continue
		}
		hpre, err := badkeys.PrefixFromPublicKey(pk)
		if err != nil {
			continue
		}
		bkr, err := conf.BadKeyCache.Blocklist.LookupPrefix(hpre)
		if err != nil {
			continue
		}

		if bkr.Private {
			repStr := strconv.FormatUint(uint64(bkr.RepoID), 10)
			hexPre := hex.EncodeToString(hpre)
			conf.Logger.Warnf("%s %s found compromised unpublished hostkey with repo %s and hash %s", addr, tname, repStr, hexPre)
			root.AddVuln(auth.VulnResult{
				ID:    "badkeys-private-" + repStr + "-" + hexPre,
				Ref:   "https://badkeys.info/",
				Proof: repStr + "-" + hexPre,
			})
		} else {
			conf.Logger.Warnf("%s %s found compromised hostkey: %s", addr, tname, bkr.ToURL())
			root.AddVuln(auth.VulnResult{
				ID:    "badkeys-" + bkr.RepoType + "-" + bkr.Repo + "-" + bkr.RepoPath + "-" + hkt,
				Ref:   "https://badkeys.info/",
				Proof: bkr.ToURL(),
			})
		}
	}

	return nil
}

func initHostkeyChecks() {
	registerCheck(checkBadKeysBlocklist, "hostkey", false, true)

}
