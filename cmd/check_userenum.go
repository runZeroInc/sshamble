package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"gonum.org/v1/gonum/stat"

	"github.com/runZeroInc/excrypto/crypto/sha256"
	"github.com/runZeroInc/excrypto/x/crypto/ssh"
	"github.com/runZeroInc/sshamble/auth"
)

type userenumAuthTracker struct {
	Name          string
	Count         int
	Raw           []float64
	MaxTotal      int
	MaxPerSession int
}

func (t *userenumAuthTracker) AuthRepeater(authMethod ssh.AuthMethod) func(uac *ssh.UnauthClientConn, extensions map[string][]byte, res *auth.AuthResult) error {
	return func(uac *ssh.UnauthClientConn, extensions map[string][]byte, res *auth.AuthResult) error {
		for i := 0; ; i++ {
			stime := time.Now()
			_, _, err := uac.Authenticate(authMethod, extensions)
			elapsed := time.Since(stime)
			if err != nil {
				// conf.Logger.Debugf("%s disconnected at %d", t.Name, i)
				return err
			}
			t.Raw = append(t.Raw, float64(elapsed/time.Microsecond))
			t.Count++
			if t.Done() || (t.MaxPerSession > 0 && i == t.MaxPerSession) {
				// conf.Logger.Debugf("%s stopping at %d", t.Name, i)
				return nil
			}
		}
	}
}

func (t *userenumAuthTracker) Done() bool {
	return t.Count >= t.MaxTotal
}

func (t *userenumAuthTracker) Stats() map[string]float64 {
	res := map[string]float64{}

	// Quantile needs the input slice to be sorted.
	sort.Float64s(t.Raw)

	// Take the 10 lowest values for our stats
	if len(t.Raw) > 10 {
		t.Raw = t.Raw[:10]
	}

	res["min"] = t.Raw[0]
	res["avg"] = math.Floor(stat.Mean(t.Raw, nil))
	res["var"] = math.Floor(stat.Variance(t.Raw, nil))
	res["dev"] = math.Floor(math.Sqrt(res["var"]))
	res["med"] = math.Floor(stat.Quantile(0.5, stat.Empirical, t.Raw, nil))

	return res
}

func sshCheckUserAuthTimingHelper(tname string, addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult, authMethod ssh.AuthMethod) *auth.AuthResult {
	if !conf.IsCheckEnabled(tname) {
		return nil
	}

	if patIsLikelyOpenSSH.MatchString(root.Version) {
		conf.Logger.Warnf("%s %s is running with user '%s' against '%s', expect false positives",
			addr, tname, options.Username, strings.TrimPrefix(root.Version, "SSH-2.0-"),
		)
	}

	// Prevent concurrent testing of timing attacks on the same target
	userEnumHostLimiter.LockHost(addr)
	defer userEnumHostLimiter.UnlockHost(addr)

	conf.Logger.Infof("%s %s is running with user '%s' and %d tries (%d per-session)", addr, tname, options.Username, gUserEnumTestCount, gUserEnumMaxPerSessionCount)

	bogusUser := generateBogusUsername(options.Username)

	trackTarget := &userenumAuthTracker{Name: "target", MaxTotal: int(gUserEnumTestCount), MaxPerSession: int(gUserEnumMaxPerSessionCount)}
	authTarget := trackTarget.AuthRepeater(authMethod)

	trackBogus := userenumAuthTracker{Name: "bogus", MaxTotal: int(gUserEnumTestCount), MaxPerSession: int(gUserEnumMaxPerSessionCount)}
	authBogus := trackBogus.AuthRepeater(authMethod)

	optionsBogus := options.WithUsername(bogusUser)

	stime := time.Now()
	lastStatus := stime
	for {
		if trackBogus.Done() && trackTarget.Done() {
			break
		}
		if !trackTarget.Done() {
			if res := auth.SSHAuth(addr, options, authTarget); res.Stage == "init" || res.Stage == "connect" || res.Stage == "kex" {
				conf.Logger.Errorf("%s %s failed to test target user %s", addr, tname, res.Error)
				if res.Unreachable {
					return nil
				}
			}
		}
		if !trackBogus.Done() {
			if res := auth.SSHAuth(addr, optionsBogus, authBogus); res.Stage == "init" || res.Stage == "connect" || res.Stage == "kex" {
				conf.Logger.Errorf("%s %s failed to test bogus user %s", addr, tname, res.Error)
				if res.Unreachable {
					return nil
				}
			}
		}
		if time.Since(lastStatus) > (time.Second * 5) {
			conf.Logger.Infof("%s %s is testing user '%s' timing (%d/%d target, %d/%d bogus after %ds)",
				addr, tname, options.Username,
				trackTarget.Count, gUserEnumTestCount,
				trackBogus.Count, gUserEnumTestCount,
				uint(time.Since(stime)/time.Second),
			)
			lastStatus = time.Now()
		}
	}

	bogusStats := trackBogus.Stats()
	targetStats := trackTarget.Stats()

	conf.Logger.Debugf("%s %s target username '%s' has timing %v", addr, tname, options.Username, targetStats)
	conf.Logger.Debugf("%s %s  bogus username '%s' has timing %v", addr, tname, optionsBogus.Username, bogusStats)

	compStr := fmt.Sprintf("target(min=%.0f + var=%.0f) < bogus(min=%.0f)", targetStats["min"], targetStats["var"], bogusStats["min"])
	if targetStats["min"]+targetStats["var"] < bogusStats["min"] {
		conf.Logger.Warnf("%s %s username %s is likely VALID: %s", addr, tname, options.Username, compStr)
		root.AddVuln(auth.VulnResult{
			ID: tname,
			Proof: fmt.Sprintf("user '%s' target(%v) vs bogus(%v)",
				options.Username, targetStats, bogusStats,
			),
		})
	} else {
		conf.Logger.Infof("%s %s username %s could not be identified: %s", addr, tname, options.Username, compStr)
	}

	return nil
}

const checkUserAuthNoneTiming = "userenum-none-timing"

func sshCheckUserAuthNoneTiming(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkUserAuthNoneTiming
	if !conf.IsCheckEnabled(tname) {
		return nil
	}
	authMethod := ssh.None()
	return sshCheckUserAuthTimingHelper(checkUserAuthNoneTiming, addr, conf, options, root, authMethod)
}

const checkUserAuthPasswordTiming = "userenum-password-timing"

func sshCheckUserAuthPasswordTiming(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkUserAuthPasswordTiming
	if !conf.IsCheckEnabled(tname) {
		return nil
	}
	testPass := genRandomPassword()
	authMethod := ssh.AuthMethod(ssh.PasswordCallback(func() (string, error) {
		return testPass, nil
	}))
	return sshCheckUserAuthTimingHelper(checkUserAuthPasswordTiming, addr, conf, options, root, authMethod)
}

const checkUserAuthPubkeyTiming = "userenum-pubkey-timing"

func sshCheckUserAuthPubkeyTiming(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkUserAuthPubkeyTiming
	if !conf.IsCheckEnabled(tname) {
		return nil
	}

	var testKey ssh.Signer
	if root.SupportsPubKeyType("ssh-ed25519") {
		testKey = auth.HalfSignerFromPubkey(conf.TestKeyED25519.PublicKey())
	} else if root.SupportsPubKeyType("ssh-rsa") {
		testKey = auth.HalfSignerFromPubkey(conf.TestKeyRSA4096.PublicKey())
	} else {
		conf.Logger.Errorf("%s %s no test compatible test keys are available", addr, tname)
	}

	// Configure a repeated half-auth pubkey sequence to do timing analysis
	// TODO: Support additional key types
	authMethod := ssh.AuthMethod(ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
		return []ssh.Signer{testKey}, nil
	}))

	return sshCheckUserAuthTimingHelper(tname, addr, conf, options, root, authMethod)
}

func generateBogusUsername(orig string) string {
	origLen := len(orig)
	// Generate a random bogus user name with the same length as the target user
	bogusUserBytes := make([]byte, 8)
	for {
		_, _ = rand.Read(bogusUserBytes)
		bogusUserHash := sha256.Sum256(bogusUserBytes)
		bogusUserHex := hex.EncodeToString(bogusUserHash[:])
		for len(bogusUserHex) < origLen {
			bogusUserHex = bogusUserHex + bogusUserHex
		}
		res := bogusUserHex[:origLen]
		if res != orig {
			return res
		}
		// Try again to get a non-conflicting username
	}
}

type hostConcurrencyLimiter struct {
	sync.Mutex
	hosts map[string]*sync.Mutex
}

func newHostConcurrencyLimiter() *hostConcurrencyLimiter {
	return &hostConcurrencyLimiter{
		hosts: make(map[string]*sync.Mutex),
	}
}

func (limiter *hostConcurrencyLimiter) LockHost(host string) {
	limiter.Lock()
	m, ok := limiter.hosts[host]
	if !ok {
		limiter.hosts[host] = &sync.Mutex{}
		m = limiter.hosts[host]
	}
	limiter.Unlock()
	m.Lock()
}

func (limiter *hostConcurrencyLimiter) UnlockHost(host string) {
	limiter.Lock()
	m, ok := limiter.hosts[host]
	if !ok {
		limiter.Unlock()
		return
	}
	m.Unlock()
	limiter.Unlock()
}

var userEnumHostLimiter = newHostConcurrencyLimiter()

func initUserEnumChecks() {
	registerCheck(checkUserAuthNoneTiming, "userenum", false, false)
	registerCheck(checkUserAuthPasswordTiming, "userenum", false, false)
	registerCheck(checkUserAuthPubkeyTiming, "userenum", false, false)
}
