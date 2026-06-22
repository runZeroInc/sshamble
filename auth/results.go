package auth

import (
	"slices"
	"strings"
	"time"

	"github.com/runZeroInc/excrypto/x/crypto/ssh"
)

type VulnResult struct {
	ID    string `json:"id,omitempty"`
	Proof string `json:"proof,omitempty"`
	Ref   string `json:"ref,omitempty"`
	URL   string `json:"url,omitempty"`
}

type AuthResult struct {
	Host                          string             `json:"host,omitempty"`
	Port                          int                `json:"port,omitempty"`
	User                          string             `json:"user,omitempty"`
	TS                            int64              `json:"ts,omitempty"`
	Banner                        string             `json:"banner,omitempty"`
	HostKeys                      map[string]string  `json:"hostkeys,omitempty"`
	Version                       string             `json:"version,omitempty"`
	KexInit                       *ssh.ExpKexInitMsg `json:"kex,omitempty"`
	Methods                       []string           `json:"methods,omitempty"`
	Error                         string             `json:"authNoneError,omitempty"`
	Stage                         string             `json:"authNoneStage,omitempty"`
	Result                        string             `json:"authNoneResult,omitempty"`
	Extensions                    map[string]string  `json:"extensions,omitempty"`
	Elapsed                       time.Duration      `json:"elapsed,omitempty"`
	ExitStatus                    string             `json:"sessionExitStatus,omitempty"`
	SessionOutput                 string             `json:"sessionOutput,omitempty"`
	SessionMethod                 string             `json:"sessionMethod,omitempty"`
	SessionSecret                 string             `json:"sessionSecret,omitempty"`
	PubKeyHalfAuthLimit           int                `json:"pubKeyHalfAuthLimit,omitempty"`
	PubKeyHuntResults             []string           `json:"pubKeyHuntResults,omitempty"`
	KeyboardChallengeName         string             `json:"kbdName,omitempty"`
	KeyboardChallengeInstructions string             `json:"kbdInstructions,omitempty"`
	KeyboardChallengeQuestions    string             `json:"kbdQuestions,omitempty"`
	Vulns                         []VulnResult       `json:"vulns,omitempty"`
	Unreachable                   bool               `json:"unreachable,omitempty"`

	PubKeyAnyHalfKey ssh.Signer     `json:"-"`
	PubKeyAnyFullKey ssh.Signer     `json:"-"`
	SessionAuth      ssh.AuthMethod `json:"-"`
	CachedChecks     map[string]any `json:"-"`
}

func NewAuthResult() *AuthResult {
	return &AuthResult{
		Stage:        "init",
		TS:           time.Now().Unix(),
		HostKeys:     make(map[string]string),
		Extensions:   make(map[string]string),
		CachedChecks: make(map[string]any),
	}
}

func (r *AuthResult) SupportsAuth(t string) bool {
	return slices.Contains(r.Methods, t)
}

func (r *AuthResult) SupportsHostKey(t string) bool {
	if r.KexInit == nil {
		return false
	}
	return slices.Contains(r.KexInit.ServerHostKeyAlgos, t)
}

func (r *AuthResult) SupportsPubKeyType(t string) bool {
	okTypes, ok := r.Extensions["server-sig-algs"]
	if !ok || strings.TrimSpace(okTypes) == "" {
		return true
	}
	// ssh-rsa keys are usable when the server advertises any RSA signature algo;
	// modern OpenSSH (>= 8.8) only offers rsa-sha2-256/rsa-sha2-512, not ssh-rsa.
	wanted := sigAlgosForKeyType(t)
	for kt := range strings.SplitSeq(okTypes, ",") {
		kt = strings.TrimSpace(kt)
		for _, w := range wanted {
			if strings.EqualFold(kt, w) {
				return true
			}
		}
	}
	return false
}

func sigAlgosForKeyType(t string) []string {
	if t == "ssh-rsa" {
		return []string{"ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"}
	}
	return []string{t}
}

func (r *AuthResult) AddVuln(v VulnResult) {
	r.Vulns = append(r.Vulns, v)
}
