package auth

import (
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
	for _, v := range r.Methods {
		if v == t {
			return true
		}
	}
	return false
}

func (r *AuthResult) SupportsHostKey(t string) bool {
	if r.KexInit == nil {
		return false
	}
	for _, v := range r.KexInit.ServerHostKeyAlgos {
		if v == t {
			return true
		}
	}
	return false
}

func (r *AuthResult) SupportsPubKeyType(t string) bool {
	// Example: ssh-ed25519,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-256,rsa-sha2-512,ssh-rsa,ssh-dss
	okTypes, ok := r.Extensions["server-sig-algs"]
	if !ok {
		// Assume all types are supported unless the server
		// has told us otherwise via the extension.
		return true
	}
	for _, kt := range strings.Split(okTypes, ",") {
		kt = strings.TrimSpace(kt)
		if strings.EqualFold(kt, t) {
			return true
		}
	}
	return false
}

func (r *AuthResult) AddVuln(v VulnResult) {
	r.Vulns = append(r.Vulns, v)
}
