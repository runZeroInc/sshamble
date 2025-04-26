package auth

import (
	"net"
	"time"
	"unicode/utf8"

	"github.com/sirupsen/logrus"

	"github.com/runZeroInc/excrypto/x/crypto/ssh"
)

type (
	SessionHandler  func(net.Conn, *ssh.Client, *ssh.Session, *AuthResult) error
	PostAuthHandler func(net.Conn, *ssh.UnauthClientConn, *AuthResult) error
)

type Options struct {
	Host            string
	Port            int
	Timeout         time.Duration
	Usernames       string
	Username        string
	StopStage       string
	HostKeyAlgs     []string
	IgnoreAuthError bool
	PrivateKey      ssh.Signer
	Retries         uint
	ClientVersion   string
	Logger          *logrus.Logger
	SessionPoke     string

	skipStages             []string
	sessionHandler         SessionHandler
	postAuthHandler        PostAuthHandler
	ignoreChannelOpenReply bool
}

func (o *Options) WithRetries(limit uint) *Options {
	n := *o
	n.Retries = limit
	return &n
}

func (o *Options) WithStopStage(stage string) *Options {
	n := *o
	n.StopStage = stage
	return &n
}

func (o *Options) WithSkipStages(stages ...string) *Options {
	n := *o
	n.skipStages = stages
	return &n
}

func (o *Options) WithIgnoreChannelOpenReply(v bool) *Options {
	n := *o
	n.ignoreChannelOpenReply = v
	return &n
}

func (o *Options) WithTimeout(d time.Duration) *Options {
	n := *o
	n.Timeout = d
	return &n
}

func (o *Options) WithIgnoreAuthError() *Options {
	n := *o
	n.IgnoreAuthError = true
	return &n
}

func (o *Options) WithHostKeyAlgs(algs []string) *Options {
	n := *o
	n.HostKeyAlgs = algs
	return &n
}

func (o *Options) WithPrivateKey(key ssh.Signer) *Options {
	n := *o
	n.PrivateKey = key
	return &n
}

func (o *Options) WithUsername(u string) *Options {
	n := *o
	n.Username = u
	return &n
}

func (o *Options) WithClientVersion(v string) *Options {
	n := *o
	n.ClientVersion = v
	return &n
}

func (o *Options) WithSessionPoke(v string) *Options {
	n := *o
	n.SessionPoke = v
	return &n
}

func (o *Options) WithSessionHandler(handler SessionHandler) *Options {
	n := *o
	n.sessionHandler = handler
	return &n
}

func (o *Options) WithPostAuthHandler(handler PostAuthHandler) *Options {
	n := *o
	n.postAuthHandler = handler
	return &n
}

func (o *Options) SkipStage(stage string) bool {
	for _, skipStage := range o.skipStages {
		if stage == skipStage {
			return true
		}
	}
	return false
}

func ReverseString(s string) string {
	size := len(s)
	buf := make([]byte, size)
	for start := 0; start < size; {
		r, n := utf8.DecodeRuneInString(s[start:])
		start += n
		utf8.EncodeRune(buf[size-start:], r)
	}
	return string(buf)
}
