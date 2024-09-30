package auth

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/runZeroInc/excrypto/x/crypto/ssh"
)

type PubKeyEnt struct {
	Algo     string
	Key      string
	PubKey   ssh.PublicKey
	Comments string
}

type PubKeyFile struct {
	path string
	fd   *os.File
	m    sync.Mutex
	scan *bufio.Scanner
	logr *logrus.Logger
}

func NewPubKeyFile(path string, logr *logrus.Logger) *PubKeyFile {
	return &PubKeyFile{path: path, logr: logr}
}

func (f *PubKeyFile) Open() error {
	f.Close()

	f.m.Lock()
	defer f.m.Unlock()

	fd, err := os.Open(f.path)
	if err != nil {
		return err
	}
	f.fd = fd

	scan := bufio.NewScanner(f.fd)
	buff := make([]byte, MaxPubKeyLine)
	scan.Buffer(buff, MaxPubKeyLine)
	f.scan = scan

	return nil
}

func (f *PubKeyFile) Close() {
	f.m.Lock()
	defer f.m.Unlock()
	if f.fd != nil {
		f.fd.Close()
		f.fd = nil
	}
}

func (f *PubKeyFile) Read(cnt int) ([]*PubKeyEnt, error) {
	res := []*PubKeyEnt{}
	f.m.Lock()
	defer f.m.Unlock()
	if f.fd == nil {
		return res, fmt.Errorf("no open file")
	}

	for f.scan.Scan() {
		bits := strings.Fields(strings.TrimSpace(f.scan.Text()))
		if len(bits) < 2 {
			f.logr.Errorf("bad pubkey line: %v", bits)
			continue
		}

		raw, err := base64.StdEncoding.DecodeString(bits[1])
		if err != nil {
			f.logr.Errorf("bad pubkey line: %v: %s", bits, err)
			continue
		}

		pubKey, err := ssh.ParsePublicKey(raw)
		if err != nil {
			f.logr.Errorf("bad pubkey line: %v: %s", bits, err)
			continue
		}

		var comments string
		if len(bits) > 2 {
			comments = strings.Join(bits[2:], " ")
		}
		res = append(res, &PubKeyEnt{
			Algo:     pubKey.Type(),
			Key:      PubKeyToString(pubKey),
			PubKey:   pubKey,
			Comments: comments,
		})
		if len(res) == cnt {
			return res, nil
		}
	}
	return res, nil
}

func PubKeyToString(pub ssh.PublicKey) string {
	return pub.Type() + " " + base64.StdEncoding.EncodeToString(pub.Marshal())
}
