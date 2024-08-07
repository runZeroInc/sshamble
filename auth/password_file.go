package auth

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

const MaxPasswordLine = 32768

type PasswordFile struct {
	path string
	fd   *os.File
	m    sync.Mutex
	scan *bufio.Scanner
	logr *logrus.Logger
}

func NewPasswordFile(path string, logr *logrus.Logger) *PasswordFile {
	return &PasswordFile{path: path, logr: logr}
}

func (f *PasswordFile) Open() error {
	f.Close()

	f.m.Lock()
	defer f.m.Unlock()

	fd, err := os.Open(f.path)
	if err != nil {
		return err
	}
	f.fd = fd

	scan := bufio.NewScanner(f.fd)
	buff := make([]byte, MaxPasswordLine)
	scan.Buffer(buff, MaxPasswordLine)
	f.scan = scan

	return nil
}

func (f *PasswordFile) Close() {
	f.m.Lock()
	defer f.m.Unlock()
	if f.fd != nil {
		f.fd.Close()
		f.fd = nil
	}
}

func (f *PasswordFile) Read(cnt int) ([]string, error) {
	res := []string{}
	f.m.Lock()
	defer f.m.Unlock()
	if f.fd == nil {
		return res, fmt.Errorf("no open file")
	}

	for f.scan.Scan() {
		line := strings.TrimSpace(f.scan.Text())
		if line == "" {
			continue
		}
		res = append(res, line)
		if len(res) == cnt {
			return res, nil
		}
	}
	return res, nil
}
