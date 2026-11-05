package cmd

import (
	"strings"
	"testing"

	"github.com/runZeroInc/excrypto/x/crypto/ssh"
)

func TestSSHHolePasswords(t *testing.T) {
	pws := sshholePasswords()
	want := append([]int{sshholeControlLen}, sshholeTriggerLens...)
	if len(pws) != len(want) {
		t.Fatalf("sshholePasswords() returned %d passwords, want %d", len(pws), len(want))
	}
	for i, pw := range pws {
		if len(pw) != want[i] {
			t.Errorf("password %d is %d bytes, want %d", i, len(pw), want[i])
		}
		if strings.ContainsRune(pw, 0) {
			t.Errorf("password %d contains a NUL byte", i)
		}
	}
	if pws[1] == sshholePasswords()[1] {
		t.Errorf("trigger passwords repeat across calls")
	}
}

func TestSSHHoleClassify(t *testing.T) {
	fail := ssh.AuthResultFailure
	ok := ssh.AuthResultSuccess
	partial := ssh.AuthResultPartialSuccess
	cases := []struct {
		name    string
		results []ssh.ExpAuthResult
		want    int
	}{
		{"no attempts", nil, -1},
		{"control accepted", []ssh.ExpAuthResult{ok}, -1},
		{"control partial", []ssh.ExpAuthResult{partial}, -1},
		{"first trigger accepted", []ssh.ExpAuthResult{fail, ok}, 1},
		{"first trigger partial", []ssh.ExpAuthResult{fail, partial}, 1},
		{"second trigger accepted", []ssh.ExpAuthResult{fail, fail, ok}, 2},
		{"all rejected", []ssh.ExpAuthResult{fail, fail, fail}, -1},
		{"disconnected after control", []ssh.ExpAuthResult{fail}, -1},
		{"disconnected after first trigger", []ssh.ExpAuthResult{fail, fail}, -1},
	}
	for _, tc := range cases {
		got, reason := sshholeClassify(tc.results)
		if got != tc.want {
			t.Errorf("%s: sshholeClassify() = %d (%s), want %d", tc.name, got, reason, tc.want)
		}
		if got < 0 && reason == "" {
			t.Errorf("%s: no reason given for a negative result", tc.name)
		}
	}
}
