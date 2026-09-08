package cmd

import "testing"

func TestMikrotikFD2SquashedPrompt(t *testing.T) {
	// Real 7.24.1 console transcript fragment: log lines, escapes, then the prompt
	raw := []byte("\x1b[24;1H\r\n2026-09-08 06:08:18 system,error,critical router was rebooted without proper shutdown\r\n" +
		"\x1b[6n\r[0@CHR] > ")
	squashed := mikrotikFD2Squashed(raw)
	if !mikrotikFD2PromptRe.MatchString(squashed) {
		t.Errorf("prompt not detected in squashed transcript %q", squashed)
	}
}

func TestMikrotikFD2SquashedVertical(t *testing.T) {
	// Vertically-rendered prompt (one character per line) must still match
	raw := []byte("[\r\n0\r\n@\r\nC\r\nH\r\nR\r\n]\r\n \r\n>\r\n")
	squashed := mikrotikFD2Squashed(raw)
	if !mikrotikFD2PromptRe.MatchString(squashed) {
		t.Errorf("vertical prompt not detected in squashed transcript %q", squashed)
	}
}

func TestMikrotikFD2NoPrompt(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(""),
		[]byte("login as: "),
		[]byte("\x1b[6n\x1b[6n"),
		[]byte("2026-09-08 06:08:18 system,error,critical router was rebooted\r\n"),
	} {
		if squashed := mikrotikFD2Squashed(raw); mikrotikFD2PromptRe.MatchString(squashed) {
			t.Errorf("false prompt detection in %q", squashed)
		}
	}
}
