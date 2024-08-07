package cmd

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestProcessSend(t *testing.T) {
	testCases := []struct {
		Input    string
		Expected []byte
	}{
		{"ABCDEFG", []byte("ABCDEFG")},
		{"ABCDEFG\x00", []byte("ABCDEFG\x00")},
		{"\\x00ABCDEFG\x00", []byte("\x00ABCDEFG\x00")},
		{"\\x00ABCDEFG\x00\\x0", []byte("\x00ABCDEFG\x00\\x0")},
		{"\\x00ABCDEFG\x00\\x01", []byte("\x00ABCDEFG\x00\x01")},
		{"\\r\\nABC\\tDEFG", []byte("\r\nABC\tDEFG")},
	}
	for _, tc := range testCases {
		got := processSendBytes(tc.Input)
		if !bytes.Equal(tc.Expected, got) {
			t.Errorf("got %s for %s, expected %s", hex.EncodeToString(got), tc.Input, hex.EncodeToString(tc.Expected))
		}
	}
}
