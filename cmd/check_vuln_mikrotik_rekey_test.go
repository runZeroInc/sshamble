package cmd

import "testing"

func TestMikrotikPreauthRekeyIsRouterOS(t *testing.T) {
	cases := []struct {
		banner string
		output string
		want   bool
	}{
		{"SSH-2.0-ROSSSH", "", true},
		{"SSH-2.0-ROSSSH", "version: 7.24.1 (stable)", true},
		{"SSH-2.0-OpenSSH_9.9", "platform: MikroTik", true},
		{"SSH-2.0-OpenSSH_9.9", "Linux router 6.1.0", false},
		{"SSH-2.0-OpenSSH_9.9", "", false},
	}
	for _, tc := range cases {
		if got := mikrotikPreauthRekeyIsRouterOS(tc.banner, tc.output); got != tc.want {
			t.Errorf("mikrotikPreauthRekeyIsRouterOS(%q, %q) = %v, want %v", tc.banner, tc.output, got, tc.want)
		}
	}
}

func TestMikrotikParseRouterOSVersion(t *testing.T) {
	output := `                  uptime: 1h29m12s
                  version: 7.24.1 (stable)
                  build-time: 2026-08-21 13:06:38
                  platform: MikroTik
`
	if got := mikrotikParseRouterOSVersion(output); got != "7.24.1" {
		t.Errorf("mikrotikParseRouterOSVersion() = %q, want %q", got, "7.24.1")
	}
	if got := mikrotikParseRouterOSVersion("no version here"); got != "" {
		t.Errorf("mikrotikParseRouterOSVersion() = %q, want empty", got)
	}
}
