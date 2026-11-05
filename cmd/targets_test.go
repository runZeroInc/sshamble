package cmd

import (
	"slices"
	"testing"
)

func TestParseTargetsCIDR(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{"10.0.0.0/30", []string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"}},
		{"admin@10.0.0.0/31", []string{"admin@10.0.0.0", "admin@10.0.0.1"}},
		{"10.0.0.5", []string{"10.0.0.5"}},
	}
	for _, tc := range cases {
		got, err := parseTargets(tc.input)
		if err != nil {
			t.Fatalf("parseTargets(%q) returned error: %v", tc.input, err)
		}
		slices.Sort(got)
		if !slices.Equal(got, tc.want) {
			t.Errorf("parseTargets(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}
