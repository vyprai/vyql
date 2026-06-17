package treesitter

import "testing"

func TestCBoolValueNormalizesObjCAndCBoolLiterals(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"YES", "true", true},
		{"TRUE", "true", true},
		{"true", "true", true},
		{"NO", "false", true},
		{"FALSE", "false", true},
		{"false", "false", true},
		{"manager", "", false},
	}
	for _, c := range cases {
		got, ok := cBoolValue(c.in)
		if got != c.want || ok != c.ok {
			t.Fatalf("cBoolValue(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}
