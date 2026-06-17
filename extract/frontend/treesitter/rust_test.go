package treesitter

import "testing"

func TestRustStringValuePreservesLiteralPayload(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{`"0000000000000000"`, `"0000000000000000"`},
		{`b"0000000000000000"`, `"0000000000000000"`},
		{`r#"http://example.com"#`, `"http://example.com"`},
		{`br##"/tmp/vyql-cache"##`, `"/tmp/vyql-cache"`},
		{`"line\nbreak"`, `"linenbreak"`},
	}
	for _, c := range cases {
		if got := rustStringValue(c.raw); got != c.want {
			t.Fatalf("rustStringValue(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}
