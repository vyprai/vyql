package treesitter

import "testing"

func TestRustStringValuePreservesLiteralPayload(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{`"plain literal"`, `"plain literal"`},
		{`b"byte literal"`, `"byte literal"`},
		{`r#"raw literal"#`, `"raw literal"`},
		{`br##"raw byte literal"##`, `"raw byte literal"`},
		{`"line\nbreak"`, `"linenbreak"`},
	}
	for _, c := range cases {
		if got := rustStringValue(c.raw); got != c.want {
			t.Fatalf("rustStringValue(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}
