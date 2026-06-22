package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/extract/lowering"
)

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

func TestRustUnsafeImplMetadataIncludesSendBoundOnSyncImpl(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lib.rs")
	src := []byte(`
pub struct QueueSender<T> {
    value: T,
}

unsafe impl<T: Send> Sync for QueueSender<T> {}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := ExtractRust([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.rust.unsafe_impl" {
			continue
		}
		tokens := n.Prop("str_args")
		if strings.Contains(tokens, "trait:Sync") && strings.Contains(tokens, "bound:Send") {
			return
		}
	}
	t.Fatalf("unsafe Sync impl metadata did not include bound:Send; nodes=%#v", nodes)
}
