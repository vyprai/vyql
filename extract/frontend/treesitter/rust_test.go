package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/extract/lowering"
	"github.com/vyprai/vyql/usg"
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

func TestRustFunctionContextIncludesAssignmentCallAndMatchTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lib.rs")
	src := []byte(`
const DEVICE_STATUS: u64 = 20;

struct Config {
    driver_status: u8,
}

impl Config {
    fn write_common_config_byte(&mut self, offset: u64, value: u8) {
        match offset {
            DEVICE_STATUS => self.driver_status = value,
            _ => warn!("bad"),
        }
    }

    fn fixed_write_common_config_byte(&mut self, offset: u64, value: u8) {
        match offset {
            DEVICE_STATUS => self.set_device_status(value),
            _ => warn!("bad"),
        }
    }

    fn set_device_status(&mut self, status: u8) {
        self.driver_status = status;
    }
}
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
	vuln := rustFunctionContextArgs(nodes, "write_common_config_byte")
	for _, want := range []string{
		"match_arm:DEVICE_STATUS",
		"assign:self.driver_status=value",
	} {
		if !strings.Contains(vuln, want) {
			t.Fatalf("rust vulnerable function context missing %q; context=%q", want, vuln)
		}
	}
	fixed := rustFunctionContextArgs(nodes, "fixed_write_common_config_byte")
	for _, want := range []string{
		"match_arm:DEVICE_STATUS",
		"call_path:self.set_device_status",
		"call_arg:self.set_device_status:value",
	} {
		if !strings.Contains(fixed, want) {
			t.Fatalf("rust fixed function context missing %q; context=%q", want, fixed)
		}
	}
	if strings.Contains(fixed, "assign:self.driver_status=value") {
		t.Fatalf("fixed write function should not directly assign driver_status; context=%q", fixed)
	}
}

func rustFunctionContextArgs(nodes []usg.Node, name string) string {
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.function.context" {
			continue
		}
		args := n.Prop("str_args")
		if strings.Contains(args, "name="+name) {
			return args
		}
	}
	return ""
}
