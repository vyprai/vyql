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

func TestRustUnsafeImplSpecificMissingBoundObservations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lib.rs")
	src := []byte(`
pub struct Boxed<T> {
    value: *mut T,
}

unsafe impl<T: Sized> Sync for Boxed<T> {}
unsafe impl<T: Sized> Send for Boxed<T> {}
unsafe impl<T: Send> Sync for VecBox<T> {}
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
	if !hasRustAnalysisNode(nodes, "analysis.rust.unsafe_sync_impl_missing_bound") {
		t.Fatalf("missing unsafe Sync observation; nodes=%#v", nodes)
	}
	if !hasRustAnalysisNode(nodes, "analysis.rust.unsafe_send_impl_missing_bound") {
		t.Fatalf("missing unsafe Send observation; nodes=%#v", nodes)
	}
	if countRustAnalysisNodes(nodes, "analysis.rust.unsafe_sync_impl_missing_bound") != 1 {
		t.Fatalf("bounded Sync impl should not emit missing-bound observation; nodes=%#v", nodes)
	}
}

func TestRustFfiEnumLayoutSpecificObservation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lib.rs")
	src := []byte(`
#[repr(C)]
pub enum WireKind {
    A = 0,
    B = 1,
}

#[repr(u32)]
pub enum StableKind {
    A = 0,
    B = 1,
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
	if countRustAnalysisNodes(nodes, "analysis.rust.ffi_enum_layout_risk") != 1 {
		t.Fatalf("expected only repr(C) enum to emit FFI layout observation; nodes=%#v", nodes)
	}
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

func TestRustFunctionContextIncludesModexpBitLengthArithmetic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lib.rs")
	src := []byte(`
fn calculate_iteration_count(exp_length: u64, exponent: &BigUint) -> u64 {
    let mut iteration_count = 0;
    if exp_length > 32 {
        let bytes: [u8; 32] = [0xFF; 32];
        let max_256_bit_uint = BigUint::from_bytes_be(&bytes);
        iteration_count =
            (8 * (exp_length - 32)) + ((exponent.bitand(max_256_bit_uint)).bits() - 1);
    }
    iteration_count
}

fn fixed_calculate_iteration_count(exp_length: u64, exponent: &BigUint) -> u64 {
    let mut iteration_count = 0;
    if exp_length > 32 {
        let bytes: [u8; 32] = [0xFF; 32];
        let max_256_bit_uint = BigUint::from_bytes_be(&bytes);
        iteration_count =
            (8 * (exp_length - 32)) + exponent.bitand(max_256_bit_uint).bits() - 1;
    }
    iteration_count
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
	vuln := rustFunctionContextArgs(nodes, "calculate_iteration_count")
	for _, want := range []string{
		"call_path:exponent.bitand",
		"((exponent.bitand(max_256_bit_uint)).bits()-1)",
	} {
		if !strings.Contains(vuln, want) {
			t.Fatalf("rust modexp vulnerable function context missing %q; context=%q", want, vuln)
		}
	}
	fixed := rustFunctionContextArgs(nodes, "fixed_calculate_iteration_count")
	if !strings.Contains(fixed, "(8*(exp_length-32))+exponent.bitand(max_256_bit_uint).bits()-1") {
		t.Fatalf("rust modexp fixed function context missing reordered subtraction; context=%q", fixed)
	}
	if strings.Contains(fixed, "((exponent.bitand(max_256_bit_uint)).bits()-1)") {
		t.Fatalf("fixed modexp context should not contain parenthesized bits-minus-one term; context=%q", fixed)
	}
}

func TestRustSerdeStructFieldMetadataIncludesDependencyMapValidationTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.rs")
	src := []byte(`
use serde::{Deserialize, Serialize};

type Dependencies = std::collections::HashMap<String, String>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageConfig {
    #[serde(default, serialize_with = "ordered_map")]
    pub dependencies: Dependencies,
    #[serde(
        default,
        alias = "dev-dependencies",
        serialize_with = "ordered_map",
        deserialize_with = "dependencies_map::deserialize"
    )]
    pub dev_dependencies: Dependencies,
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
	var deps, devDeps string
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.rust.serde_field" {
			continue
		}
		args := n.Prop("str_args")
		switch {
		case strings.Contains(args, "field:dependencies"):
			deps = args
		case strings.Contains(args, "field:dev_dependencies"):
			devDeps = args
		}
	}
	for _, want := range []string{
		"struct_name:PackageConfig",
		"derive:Deserialize",
		"field:dependencies",
		"field_type:Dependencies",
		"serde_attr:default",
		"serde_attr:serialize_with",
		"serde_serialize_with:ordered_map",
		"semantic:dependency_map",
	} {
		if !strings.Contains(deps, want) {
			t.Fatalf("serde dependency field metadata missing %q; context=%q", want, deps)
		}
	}
	if strings.Contains(deps, "serde_attr:deserialize_with") {
		t.Fatalf("vulnerable dependency field should not have deserialize_with token; context=%q", deps)
	}
	if countRustAnalysisNodes(nodes, "analysis.rust.unvalidated_dependency_map_key_deserialization") != 1 {
		t.Fatalf("expected exactly one unvalidated dependency-map observation; nodes=%#v", nodes)
	}
	for _, want := range []string{
		"field:dev_dependencies",
		"serde_alias:dev-dependencies",
		"serde_attr:deserialize_with",
		"serde_deserialize_with:dependencies_map::deserialize",
		"semantic:dependency_map",
	} {
		if !strings.Contains(devDeps, want) {
			t.Fatalf("serde dev dependency field metadata missing %q; context=%q", want, devDeps)
		}
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

func hasRustAnalysisNode(nodes []usg.Node, path string) bool {
	return countRustAnalysisNodes(nodes, path) > 0
}

func countRustAnalysisNodes(nodes []usg.Node, path string) int {
	count := 0
	for _, n := range nodes {
		if n.Type == "code.Call" && n.Prop("callee_path") == path {
			count++
		}
	}
	return count
}
