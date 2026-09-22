package treesitter_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
)

// rustSignatureEventTokens returns the str_args of the analysis.rust.signature
// event lowered for the named function, and rustContextEventTokens the
// analysis.function.context one, so a test can pin what each node family
// carries separately.
func rustEventTokens(t *testing.T, src, functionName, calleePath string) []string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "tower.rs")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractRust([]string{path}, dir)
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
		if n.Type != "code.Call" || n.Prop("callee_path") != calleePath {
			continue
		}
		tokens := strings.Split(n.Prop("str_args"), "\x00")
		if slices.Contains(tokens, "name="+functionName) {
			return tokens
		}
	}
	t.Fatalf("no %s event for %s", calleePath, functionName)
	return nil
}

func rustSignatureTokens(t *testing.T, src, functionName string) []string {
	return rustEventTokens(t, src, functionName, "analysis.rust.signature")
}

func rustContextTokens(t *testing.T, src, functionName string) []string {
	return rustEventTokens(t, src, functionName, "analysis.function.context")
}

// The Rust frontend records no signature or impl-header facts: a function's
// return type, its parameter and receiver types, and which trait an impl block
// implements were absent from the graph, so a weakness whose vulnerable and
// fixed spellings differ only in types -- items typed by the impl's lifetime
// instead of the receiver borrow, an owning Iterator declaration over a lending
// accessor -- could not be separated at the data layer, because the two bodies
// read the same. These tests pin the declaration-level facts the
// analysis.rust.signature event carries.

// The two Iterator spellings the gap names: the lending one types its items by
// the impl's lifetime ('a off the impl header, not a borrow of the receiver),
// the owning one returns values the iterator owns. Every difference between
// them lives in the signature and the impl header, none in the body.
func TestRustSignatureFactsSeparateLendingAndOwningImpls(t *testing.T) {
	lending := `
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Iterator for Reader<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        self.data.first().copied()
    }
}
`
	owning := `
pub struct Reader {
    data: Vec<u8>,
}

impl Iterator for Reader {
    fn next(&mut self) -> Option<u8> {
        self.data.pop()
    }
}
`
	tokens := rustSignatureTokens(t, lending, "next")
	for _, want := range []string{
		"lang=rust",
		"name=next",
		"return_type:Option<&'a[u8]>",
		"receiver:&mutself",
		"impl_trait:Iterator",
		"impl_type:Reader<'a>",
	} {
		if !slices.Contains(tokens, want) {
			t.Fatalf("lending fact %q missing from next's signature event; tokens=%q", want, tokens)
		}
	}

	tokens = rustSignatureTokens(t, owning, "next")
	for _, want := range []string{
		"return_type:Option<u8>",
		"receiver:&mutself",
		"impl_trait:Iterator",
		"impl_type:Reader",
	} {
		if !slices.Contains(tokens, want) {
			t.Fatalf("owning fact %q missing from next's signature event; tokens=%q", want, tokens)
		}
	}
	// The owning spelling must not carry the lending one's facts: the
	// discrimination is exactly that no lifetime reaches the items.
	for _, stale := range []string{"return_type:Option<&'a[u8]>", "impl_type:Reader<'a>"} {
		if slices.Contains(tokens, stale) {
			t.Fatalf("owning spelling carried the lending fact %q; tokens=%q", stale, tokens)
		}
	}
}

// A free function's declaration: the return type after the arrow, one
// name/index/type triple per value parameter, and no impl facts -- it sits in
// no impl block.
func TestRustSignatureFactsRecordFreeFunctionParameters(t *testing.T) {
	src := `
fn translate(text: &str, mut budget: usize) -> String {
    String::new()
}
`
	tokens := rustSignatureTokens(t, src, "translate")
	for _, want := range []string{
		"return_type:String",
		"param_name:text",
		"param_index:0",
		"param_type:&str",
		"param_name:budget",
		"param_index:1",
		"param_type:usize",
	} {
		if !slices.Contains(tokens, want) {
			t.Fatalf("signature fact %q missing from translate's signature event; tokens=%q", want, tokens)
		}
	}
	for _, tok := range tokens {
		if strings.HasPrefix(tok, "impl_type:") || strings.HasPrefix(tok, "impl_trait:") || strings.HasPrefix(tok, "receiver:") {
			t.Fatalf("free function carried an impl or receiver fact %q; tokens=%q", tok, tokens)
		}
	}
}

// The receiver borrow is the other half of the discrimination: a method on
// `&self` lends, one on `self` consumes, and a typed receiver names the type it
// is pinned behind. An inherent impl (no trait) records the type and no trait.
func TestRustSignatureFactsRecordReceiverSpellings(t *testing.T) {
	src := `
pub struct Cache {
    entries: Vec<Entry>,
}

impl Cache {
    pub fn peek(&self) -> Option<&Entry> {
        self.entries.first()
    }

    pub fn drain(self) -> Vec<Entry> {
        self.entries
    }

    pub fn poke(self: std::pin::Pin<&mut Self>) {}
}
`
	tokens := rustSignatureTokens(t, src, "peek")
	for _, want := range []string{"receiver:&self", "impl_type:Cache", "return_type:Option<&Entry>"} {
		if !slices.Contains(tokens, want) {
			t.Fatalf("peek fact %q missing; tokens=%q", want, tokens)
		}
	}
	for _, tok := range tokens {
		if strings.HasPrefix(tok, "impl_trait:") {
			t.Fatalf("inherent impl recorded a trait fact %q; tokens=%q", tok, tokens)
		}
	}

	tokens = rustSignatureTokens(t, src, "drain")
	for _, want := range []string{"receiver:self", "impl_type:Cache"} {
		if !slices.Contains(tokens, want) {
			t.Fatalf("drain fact %q missing; tokens=%q", want, tokens)
		}
	}

	tokens = rustSignatureTokens(t, src, "poke")
	if !slices.Contains(tokens, "receiver:std::pin::Pin<&mutSelf>") {
		t.Fatalf("typed receiver fact missing; tokens=%q", tokens)
	}
}

// The impl header must not escape the block: a function after it, and a
// function nested inside a method's body, are plain functions and carry none.
func TestRustSignatureFactsDoNotEscapeTheImplBlock(t *testing.T) {
	src := `
pub struct Holder<T> {
    value: T,
}

impl<T: Clone> Holder<T> {
    pub fn get(&self) -> &T {
        &self.value
    }

    pub fn describe(&self) -> String {
        fn label(value: &T) -> String {
            String::new()
        }
        label(&self.value)
    }
}

fn standalone(n: u8) -> u8 {
    n
}
`
	for _, fn := range []string{"standalone", "label"} {
		tokens := rustSignatureTokens(t, src, fn)
		for _, tok := range tokens {
			if strings.HasPrefix(tok, "impl_type:") || strings.HasPrefix(tok, "impl_trait:") || strings.HasPrefix(tok, "receiver:") {
				t.Fatalf("%s carried an impl or receiver fact %q; tokens=%q", fn, tok, tokens)
			}
		}
	}
	tokens := rustSignatureTokens(t, src, "get")
	if !slices.Contains(tokens, "impl_type:Holder<T>") {
		t.Fatalf("generic impl type fact missing; tokens=%q", tokens)
	}
	for _, tok := range tokens {
		if strings.HasPrefix(tok, "impl_trait:") {
			t.Fatalf("impl without a trait recorded one (%q); tokens=%q", tok, tokens)
		}
	}
}

// The signature facts live on their own node because a Rust type is full of
// angle brackets, and shipped bindings read a bare `<` or `>` among the
// function context's tokens as "a comparison exists in this body" -- the only
// carrier that witness has. The simple-slab Index impl
// (bindings/rust/index_operator_without_bounds_check.vyql) is generic
// (`impl<T> Index<usize> for Slab<T>`), so its declaration types must not
// reach the context node and unfire the missing-bounds check.
func TestRustSignatureFactsStayOffTheFunctionContextNode(t *testing.T) {
	src := `
use std::ops::Index;

pub struct Slab<T> {
    len: usize,
    mem: *mut T,
}

impl<T> Index<usize> for Slab<T> {
    type Output = T;
    fn index(&self, index: usize) -> &Self::Output {
        unsafe { &(*(self.mem.offset(index as isize))) }
    }
}
`
	tokens := rustContextTokens(t, src, "index")
	for _, tok := range tokens {
		if strings.ContainsAny(tok, "<>") {
			t.Fatalf("function context gained an angle bracket (%q), which a shipped bounds-check negation reads as a comparison; tokens=%q", tok, tokens)
		}
	}
	// The declaration types the binding could not see are on the signature
	// event instead, including the Index trait the method implements.
	sig := rustSignatureTokens(t, src, "index")
	for _, want := range []string{"impl_trait:Index<usize>", "impl_type:Slab<T>", "receiver:&self", "param_type:usize", "return_type:&Self::Output"} {
		if !slices.Contains(sig, want) {
			t.Fatalf("signature fact %q missing; tokens=%q", want, sig)
		}
	}
}
