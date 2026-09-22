package treesitter_test

import (
	"slices"
	"strings"
	"testing"
)

// The Rust frontend records no signature or impl-header facts: a function's
// return type, its parameter and receiver types, and which trait an impl block
// implements were absent from the graph, so a weakness whose vulnerable and
// fixed spellings differ only in types -- items typed by the impl's lifetime
// instead of the receiver borrow, an owning Iterator declaration over a lending
// accessor -- could not be separated at the data layer, because the two bodies
// read the same. These tests pin the declaration-level facts a binding reads
// off the function-context event.

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
	tokens := rustFunctionContextTokens(t, lending, "next")
	for _, want := range []string{
		"return_type:Option<&'a[u8]>",
		"receiver:&mutself",
		"impl_trait:Iterator",
		"impl_type:Reader<'a>",
	} {
		if !slices.Contains(tokens, want) {
			t.Fatalf("lending fact %q missing from next's context; tokens=%q", want, tokens)
		}
	}

	tokens = rustFunctionContextTokens(t, owning, "next")
	for _, want := range []string{
		"return_type:Option<u8>",
		"receiver:&mutself",
		"impl_trait:Iterator",
		"impl_type:Reader",
	} {
		if !slices.Contains(tokens, want) {
			t.Fatalf("owning fact %q missing from next's context; tokens=%q", want, tokens)
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
	tokens := rustFunctionContextTokens(t, src, "translate")
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
			t.Fatalf("signature fact %q missing from translate's context; tokens=%q", want, tokens)
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
	tokens := rustFunctionContextTokens(t, src, "peek")
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

	tokens = rustFunctionContextTokens(t, src, "drain")
	for _, want := range []string{"receiver:self", "impl_type:Cache"} {
		if !slices.Contains(tokens, want) {
			t.Fatalf("drain fact %q missing; tokens=%q", want, tokens)
		}
	}

	tokens = rustFunctionContextTokens(t, src, "poke")
	if !slices.Contains(tokens, "receiver:std::pin::Pin<&mutSelf>") {
		t.Fatalf("typed receiver fact missing; tokens=%q", tokens)
	}
}

// A method restored to its surrounding context after the impl is walked: the
// free function that follows an impl block must not inherit its header.
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
	tokens := rustFunctionContextTokens(t, src, "standalone")
	for _, tok := range tokens {
		if strings.HasPrefix(tok, "impl_type:") || strings.HasPrefix(tok, "impl_trait:") {
			t.Fatalf("function after the impl block inherited its header (%q); tokens=%q", tok, tokens)
		}
	}
	// A function nested inside a method's body is a plain function scoped to
	// that body, not a method of the impl, so it carries no header either.
	tokens = rustFunctionContextTokens(t, src, "label")
	for _, tok := range tokens {
		if strings.HasPrefix(tok, "impl_type:") || strings.HasPrefix(tok, "impl_trait:") || strings.HasPrefix(tok, "receiver:") {
			t.Fatalf("nested function inherited the impl header (%q); tokens=%q", tok, tokens)
		}
	}
	tokens = rustFunctionContextTokens(t, src, "get")
	if !slices.Contains(tokens, "impl_type:Holder<T>") {
		t.Fatalf("generic impl type fact missing; tokens=%q", tokens)
	}
	for _, tok := range tokens {
		if strings.HasPrefix(tok, "impl_trait:") {
			t.Fatalf("impl without a trait recorded one (%q); tokens=%q", tok, tokens)
		}
	}
}
