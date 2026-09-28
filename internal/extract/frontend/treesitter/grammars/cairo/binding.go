// Package cairo provides the tree-sitter Cairo language.
//
// Vendored from github.com/tree-sitter-grammars/tree-sitter-cairo (amaanq),
// which ships a committed parser.c + scanner.c but no Go binding. The grammar
// covers both Cairo 0 (`func`/`end`) and Cairo 1 (`fn`/`impl`) syntax, so one
// parser reads the pre-migration Starknet contracts the OWASP-era CVEs live in
// and the current language alike. scripts/vendor-grammars.sh does not cover
// this grammar; refresh it by copying the repo's parser.c, scanner.c and
// tree_sitter/ here, then re-applying the patches below and regenerating with
// `npx -y tree-sitter-cli@0.25 generate` from a checkout holding the patched
// grammar.js, cairo_0.js, cairo_1.js and utils.js.
//
// The committed parser.c is regenerated from that grammar with five repairs
// the upstream source needs before it reads real contracts (measured on the
// OpenZeppelin Cairo 0 corpus: every `func` parses, zero ERROR nodes; the
// unpatched grammar drops 12 of 388 functions and emits 523 ERROR nodes):
//
//   - comment: a `#` comment must not swallow `#[attribute]`, so the token
//     stops before a `[` that follows it directly.
//   - Cairo 0 block forms: `_cairo_0_namespace_definition`,
//     `_cairo_0_struct_definition`, `_cairo_0_attribute_statement` (with_attr)
//     and `_cairo_0_with_statement` use the colon/`end` shape the language
//     actually spells, not the brace shape upstream invented.
//   - `_cairo_0_if_statement` aliases its else arm to the `else_clause` node
//     name Cairo 1 already uses, so one walk covers both dialects.
//   - Cairo 1 `visibility_modifier` (`pub`) is defined and the
//     `optional($.visibility_modifier)` slots are enabled wherever the
//     language spells it — upstream has them commented out, and every `pub`
//     in a real file parsed as an ERROR without this.
package cairo

// #cgo CFLAGS: -std=c11 -fPIC -I${SRCDIR}
// #include "tree_sitter/parser.h"
// const TSLanguage *tree_sitter_cairo(void);
import "C"

import "unsafe"

// Language returns the tree-sitter language pointer for Cairo.
func Language() unsafe.Pointer { return unsafe.Pointer(C.tree_sitter_cairo()) }
