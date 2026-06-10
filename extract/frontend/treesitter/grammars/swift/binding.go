// Package swift provides the tree-sitter Swift language.
//
// parser.c is GENERATED from github.com/alex-pinkus/tree-sitter-swift's grammar.js
// via `tree-sitter generate` (that grammar ships no committed parser.c); scanner.c
// is its hand-written external scanner. Both are compiled by cgo here. See
// scripts/vendor-grammars.sh to regenerate.
package swift

// #cgo CFLAGS: -std=c11 -fPIC -I${SRCDIR}
// #include "tree_sitter/parser.h"
// const TSLanguage *tree_sitter_swift(void);
import "C"

import "unsafe"

// Language returns the tree-sitter language pointer for Swift.
func Language() unsafe.Pointer { return unsafe.Pointer(C.tree_sitter_swift()) }
