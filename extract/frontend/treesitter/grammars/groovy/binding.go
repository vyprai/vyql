// Package groovy provides the tree-sitter Groovy language.
//
// parser.c is VENDORED from github.com/murtaza64/tree-sitter-groovy (committed
// parser.c). Compiled by cgo here. See scripts/vendor-grammars.sh.
package groovy

// #cgo CFLAGS: -std=c11 -fPIC -I${SRCDIR}
// #include "tree_sitter/parser.h"
// const TSLanguage *tree_sitter_groovy(void);
import "C"

import "unsafe"

// Language returns the tree-sitter language pointer for Groovy.
func Language() unsafe.Pointer { return unsafe.Pointer(C.tree_sitter_groovy()) }
