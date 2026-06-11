// Package elixir provides the tree-sitter Elixir language.
//
// parser.c + scanner.c are VENDORED from github.com/elixir-lang/tree-sitter-elixir
// (which ships a committed parser.c but a Go binding under a non-resolvable module
// path). Compiled by cgo here. See scripts/vendor-grammars.sh.
package elixir

// #cgo CFLAGS: -std=c11 -fPIC -I${SRCDIR}
// #include "tree_sitter/parser.h"
// const TSLanguage *tree_sitter_elixir(void);
import "C"

import "unsafe"

// Language returns the tree-sitter language pointer for Elixir.
func Language() unsafe.Pointer { return unsafe.Pointer(C.tree_sitter_elixir()) }
