// Package solidity provides the tree-sitter Solidity language.
//
// parser.c is GENERATED via `tree-sitter generate` from JoranHonig/tree-sitter-
// solidity's grammar.js (fetched by raw URL — the repo has no Go module). No
// external scanner. See scripts/vendor-grammars.sh.
package solidity

// #cgo CFLAGS: -std=c11 -fPIC -I${SRCDIR}
// #include "tree_sitter/parser.h"
// const TSLanguage *tree_sitter_solidity(void);
import "C"

import "unsafe"

// Language returns the tree-sitter language pointer for Solidity.
func Language() unsafe.Pointer { return unsafe.Pointer(C.tree_sitter_solidity()) }
