// Package dart provides the tree-sitter Dart language.
//
// parser.c + scanner.c are VENDORED from github.com/UserNobody14/tree-sitter-dart
// (committed parser.c). Compiled by cgo here. See scripts/vendor-grammars.sh.
package dart

// #cgo CFLAGS: -std=c11 -fPIC -I${SRCDIR}
// #include "tree_sitter/parser.h"
// const TSLanguage *tree_sitter_dart(void);
import "C"

import "unsafe"

// Language returns the tree-sitter language pointer for Dart.
func Language() unsafe.Pointer { return unsafe.Pointer(C.tree_sitter_dart()) }
