// Package objc provides the tree-sitter Objective-C language (vendored from
// tree-sitter-grammars/tree-sitter-objc, committed parser.c, no Go binding).
package objc

// #cgo CFLAGS: -std=c11 -fPIC -I${SRCDIR}
// #include "tree_sitter/parser.h"
// const TSLanguage *tree_sitter_objc(void);
import "C"

import "unsafe"

// Language returns the tree-sitter language pointer for Objective-C.
func Language() unsafe.Pointer { return unsafe.Pointer(C.tree_sitter_objc()) }
