// Package perl provides the tree-sitter Perl language.
//
// parser.c is GENERATED from github.com/tree-sitter-perl/tree-sitter-perl's
// grammar.js (it ships no Go binding and no committed parser.c); scanner.c +
// tsp_*.h are its hand-written scanner. Compiled by cgo here. See
// scripts/vendor-grammars.sh to regenerate.
package perl

// #cgo CFLAGS: -std=c11 -fPIC -I${SRCDIR}
// #include "tree_sitter/parser.h"
// const TSLanguage *tree_sitter_perl(void);
import "C"

import "unsafe"

// Language returns the tree-sitter language pointer for Perl.
func Language() unsafe.Pointer { return unsafe.Pointer(C.tree_sitter_perl()) }
