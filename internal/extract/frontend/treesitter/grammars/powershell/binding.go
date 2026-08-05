// Package powershell provides the tree-sitter PowerShell language.
//
// Vendored from github.com/airbus-cert/tree-sitter-powershell (which ships a
// committed parser.c + scanner.c but no Go bindings). parser.c and scanner.c are
// compiled by cgo as part of this package; see scripts/vendor-grammars.sh to
// regenerate/refresh.
package powershell

// #cgo CFLAGS: -std=c11 -fPIC -I${SRCDIR}
// #include "tree_sitter/parser.h"
// const TSLanguage *tree_sitter_powershell(void);
import "C"

import "unsafe"

// Language returns the tree-sitter language pointer for PowerShell.
func Language() unsafe.Pointer { return unsafe.Pointer(C.tree_sitter_powershell()) }
