package lowering

import "strings"

// resolveReceiverPackage reports which package a call is made on, by resolving
// the root segment of its callee path through the enclosing module's import
// table.
//
// A call reaches a package two ways. `yaml.load(x)` has the package bound to a
// receiver, so the root segment ("yaml") is the import local. `parse(x)` after
// `const { parse } = require('qs')` has no receiver at all, and the callee path
// is itself the import local. Both resolve here; anything else -- a builtin, a
// dynamic receiver, a local variable -- returns "" and is treated as
// unresolved.
func resolveReceiverPackage(calleePath string, table map[string]importEntry) string {
	if calleePath == "" || len(table) == 0 {
		return ""
	}
	root := calleePath
	if i := strings.IndexByte(root, '.'); i > 0 {
		root = root[:i]
	}
	entry, ok := table[root]
	if !ok || entry.module == "" {
		return ""
	}
	// A dotted module is a submodule of its package: `defusedxml.ElementTree`
	// belongs to `defusedxml`. importPackageRoot splits on "/", which is npm
	// and Go syntax, so the dotted tail is trimmed first and only where no
	// slash is present -- a scoped npm name like @hapi/bourne has no dotted
	// package structure to strip.
	mod := entry.module
	if !strings.Contains(mod, "/") {
		if i := strings.IndexByte(mod, '.'); i > 0 {
			mod = mod[:i]
		}
	}
	return importPackageRoot(mod)
}
