package sca

import (
	"sort"

	"github.com/vyprai/vyql/internal/usg"
)

// VulnerableEntrypoint is an enriched advisory: which library symbol is the
// vulnerable entrypoint, what vulnerability class it is (→ a sink concept), and
// which argument carries attacker data (docs/11 §"Vulnerable-library
// entrypoints"). Projecting it lets the existing taint rules decide
// EXPLOITABILITY, not just presence.
type VulnerableEntrypoint struct {
	Advisory   string   // CVE / GHSA / OSV id
	Package    string   // PyPI package name (sbom node)
	Version    string   // affected version
	Symbol     string   // entrypoint call path
	VulnClass  string   // sink concept
	TaintedArg int      // which argument carries attacker data (sink precision)
	CWE        []string // optional CWE ids
}

type callUse struct {
	arg0 string
}

// ProjectEntrypoints projects each advisory whose affected package version is
// present and advisory-matched in the SBOM onto the application's real call
// sites: it labels the tainted argument of every matching call with the
// vuln-class sink concept and marks the package reachable if any call
// exists. Relies on the import/type-resolved call graph the SAST frontend built.
func ProjectEntrypoints(g usg.Store, entrypoints []VulnerableEntrypoint) error {
	// which (name, version) are present + advisory-matched in the sbom
	vulnerable := map[PkgKey]string{} // key -> package node id
	if err := rangeStoreNodes(g, func(n usg.Node) bool {
		if n.Type == "sbom.PackageVersion" && hasPackageToken(n, "status=vulnerable") {
			vulnerable[PkgKey{n.Prop("name"), n.Prop("version")}] = n.ID
		}
		return true
	}); err != nil {
		return err
	}

	bySymbol := map[string][]VulnerableEntrypoint{}
	for _, ve := range entrypoints {
		if _, ok := vulnerable[PkgKey{ve.Package, ve.Version}]; !ok {
			continue // not present / not flagged -> skip
		}
		bySymbol[ve.Symbol] = append(bySymbol[ve.Symbol], ve)
	}
	if len(bySymbol) == 0 {
		return nil
	}

	callsBySymbol := map[string][]callUse{}
	if err := rangeStoreNodes(g, func(n usg.Node) bool {
		if n.Type != "code.Call" {
			return true
		}
		sym := n.Prop("callee_path")
		if _, ok := bySymbol[sym]; !ok {
			return true
		}
		callsBySymbol[sym] = append(callsBySymbol[sym], callUse{arg0: n.Prop("arg0")})
		return true
	}); err != nil {
		return err
	}

	matchedPkg := map[string]bool{}
	for _, ve := range entrypoints {
		pkgNode, ok := vulnerable[PkgKey{ve.Package, ve.Version}]
		if !ok {
			continue
		}
		calls := callsBySymbol[ve.Symbol]
		if len(calls) == 0 {
			continue
		}
		matchedPkg[pkgNode] = true
		for _, call := range calls {
			// sink-argument precision: label exactly the dangerous arg
			var arg string
			if ve.TaintedArg == 0 {
				arg = call.arg0
			}
			if arg == "" {
				continue
			}
			if err := g.AddLabel(arg, usg.Label{Concept: ve.VulnClass,
				Provenance: usg.Provenance{Applicator: "advisory:" + ve.Advisory},
				Detail: map[string]string{"advisory": ve.Advisory,
					"package": ve.Package + "@" + ve.Version, "provenance_priority": "100"}}); err != nil {
				return err
			}
		}
	}
	var pkgIDs []string
	for id := range matchedPkg {
		pkgIDs = append(pkgIDs, id)
	}
	sort.Strings(pkgIDs)
	for _, id := range pkgIDs {
		if err := addPackageTokens(g, id, "reachable=true"); err != nil {
			return err
		}
	}
	return nil
}
