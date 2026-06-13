package sca

import "strings"

// NormalizePackageName canonicalizes dependency names for matching across
// manifests, imports, and call roots. It intentionally keeps ecosystem-specific
// spelling such as npm scopes, while removing quote noise and case drift.
func NormalizePackageName(s string) string {
	return strings.ToLower(strings.TrimSpace(strings.Trim(s, `"'`)))
}

// PackageRoot returns the import/package root for nested module paths. It keeps
// scoped npm packages intact: @scope/pkg/lib -> @scope/pkg.
func PackageRoot(s string) string {
	s = NormalizePackageName(s)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "@") {
		parts := strings.Split(s, "/")
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
	}
	if i := strings.IndexByte(s, '/'); i > 0 {
		return s[:i]
	}
	return s
}

// PackageMatches reports whether observed package/import evidence satisfies a
// requested package gate. Prefix matching covers Java/.NET namespace imports and
// nested JS/Go module paths without making unrelated word-prefix matches.
func PackageMatches(observed, want string) bool {
	observed = NormalizePackageName(observed)
	want = NormalizePackageName(want)
	if observed == "" || want == "" {
		return false
	}
	return observed == want ||
		PackageRoot(observed) == want ||
		PackageRoot(want) == observed ||
		strings.HasPrefix(observed, want+".") ||
		strings.HasPrefix(want, observed+".") ||
		strings.HasPrefix(observed, want+"/") ||
		strings.HasPrefix(want, observed+"/")
}

// CallRoot extracts the package-shaped root from a resolved callee path.
func CallRoot(path string) string {
	path = NormalizePackageName(path)
	if path == "" {
		return ""
	}
	if i := strings.IndexAny(path, ".["); i >= 0 {
		path = path[:i]
	}
	return PackageRoot(path)
}
