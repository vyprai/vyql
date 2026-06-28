package sca

import "strings"

// NormalizePackageName canonicalizes dependency names for matching across
// manifests, imports, and call roots. It intentionally keeps ecosystem-specific
// spelling such as npm scopes, while removing quote noise and case drift.
func NormalizePackageName(s string) string {
	s = strings.ToLower(strings.TrimSpace(strings.Trim(s, `"'`)))
	if i := strings.IndexByte(s, '['); i >= 0 {
		s = s[:i]
	}
	return s
}

// importAlias maps a language IMPORT name to the distribution/package name(s) it actually
// belongs to, for ecosystems where they differ — overwhelmingly Python (`import yaml` ships
// in the `pyyaml` distribution). Without this, a package-gated adapter keyed by the
// distribution name never activates from an import alone (only via a manifest/SBOM). Keys and
// values are lowercased. Conservative and curated: a wrong alias would wrongly activate an
// adapter, so only well-known 1:1 (or near-1:1) mappings are listed.
var importAlias = map[string][]string{
	"yaml":     {"pyyaml"},
	"sklearn":  {"scikit-learn"},
	"dateutil": {"python-dateutil"},
	"jwt":      {"pyjwt"},
	"dotenv":   {"python-dotenv"},
	"openssl":  {"pyopenssl"},
	"mysqldb":  {"mysqlclient"},
	"pil":      {"pillow"},
	"cv2":      {"opencv-python"},
	"bs4":      {"beautifulsoup4"},
	"crypto":   {"pycryptodome", "pycrypto"},
	"serial":   {"pyserial"},
	"git":      {"gitpython"},
	"attr":     {"attrs"},
	"dns":      {"dnspython"},
	"usb":      {"pyusb"},
	"slugify":  {"python-slugify"},
	"magic":    {"python-magic"},
	"docx":     {"python-docx"},
	"jose":     {"python-jose"},
	"memcache": {"python-memcached"},
}

// ImportAliases returns the distribution/package name(s) an import name resolves to when they
// differ (e.g. "yaml" -> "pyyaml"), or nil. Used to expand a project's dependency evidence so
// package-gated adapters activate from imports without requiring a manifest.
func ImportAliases(name string) []string {
	return importAlias[NormalizePackageName(name)]
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
		strings.HasPrefix(want, observed+"/") ||
		packagePathContains(observed, want) ||
		packagePathContains(want, observed)
}

func packagePathContains(path, want string) bool {
	if !strings.Contains(path, "/") || want == "" || strings.ContainsAny(want, "/.") {
		return false
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == want {
			return true
		}
	}
	return false
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
