package sca

import (
	"path/filepath"
	"regexp"
	"strings"
)

type vendoredJSLibrary struct {
	Name      string
	PathHints []string
	VersionRe *regexp.Regexp
}

var vendoredJSLibraries = []vendoredJSLibrary{
	{
		Name:      "tinymce",
		PathHints: []string{"tinymce/"},
		VersionRe: regexp.MustCompile(`(?im)^\s*\*\s*Version:\s*v?([0-9]+(?:\.[0-9A-Za-z-]+)+)`),
	},
}

// ParseVendoredJS reads known third-party JavaScript library banners from checked-in
// assets and returns normal package dependencies. This covers projects that vendor
// browser libraries directly instead of declaring them in package.json.
func ParseVendoredJS(path, content string) []Dep {
	clean := strings.ToLower(filepath.ToSlash(path))
	var out []Dep
	for _, lib := range vendoredJSLibraries {
		if !matchesAnyPathHint(clean, lib.PathHints) {
			continue
		}
		m := lib.VersionRe.FindStringSubmatch(content)
		if len(m) < 2 {
			continue
		}
		out = append(out, Dep{Name: lib.Name, Version: m[1]})
	}
	return out
}

func matchesAnyPathHint(path string, hints []string) bool {
	for _, hint := range hints {
		if strings.Contains(path, strings.ToLower(filepath.ToSlash(hint))) {
			return true
		}
	}
	return false
}
