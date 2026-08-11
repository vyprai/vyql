package extract

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// Exclusion is a compiled -exclude pattern.
//
// One rule decides what a pattern means: a value with no slash and no glob
// metacharacter names a directory and matches it at any depth; anything else is
// a glob matched against the scan-relative, slash-separated path.
//
//	node_modules           **/node_modules/**
//	**/*_templ.go          any file with that suffix, at any depth
//	src/gen/**             everything under that directory, from the scan root
//	*.min.js               any file with that suffix, at any depth
//	**/*.{test,spec}.ts    brace alternation
//
// The directory form is separated out because a directory can be skipped during
// the walk, which is what keeps an excluded tree from being read at all.
type Exclusion struct {
	// Raw is the pattern as written, for reporting which patterns matched.
	Raw string
	// Pattern is the compiled glob.
	Pattern string
	// Dir is the bare directory name when the pattern named one, empty otherwise.
	// A directory whose name equals this is never descended.
	Dir string
	// Matched counts the files this pattern excluded, so a pattern matching
	// nothing can be reported rather than passing silently.
	Matched int
	// PrunedDirs counts the directories this pattern kept the walk out of. Those
	// files are never listed, so they cannot be counted individually -- reporting
	// the directories is what the walk actually knows.
	PrunedDirs int
}

// globMeta are the characters that make a value a glob rather than a name.
const globMeta = "*?[]{}"

// ParseExclusion compiles one pattern. A malformed glob is rejected here, before
// any file is read: a pattern that cannot match is a filter the operator
// believes is working, and this scanner reporting an empty result reads as a
// clean bill of health.
func ParseExclusion(raw string) (*Exclusion, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return nil, fmt.Errorf("empty pattern")
	}
	// A comma almost always means a list written for the older comma-separated
	// form. Inside braces it is alternation and legitimate, so only a comma
	// outside them is rejected -- and the message names the fix rather than
	// leaving a pattern that silently matches nothing.
	if commaOutsideBraces(p) {
		return nil, fmt.Errorf("pattern %q contains a comma\n"+
			"  -exclude takes one pattern; repeat the flag for more\n"+
			"  a comma inside braces is alternation and is fine: '**/*.{test,spec}.ts'", raw)
	}
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		return nil, fmt.Errorf("empty pattern")
	}
	e := &Exclusion{Raw: raw}
	switch {
	case strings.Contains(p, "/"):
		// A pattern with a separator is positional and matches as written, so
		// `src/gen/**` means that directory from the scan root rather than one of
		// that name anywhere.
		e.Pattern = p
	case strings.ContainsAny(p, globMeta):
		// A pattern with no separator names a file at any depth. `*` does not
		// cross a separator, so `*.min.js` written literally would match only at
		// the scan root -- which is never what a bare suffix pattern means.
		e.Pattern = "**/" + p
	default:
		e.Dir = p
		e.Pattern = "**/" + p + "/**"
	}
	if !doublestar.ValidatePattern(e.Pattern) {
		return nil, fmt.Errorf("invalid pattern %q", raw)
	}
	return e, nil
}

func commaOutsideBraces(p string) bool {
	depth := 0
	for _, r := range p {
		switch r {
		case '{':
			depth++
		case '}':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				return true
			}
		}
	}
	return false
}

// Excludes is a compiled pattern set.
type Excludes []*Exclusion

// ParseExcludes compiles a pattern list, reporting the first that does not compile.
func ParseExcludes(raw []string) (Excludes, error) {
	var out Excludes
	for _, r := range raw {
		e, err := ParseExclusion(r)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// SkipDir reports whether a directory should not be descended. Only the
// directory form answers here: whether a file is excluded cannot be decided from
// its parent, and pruning on a file glob would drop files the pattern does not
// name.
func (es Excludes) SkipDir(name string) bool {
	for _, e := range es {
		if e.Dir != "" && e.Dir == name {
			e.PrunedDirs++
			return true
		}
	}
	return false
}

// Match reports whether a path is excluded, and records which pattern did it.
// The path is made relative to root and slash-separated first, so a pattern
// anchored at the scan root means the same thing on every platform.
func (es Excludes) Match(root, path string) bool {
	if len(es) == 0 {
		return false
	}
	rel := path
	if root != "" {
		if r, err := filepath.Rel(root, path); err == nil && !strings.HasPrefix(r, "..") {
			rel = r
		}
	}
	rel = filepath.ToSlash(rel)
	for _, e := range es {
		if ok, err := doublestar.Match(e.Pattern, rel); err == nil && ok {
			e.Matched++
			return true
		}
		// A directory pattern is also checked against the bare segments, so an
		// absolute or otherwise unrelativised path still matches the directory
		// it names.
		if e.Dir != "" && hasSegment(rel, e.Dir) {
			e.Matched++
			return true
		}
	}
	return false
}

func hasSegment(p, seg string) bool {
	for _, s := range strings.Split(p, "/") {
		if s == seg {
			return true
		}
	}
	return false
}

// Unmatched returns the patterns that excluded nothing. Excluding a directory a
// given repository does not have is legitimate in a shared configuration, so
// this is reported rather than treated as an error.
func (es Excludes) Unmatched() []string {
	var out []string
	for _, e := range es {
		if e.Matched == 0 && e.PrunedDirs == 0 {
			out = append(out, e.Raw)
		}
	}
	return out
}
