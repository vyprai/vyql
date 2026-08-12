package extract

import "testing"

// A pattern that matches nothing is the dangerous case: the scan reports a clean
// result over a tree it never read. These pin the one rule that decides what a
// pattern means, so a value cannot quietly stop matching.
func TestExclusionDesugaring(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		pattern string
		dir     string
	}{
		{"node_modules", "**/node_modules/**", "node_modules"},
		{"gen/", "**/gen/**", "gen"},
		{"*.min.js", "**/*.min.js", ""},
		{"*_templ.go", "**/*_templ.go", ""},
		{"**/*_templ.go", "**/*_templ.go", ""},
		{"src/gen/**", "src/gen/**", ""},
		{"**/*.{test,spec}.ts", "**/*.{test,spec}.ts", ""},
	} {
		e, err := ParseExclusion(tc.raw)
		if err != nil {
			t.Errorf("ParseExclusion(%q) = %v", tc.raw, err)
			continue
		}
		if e.Pattern != tc.pattern {
			t.Errorf("ParseExclusion(%q).Pattern = %q, want %q", tc.raw, e.Pattern, tc.pattern)
		}
		if e.Dir != tc.dir {
			t.Errorf("ParseExclusion(%q).Dir = %q, want %q", tc.raw, e.Dir, tc.dir)
		}
	}
}

func TestExclusionMatching(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		path    string
		want    bool
	}{
		// A bare name is that directory at any depth, not only at the root.
		{"node_modules", "node_modules/x.js", true},
		{"node_modules", "a/b/node_modules/x.js", true},
		{"node_modules", "a/node_modules_helper/x.js", false},
		// A bare glob is that file at any depth. `*` does not cross a separator,
		// so this is the case an unanchored pattern gets wrong.
		{"*_templ.go", "x_templ.go", true},
		{"*_templ.go", "gen/x_templ.go", true},
		{"*_templ.go", "a/b/c/x_templ.go", true},
		{"*_templ.go", "gen/x.go", false},
		// A pattern with a separator is anchored at the scan root.
		{"src/gen/**", "src/gen/a/b.go", true},
		{"src/gen/**", "other/src/gen/a.go", false},
		// Brace alternation, the reason comma-splitting is gone.
		{"**/*.{test,spec}.ts", "a/b.test.ts", true},
		{"**/*.{test,spec}.ts", "a/b.spec.ts", true},
		{"**/*.{test,spec}.ts", "a/b.ts", false},
	} {
		e, err := ParseExclusion(tc.pattern)
		if err != nil {
			t.Errorf("ParseExclusion(%q) = %v", tc.pattern, err)
			continue
		}
		if got := (Excludes{e}).Match("", tc.path); got != tc.want {
			t.Errorf("%q matching %q = %v, want %v (compiled: %q)",
				tc.pattern, tc.path, got, tc.want, e.Pattern)
		}
	}
}

// A comma is almost always a list written for the comma-separated form. Rejecting
// it makes the change a loud error rather than a pattern that matches nothing.
func TestExclusionRejectsCommaOutsideBraces(t *testing.T) {
	if _, err := ParseExclusion("vendor,node_modules"); err == nil {
		t.Fatal("a comma-separated list must be rejected, not accepted as one pattern")
	}
	if _, err := ParseExclusion("**/*.{test,spec}.ts"); err != nil {
		t.Fatalf("a comma inside braces is alternation and must be accepted: %v", err)
	}
}

func TestExclusionRejectsMalformedPattern(t *testing.T) {
	if _, err := ParseExclusion("a[b"); err == nil {
		t.Fatal("a malformed glob must be rejected at parse time, before any file is read")
	}
}

// Only the directory form prunes. Pruning on a file glob would skip a whole
// directory because one file in it matched.
func TestOnlyDirectoryPatternsPruneTheWalk(t *testing.T) {
	dirPattern, _ := ParseExclusion("node_modules")
	filePattern, _ := ParseExclusion("*.min.js")
	if !(Excludes{dirPattern}).SkipDir("node_modules") {
		t.Error("a directory pattern must prune the walk")
	}
	if (Excludes{filePattern}).SkipDir("assets") {
		t.Error("a file glob must not prune a directory")
	}
}

// Reporting which patterns matched nothing is what turns a filter that silently
// fails into one the operator can see.
func TestUnmatchedReportsPatternsThatExcludedNothing(t *testing.T) {
	hit, _ := ParseExclusion("*_templ.go")
	miss, _ := ParseExclusion("*.min.js")
	es := Excludes{hit, miss}
	es.Match("", "gen/x_templ.go")
	got := es.Unmatched()
	if len(got) != 1 || got[0] != "*.min.js" {
		t.Fatalf("Unmatched() = %v, want only the pattern that excluded nothing", got)
	}
}
