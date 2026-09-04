package definitions

import (
	"bufio"
	"os"
	"sort"
	"strings"
	"testing"
)

// A rule reads "taint flows from A to B, unless control C protects it". The unless
// clause is the escape hatch: it is how correct code stops being reported. When a
// language binds a sink but binds no check able to neutralise that sink's threats,
// the clause cannot be satisfied by anything the user writes, so every match is a
// false positive by construction and no code change can clear it.

func sinkAndGuard(sinkLang, checkLang string) Catalog {
	cat := Catalog{
		Concepts: []ConceptSummary{
			{Name: "code.Sink", Kind: "sink", VulnerableTo: []string{"threat.Bad"}},
			{Name: "core.Guard", Kind: "check", Neutralizes: []string{"threat.Bad"}},
		},
		Bindings: []MappingSummary{
			{Language: sinkLang, Kind: "sink_method", Concept: "code.Sink"},
		},
	}
	if checkLang != "" {
		cat.Bindings = append(cat.Bindings, MappingSummary{
			Language: checkLang, Kind: "check_method", Concept: "core.Guard",
		})
	}
	return cat
}

func TestOrphanedSinksReportsASinkWithNoNeutralisingCheck(t *testing.T) {
	got := OrphanedSinks(sinkAndGuard("go", ""))

	if len(got) != 1 {
		t.Fatalf("want 1 orphan, got %d: %+v", len(got), got)
	}
	want := Orphan{Language: "go", Sink: "code.Sink", Threat: "threat.Bad"}
	if got[0] != want {
		t.Fatalf("orphan = %+v, want %+v", got[0], want)
	}
}

func TestOrphanedSinksAcceptsACheckInTheSameLanguage(t *testing.T) {
	if got := OrphanedSinks(sinkAndGuard("go", "go")); len(got) != 0 {
		t.Fatalf("want no orphans when the language binds the control, got %+v", got)
	}
}

// A control bound in another language does not help: the rule is evaluated against
// this language's graph, so a Python sanitiser cannot clear a Go flow.
func TestOrphanedSinksRejectsACheckInAnotherLanguage(t *testing.T) {
	if got := OrphanedSinks(sinkAndGuard("go", "python")); len(got) != 1 {
		t.Fatalf("want 1 orphan when the control is bound elsewhere, got %+v", got)
	}
}

// The library, config, textpattern, sca, pii, auditreview and cryptoreview packs
// bind against every language rather than one, so a check they bind counts for all.
func TestOrphanedSinksAcceptsACheckInACrossLanguagePack(t *testing.T) {
	if got := OrphanedSinks(sinkAndGuard("go", "library")); len(got) != 0 {
		t.Fatalf("want no orphans when a cross-language pack binds the control, got %+v", got)
	}
}

// A sink that declares no threat has nothing to neutralise, so it cannot be
// orphaned. Counting it would report every sink in the corpus.
func TestOrphanedSinksIgnoresASinkWithNoDeclaredThreat(t *testing.T) {
	cat := Catalog{
		Concepts: []ConceptSummary{{Name: "code.Sink", Kind: "sink"}},
		Bindings: []MappingSummary{{Language: "go", Kind: "sink_method", Concept: "code.Sink"}},
	}
	if got := OrphanedSinks(cat); len(got) != 0 {
		t.Fatalf("want no orphans for a sink with no declared threat, got %+v", got)
	}
}

// A sink declaring several threats is orphaned once per threat left uncovered, so
// closing one does not hide the rest.
func TestOrphanedSinksReportsEachUncoveredThreatSeparately(t *testing.T) {
	cat := Catalog{
		Concepts: []ConceptSummary{
			{Name: "code.Sink", Kind: "sink", VulnerableTo: []string{"threat.One", "threat.Two"}},
			{Name: "core.Guard", Kind: "check", Neutralizes: []string{"threat.One"}},
		},
		Bindings: []MappingSummary{
			{Language: "go", Kind: "sink_method", Concept: "code.Sink"},
			{Language: "go", Kind: "check_method", Concept: "core.Guard"},
		},
	}

	got := OrphanedSinks(cat)

	if len(got) != 1 || got[0].Threat != "threat.Two" {
		t.Fatalf("want only threat.Two reported, got %+v", got)
	}
}

// Binding kinds are prefixed -- sink_method, sink_path, check_method, check_arg and
// so on. Matching the exact word would see almost none of the corpus.
func TestOrphanedSinksMatchesEveryBindingKindPrefix(t *testing.T) {
	cat := Catalog{
		Concepts: []ConceptSummary{
			{Name: "code.Sink", Kind: "sink", VulnerableTo: []string{"threat.Bad"}},
			{Name: "core.Guard", Kind: "check", Neutralizes: []string{"threat.Bad"}},
		},
		Bindings: []MappingSummary{
			{Language: "go", Kind: "sink_path", Concept: "code.Sink"},
			{Language: "go", Kind: "check_arg", Concept: "core.Guard"},
		},
	}
	if got := OrphanedSinks(cat); len(got) != 0 {
		t.Fatalf("want no orphans when both bindings use other kind prefixes, got %+v", got)
	}
}

// ── the shipped corpus ──────────────────────────────────────────────────────

func readFixtureLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	var out []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := s.Err(); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sort.Strings(out)
	return out
}

// Every sink bound in a language must have some check bound in that same language
// able to neutralise each threat the sink declares. Otherwise the rule over it can
// only ever report, and a user with correct code has no way to silence it.
//
// orphaned_sinks.txt is a work list, not an exemption list: it holds the pairs that
// are open today and must reach empty. Removing a line without binding the control
// fails here, and binding one without removing the line fails here too.
func TestShippedCorpusHasNoOrphanedSinks(t *testing.T) {
	if definitionsArePublished() {
		t.Skip("the definitions are fetched, and the work list is versioned with the corpus it describes")
	}
	cat, err := Inspect(InspectOptions{Kind: "all", Max: 1 << 30})
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}

	excluded := map[string]bool{}
	for _, threat := range readFixtureLines(t, "testdata/threats_without_controls.txt") {
		excluded[threat] = true
	}

	seen := map[string]bool{}
	var got []string
	for _, o := range OrphanedSinks(cat) {
		if excluded[o.Threat] {
			continue
		}
		line := o.Threat + "\t" + o.Language
		if seen[line] {
			continue
		}
		seen[line] = true
		got = append(got, line)
	}
	sort.Strings(got)

	want := readFixtureLines(t, "testdata/orphaned_sinks.txt")
	if strings.Join(got, "\n") == strings.Join(want, "\n") {
		return
	}
	for _, line := range missingFrom(want, got) {
		t.Errorf("resolved but still listed in testdata/orphaned_sinks.txt: %s", line)
	}
	for _, line := range missingFrom(got, want) {
		t.Errorf("new orphaned sink, and no check in that language can clear it: %s", line)
	}
}

// missingFrom returns the entries of a that do not appear in b.
func missingFrom(a, b []string) []string {
	have := make(map[string]bool, len(b))
	for _, s := range b {
		have[s] = true
	}
	var out []string
	for _, s := range a {
		if !have[s] {
			out = append(out, s)
		}
	}
	return out
}
