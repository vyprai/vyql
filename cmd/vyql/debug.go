package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/vyprai/vyql/internal/bindings"
	"github.com/vyprai/vyql/internal/datadir"
	"github.com/vyprai/vyql/internal/extract"
	"github.com/vyprai/vyql/internal/findings"
	"github.com/vyprai/vyql/internal/ontology"
	"github.com/vyprai/vyql/internal/parser"
	"github.com/vyprai/vyql/internal/resultpolicy"
	"github.com/vyprai/vyql/internal/usg"
)

// ── vyql trace ──────────────────────────────────────────────────────────────────────
// Trace taint from sources to sinks. For each source it prints the shortest FLOWS path to a
// reachable sink (the flow vyql sees), or — when a source reaches NO sink — the frontier:
// where the taint stopped, so a broken chain (an unresolved/cross-package call, a missing sink
// label, a sanitizer kill) is visible at a glance. This is the "why is this (not) flagged?"
// tool; it works on the same graph the engine evaluates, no rules needed.

func cmdTrace(args []string) error {
	fs := newFlagSet("trace")
	from := fs.String("from", "", "only trace sources whose concept contains this substring")
	to := fs.String("to", "", "only count sinks whose concept contains this substring")
	brief := fs.Bool("brief", false, "one line per connected source→sink pair, with hop count")
	count := fs.Bool("count", false, "print only the number of connected pairs")
	profileName := addProfile(fs)
	runOpts := addRunFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	stopProfiling, err := runOpts.apply()
	if err != nil {
		return err
	}
	defer stopProfiling()
	paths, err := requirePaths(fs, "vyql trace [-from CONCEPT] [-to CONCEPT] <path>...")
	if err != nil {
		return err
	}
	// Checked before the graph is built: a filter that can never match would
	// otherwise print "0 source(s)" after a full scan, which reads as good news.
	onto := ontology.Seed()
	if err := validateConceptFilter(onto, "from", *from); err != nil {
		return err
	}
	if err := validateConceptFilter(onto, "to", *to); err != nil {
		return err
	}
	applyProfile(paths, *profileName)
	g, _, err := buildGraph(paths)
	if err != nil {
		return err
	}
	if g == nil {
		fmt.Println("(no analyzable source)")
		return nil
	}
	nodes, _ := g.AllNodes()
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].SortOrder() < nodes[j].SortOrder() })

	connected, dead := 0, 0
	terse := *brief || *count
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, n := range nodes {
		if !isSource(onto, g, n.ID) || (*from != "" && !conceptMatch(g, n.ID, *from)) {
			continue
		}
		path, sink := shortestToSink(onto, g, n.ID, *to)
		if terse {
			if sink == "" {
				dead++
				continue
			}
			connected++
			if !*count {
				fmt.Fprintf(tw, "%s @ %s\t→[%d hops]→\t%s @ %s\t{%s}\n",
					n.ID, n.Prop("loc"), len(path), sink, locOf(g, sink), conceptsOf(g, sink))
			}
			continue
		}
		fmt.Printf("\nSOURCE %s @ %s {%s}\n", n.ID, n.Prop("loc"), conceptsOf(g, n.ID))
		if sink != "" {
			connected++
			fmt.Printf("  reaches SINK %s @ %s {%s}\n", sink, locOf(g, sink), conceptsOf(g, sink))
			for _, step := range path {
				fmt.Printf("    → %s\n", traceNode(g, step))
			}
			continue
		}
		dead++
		fmt.Printf("  reaches no %ssink — taint stops at:\n", toLabel(*to))
		for _, f := range frontier(onto, g, n.ID) {
			fmt.Printf("    ⊣ %s\n", traceNode(g, f))
		}
	}
	_ = tw.Flush()
	if *count {
		fmt.Println(connected)
		return nil
	}
	// The dead-end count is reported in every mode. A terse listing of only the
	// sources that reach a sink reads identically to a clean result, and that is
	// the reading this command exists to prevent.
	if terse {
		fmt.Printf("\n%d reachable source→sink pair(s), %d source(s) dead-end\n", connected, dead)
		return nil
	}
	fmt.Printf("\n%d source(s): %d reach a sink, %d dead-end\n", connected+dead, connected, dead)
	return nil
}

func toLabel(to string) string {
	if to == "" {
		return ""
	}
	return to + " "
}

// shortestToSink BFSes FLOWS edges and returns the shortest path (excluding the source) to the
// first reachable sink-labelled node, or ("",[]) if none. `to` filters the sink concept.
func shortestToSink(onto *ontology.Ontology, g usg.Store, src, to string) ([]string, string) {
	prev := map[string]string{src: ""}
	queue := []string{src}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur != src && isSink(onto, g, cur) && (to == "" || conceptMatch(g, cur, to)) {
			var rev []string
			for x := cur; x != "" && x != src; x = prev[x] {
				rev = append([]string{x}, rev...)
			}
			return rev, cur
		}
		es, _ := g.OutEdges(cur, "FLOWS")
		for _, e := range es {
			if _, seen := prev[e.Dst]; !seen {
				prev[e.Dst] = cur
				queue = append(queue, e.Dst)
			}
		}
	}
	return nil, ""
}

// frontier returns the nodes where taint stopped: reachable Call nodes whose taint goes no
// further toward a labelled node, plus any control or advisory evidence that was hit.
// These are the candidate "broken edges" — most often an unresolved or cross-package call.
func frontier(onto *ontology.Ontology, g usg.Store, src string) []string {
	seen := map[string]bool{src: true}
	queue := []string{src}
	var order []string
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		es, _ := g.OutEdges(cur, "FLOWS")
		for _, e := range es {
			if !seen[e.Dst] {
				seen[e.Dst] = true
				queue = append(queue, e.Dst)
				order = append(order, e.Dst)
			}
		}
	}
	var out []string
	for _, id := range order {
		n, ok, _ := g.GetNode(id)
		if !ok {
			continue
		}
		// a terminal Call (taint reaches it but it has no outgoing FLOWS) is a likely
		// unresolved/external callee — the classic cross-package dead-end.
		es, _ := g.OutEdges(id, "FLOWS")
		isControl := conceptsOf(g, id) != "" && !isSource(onto, g, id)
		if (n.Type == "code.Call" && len(es) == 0) || isControl {
			out = append(out, id)
		}
		if len(out) >= 12 {
			break
		}
	}
	return out
}

func traceNode(g usg.Store, id string) string {
	n, ok, _ := g.GetNode(id)
	if !ok {
		return id
	}
	s := fmt.Sprintf("%-8s %-13s %s", id, n.Type, n.Prop("loc"))
	if p := n.Prop("callee_path"); p != "" {
		s += "  call=" + p
	} else if m := n.Prop("method"); m != "" {
		s += "  method=" + m
	}
	if c := conceptsOf(g, id); c != "" {
		s += "  {" + c + "}"
	}
	if n.Type == "code.Call" {
		if es, _ := g.OutEdges(id, "FLOWS"); len(es) == 0 {
			s += "  ⟂ no outgoing flow (callee not traced — external or cross-package)"
		}
	}
	return s
}

func conceptMatch(g usg.Store, id, sub string) bool {
	for _, l := range labelsOf(g, id) {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

func labelsOf(g usg.Store, id string) []string {
	labels, _ := g.Labels(id)
	var cs []string
	for _, l := range labels {
		cs = append(cs, l.Concept)
	}
	return cs
}

func locOf(g usg.Store, id string) string {
	if n, ok, _ := g.GetNode(id); ok {
		return n.Prop("loc")
	}
	return "?"
}

// isSink reports whether a node carries a sink concept label according to the loaded ontology.
func isSink(onto *ontology.Ontology, g usg.Store, id string) bool {
	for _, l := range labelsOf(g, id) {
		if ontologyConceptKind(onto, l) == "sink" {
			return true
		}
	}
	return false
}

func ontologyConceptKind(onto *ontology.Ontology, c string) string {
	if onto == nil {
		return ""
	}
	cc, err := onto.Get(c)
	if err != nil {
		return ""
	}
	return cc.Kind
}

// ── vyql explain ────────────────────────────────────────────────────────────────────
// Run the rules and print each finding's FULL proof: source/sink bindings (with the applicator
// that labelled them), the witness path, and every negation-evidence clause (sanitizer/guard/
// advisory notes) — the "why did this fire, and what almost stopped it" view.

func cmdExplain(args []string) error {
	fs := newFlagSet("explain")
	rulesPath := addRules(fs)
	profileName := addProfile(fs)
	runOpts := addRunFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	stopProfiling, err := runOpts.apply()
	if err != nil {
		return err
	}
	defer stopProfiling()
	paths, err := requirePaths(fs, "vyql explain [-rules ...] <path>...")
	if err != nil {
		return err
	}
	prof := applyProfile(paths, *profileName)
	ruleSources, err := loadRules(*rulesPath)
	if err != nil {
		return err
	}
	all, _, _, err := scanPathsWithProfile(paths, ruleSources, prof.Name)
	if err != nil {
		return err
	}
	if len(all) == 0 {
		fmt.Println("No findings.")
		return nil
	}
	fmt.Printf("%d finding(s):\n", len(all))
	for _, f := range all {
		fmt.Printf("\n[%s] %s  (fp=%s)\n", f.Severity, f.RuleID, resultpolicy.Fingerprint(f))
		for _, b := range f.Bindings {
			fmt.Printf("  %-6s %-22s @ %s  ← %s\n", b.Name+":", b.Concept, b.Loc, b.LabelProvenance)
		}
		if len(f.Witness) > 0 {
			fmt.Printf("  witness: %s\n", strings.Join(f.Witness, " → "))
		}
		for _, ne := range f.NegationEvidence {
			mark := "-"
			if ne.Satisfied {
				mark = "+"
			}
			fmt.Printf("  %s %s: %s\n", mark, ne.Clause, ne.Detail)
		}
		for _, ec := range f.ReviewConditions {
			fmt.Printf("  review: %s", ec.Condition)
			if ec.Category != "" {
				fmt.Printf(" [%s]", ec.Category)
			}
			if ec.Evidence != "" {
				fmt.Printf(" — evidence: %s", ec.Evidence)
			}
			if ec.Assumption != "" {
				fmt.Printf(" — advisory: %s", ec.Assumption)
			}
			if ec.Confidence != "" {
				fmt.Printf(" — conf=%s", ec.Confidence)
			}
			fmt.Println()
		}
	}
	return nil
}

// ── vyql match ──────────────────────────────────────────────────────────────────────
// Show every node a binding labelled — what matched which concept.
// Groups by concept role (source/sink/control/other) so a missing concept label shows up
// as absent.

func cmdMatch(args []string) error {
	fs := newFlagSet("match")
	profileName := addProfile(fs)
	runOpts := addRunFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	stopProfiling, err := runOpts.apply()
	if err != nil {
		return err
	}
	defer stopProfiling()
	paths, err := requirePaths(fs, "vyql match <path>...")
	if err != nil {
		return err
	}
	applyProfile(paths, *profileName)
	g, _, err := buildGraph(paths)
	if err != nil {
		return err
	}
	if g == nil {
		fmt.Println("(no analyzable source)")
		return nil
	}
	onto := ontology.Seed()
	nodes, _ := g.AllNodes()
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].SortOrder() < nodes[j].SortOrder() })
	type row struct{ role, line string }
	var rows []row
	for _, n := range nodes {
		labels, _ := g.Labels(n.ID)
		for _, l := range labels {
			role := "control/other"
			switch {
			case isSourceConcept(onto, l.Concept):
				role = "source"
			case ontologyConceptKind(onto, l.Concept) == "sink":
				role = "sink"
			}
			prov := l.Provenance.Applicator
			if prov == "" {
				prov = "?"
			}
			rows = append(rows, row{role, fmt.Sprintf("  %s\t%s\t%s\t← %s (%s)",
				n.CalleeKey(), l.Concept, n.Prop("loc"), prov, l.Provenance.Fidelity)})
		}
	}
	for _, role := range []string{"source", "sink", "control/other"} {
		fmt.Printf("\n== %s ==\n", role)
		// One writer per section, so a column sizes to that section rather than
		// to the widest row anywhere in the output.
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		n := 0
		for _, r := range rows {
			if r.role == role {
				fmt.Fprintln(tw, r.line)
				n++
			}
		}
		_ = tw.Flush()
		if n == 0 {
			fmt.Println("  (none)")
		}
	}
	return nil
}

func isSourceConcept(onto *ontology.Ontology, c string) bool {
	return ontologyConceptKind(onto, c) == "source"
}

// ── vyql resolve ────────────────────────────────────────────────────────────────────
// Report interprocedural call resolution: every call site and whether vyql found a body for
// it (so cross-package / unresolved calls — where taint silently dies — are explicit).

func cmdResolve(args []string) error {
	fs := newFlagSet("resolve")
	profileName := addProfile(fs)
	runOpts := addRunFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	stopProfiling, err := runOpts.apply()
	if err != nil {
		return err
	}
	defer stopProfiling()
	paths, err := requirePaths(fs, "vyql resolve <path>...")
	if err != nil {
		return err
	}
	applyProfile(paths, *profileName)
	g, _, err := buildGraph(paths)
	if err != nil {
		return err
	}
	if g == nil {
		fmt.Println("(no analyzable source)")
		return nil
	}
	nodes, _ := g.AllNodes()
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].SortOrder() < nodes[j].SortOrder() })
	res, unres := 0, 0
	var unresolved []string
	for _, n := range nodes {
		if n.Type != "code.Call" {
			continue
		}
		key := n.CalleeKey()
		// a call is "resolved into a body" iff it has an outgoing FLOWS edge to a node OTHER
		// than its own arg slots — i.e. the lowering wired a callee ret → result. Calls with no
		// outgoing flow are library/external/cross-package (taint stops unless the engine treats
		// the call itself as a source/sink/control).
		es, _ := g.OutEdges(n.ID, "FLOWS")
		labelled := conceptsOf(g, n.ID) != ""
		if len(es) > 0 || labelled {
			res++
		} else {
			unres++
			unresolved = append(unresolved, fmt.Sprintf("  %s\t%s", key, n.Prop("loc")))
		}
	}
	fmt.Printf("call sites: %d resolved/recognized, %d unresolved (taint terminates)\n", res, unres)
	if len(unresolved) > 0 {
		fmt.Println("\nUNRESOLVED (no callee body, not a known source/sink/control):")
		sort.Strings(unresolved)
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		for i, u := range unresolved {
			if i >= 40 {
				fmt.Fprintf(tw, "  … and %d more\n", len(unresolved)-40)
				break
			}
			fmt.Fprintln(tw, u)
		}
		_ = tw.Flush()
	}
	return nil
}

// ── vyql graph ──────────────────────────────────────────────────────────────────────
// Dump the USG (nodes + edges). Reachability is `vyql trace`, which reports where taint
// stops as well as where it arrives.

func cmdGraph(args []string) error {
	fs := newFlagSet("graph")
	profileName := addProfile(fs)
	runOpts := addRunFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	stopProfiling, err := runOpts.apply()
	if err != nil {
		return err
	}
	defer stopProfiling()
	paths, err := requirePaths(fs, "vyql graph <path>...")
	if err != nil {
		return err
	}
	applyProfile(paths, *profileName)
	g, _, err := buildGraph(paths)
	if err != nil {
		return err
	}
	if g == nil {
		fmt.Println("(no analyzable source)")
		return nil
	}
	return printUSG(g)
}

func bindingDisplayKind(m bindings.Action) string {
	mappingKind := m.Kind
	if strings.HasPrefix(mappingKind, "presence_") {
		return strings.TrimPrefix(mappingKind, "presence_")
	}
	if m.Advisory || strings.HasPrefix(mappingKind, "advisory_") {
		return "advisory"
	}
	switch {
	case strings.HasPrefix(mappingKind, "issue"):
		return "issue"
	case strings.HasPrefix(mappingKind, "fact"):
		return "fact"
	case strings.HasPrefix(mappingKind, "flow"):
		return "propagate"
	}
	return strings.SplitN(mappingKind, "_", 2)[0]
}

func bindingNames() []string {
	var out []string
	for _, l := range []string{"go", "javascript", "java", "python", "ruby", "php", "csharp",
		"rust", "kotlin", "scala", "swift", "c", "cpp"} {
		if _, err := datadir.ReadVYQLDir("bindings/" + l); err == nil {
			out = append(out, l)
		}
	}
	return out
}

func bindingDefinitionSources(lang string) ([]parser.V2DefinitionSource, error) {
	files, err := datadir.ReadVYQLDir("bindings/" + lang)
	if err != nil {
		return nil, err
	}
	if extra, err := datadir.ReadVYQLDir("bindings/packages/" + lang); err == nil {
		files = append(files, extra...)
	}
	sources := make([]parser.V2DefinitionSource, 0, len(files))
	for _, file := range files {
		sources = append(sources, parser.V2DefinitionSource{Name: file.Name, Source: string(file.Data)})
	}
	return sources, nil
}

// ── vyql validate-binding ──────────────────────────────────────────────────────────
// Parse a binding file through the real VyQL parser and emit a compact public summary.

func cmdValidateBinding(args []string) error {
	fs := newFlagSet("definitions validate-binding")
	addDataFlag(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	// The path is positional, as it is elsewhere. With none given it reads stdin,
	// which is what makes this usable on a binding being edited.
	path := ""
	if rest := fs.Args(); len(rest) > 0 {
		path = rest[0]
	}
	file := &path
	var data []byte
	var err error
	if *file != "" {
		data, err = os.ReadFile(*file)
	} else {
		data, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		return err
	}
	sets, err := compileBindingSources(v2DefinitionSourcesForRules(ruleSourcesFromText("binding.vyql", string(data))))
	if err != nil {
		return fmt.Errorf("binding parse: %w", err)
	}
	type mappingSummary struct {
		Kind     string   `json:"kind"`
		Pattern  string   `json:"pattern"`
		Concept  string   `json:"concept,omitempty"`
		Packages []string `json:"packages,omitempty"`
	}
	type bindingSummary struct {
		Name          string           `json:"name"`
		MappingCount  int              `json:"mapping_count"`
		PackageBlocks []string         `json:"package_blocks,omitempty"`
		Mappings      []mappingSummary `json:"mappings"`
	}
	summary := struct {
		OK       bool             `json:"ok"`
		Bindings []bindingSummary `json:"bindings"`
	}{OK: true}
	for _, ad := range sets {
		item := bindingSummary{Name: ad.Name, MappingCount: len(ad.Mappings)}
		packageSeen := map[string]bool{}
		for _, m := range ad.Mappings {
			item.Mappings = append(item.Mappings, mappingSummary{
				Kind:     bindingDisplayKind(m),
				Pattern:  m.Pattern,
				Concept:  m.Concept,
				Packages: m.Packages,
			})
			for _, pkg := range m.Packages {
				if !packageSeen[pkg] {
					packageSeen[pkg] = true
					item.PackageBlocks = append(item.PackageBlocks, pkg)
				}
			}
		}
		sort.Strings(item.PackageBlocks)
		summary.Bindings = append(summary.Bindings, item)
	}
	if len(summary.Bindings) == 0 {
		return fmt.Errorf("binding parse: no v2 binding set found")
	}
	out, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

// ── vyql diff ───────────────────────────────────────────────────────────────────────
// Diff two `scan -format json` outputs by fingerprint: which findings appeared / disappeared.
// Use to PROVE a change is finding-preserving (e.g. an engine optimization) without eyeballing
// scorecards.

type jsonFinding struct {
	RuleID           string                     `json:"rule"`
	Severity         string                     `json:"severity"`
	Confidence       string                     `json:"confidence,omitempty"`
	WitnessKind      string                     `json:"witness_kind,omitempty"`
	FP               string                     `json:"fp"`
	Source           string                     `json:"source"`
	Sink             string                     `json:"sink"`
	Path             []string                   `json:"path,omitempty"`
	Noted            bool                       `json:"advisory_noted"`
	ReviewConditions []findings.ReviewCondition `json:"review_conditions,omitempty"`
}

func findingsJSON(all []*findings.Finding) []jsonFinding {
	out := make([]jsonFinding, 0, len(all))
	for _, f := range all {
		jf := jsonFinding{RuleID: f.RuleID, Severity: f.Severity, Confidence: f.Confidence, WitnessKind: f.WitnessKind, FP: resultpolicy.Fingerprint(f)}
		for _, b := range f.Bindings {
			if b.Name == "source" {
				jf.Source = b.Loc
			}
			if b.Name == "sink" {
				jf.Sink = b.Loc
			}
		}
		if jf.Source == "" && jf.Sink == "" && len(f.Bindings) == 1 {
			jf.Sink = f.Bindings[0].Loc
		}
		for _, ne := range f.NegationEvidence {
			if !ne.Satisfied && strings.Contains(ne.Clause, "advisory") {
				jf.Noted = true
			}
		}
		jf.Path = f.PathLocs
		jf.ReviewConditions = f.ReviewConditions
		out = append(out, jf)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FP < out[j].FP })
	return out
}

func cmdDiff(args []string) error {
	// A flagset with no flags of its own, so -h prints the usage on stdout and exits
	// 0 like every other command. Reading the arguments directly made -h a filename,
	// and asking for help exit non-zero.
	fs := newFlagSet("diff")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 2 {
		return usageWith("diff takes two scan reports",
			"usage: vyql diff <before.json> <after.json>  (each from `vyql scan -format json`)")
	}
	a, err := readFindingsJSON(rest[0])
	if err != nil {
		return err
	}
	b, err := readFindingsJSON(rest[1])
	if err != nil {
		return err
	}
	bySet := func(fs []jsonFinding) map[string]jsonFinding {
		m := map[string]jsonFinding{}
		for _, f := range fs {
			m[f.FP] = f
		}
		return m
	}
	am, bm := bySet(a), bySet(b)
	var removed, added []jsonFinding
	for fp, f := range am {
		if _, ok := bm[fp]; !ok {
			removed = append(removed, f)
		}
	}
	for fp, f := range bm {
		if _, ok := am[fp]; !ok {
			added = append(added, f)
		}
	}
	fmt.Printf("before: %d findings   after: %d findings\n", len(a), len(b))
	fmt.Printf("- removed: %d   + added: %d   (= %d unchanged)\n", len(removed), len(added), len(a)-len(removed))
	for _, f := range removed {
		fmt.Printf("  - [%s] %s → %s\n", f.RuleID, f.Source, f.Sink)
	}
	for _, f := range added {
		fmt.Printf("  + [%s] %s → %s\n", f.RuleID, f.Source, f.Sink)
	}
	if len(removed) == 0 && len(added) == 0 {
		fmt.Println("  (identical — finding-set preserved)")
	}
	return nil
}

func readFindingsJSON(path string) ([]jsonFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []jsonFinding
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("%s: %w (expected `vyql scan -format json` output)", path, err)
	}
	return out, nil
}

// ── vyql query ──────────────────────────────────────────────────────────────────────
// Ad-hoc graph queries: select nodes by predicate (type / concept / callee / loc substrings),
// then list them, count them, or show their edges. The general "grep the analysis graph" tool
// the other commands specialize. Predicates AND together; all are substring matches.
//
//	vyql query -type code.Call -call some.path <path>...       # nodes
//	vyql query -concept SomeConcept -edges <path>...           # + outgoing FLOWS
//	vyql query -concept SomeConcept -count <path>...           # just the count
//	vyql query -from SourceConcept -to SinkConcept <path>...   # reachability

func cmdQuery(args []string) error {
	fs := newFlagSet("query")
	typ := fs.String("type", "", "match node type substring")
	concept := fs.String("concept", "", "match concept label substring")
	call := fs.String("call", "", "match callee_path/method (substring, e.g. db.Query)")
	loc := fs.String("loc", "", "match location (substring, e.g. .go or a filename)")
	edges := fs.Bool("edges", false, "also print each matching node's outgoing edges")
	count := fs.Bool("count", false, "print only the number of matches")
	profileName := addProfile(fs)
	runOpts := addRunFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	stopProfiling, err := runOpts.apply()
	if err != nil {
		return err
	}
	defer stopProfiling()
	paths, err := requirePaths(fs, "vyql query [-type T] [-concept C] [-call P] [-loc L] [-edges] [-count] <path>...")
	if err != nil {
		return err
	}
	applyProfile(paths, *profileName)
	g, _, err := buildGraph(paths)
	if err != nil {
		return err
	}
	if g == nil {
		fmt.Println("(no analyzable source)")
		return nil
	}
	nodes, _ := g.AllNodes()
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].SortOrder() < nodes[j].SortOrder() })

	matched := 0
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer func() { _ = tw.Flush() }()
	for _, n := range nodes {
		if *typ != "" && !strings.Contains(n.Type, *typ) {
			continue
		}
		if *call != "" && !strings.Contains(n.CalleeKey(), *call) {
			continue
		}
		if *loc != "" && !strings.Contains(n.Prop("loc"), *loc) {
			continue
		}
		if *concept != "" && !conceptMatch(g, n.ID, *concept) {
			continue
		}
		matched++
		if *count {
			continue
		}
		fmt.Fprintln(tw, nodeCells(g, n))
		if *edges {
			for _, et := range edgeTypes {
				es, _ := g.OutEdges(n.ID, et)
				for _, e := range es {
					fmt.Fprintf(tw, "  --%s-->\t%s\t%s\t\n", et, e.Dst, locOf(g, e.Dst))
				}
			}
		}
	}
	_ = tw.Flush()
	if *count {
		fmt.Printf("%d\n", matched)
	} else {
		fmt.Printf("\n%d node(s) matched\n", matched)
	}
	return nil
}

// ── scan -stats profiler ──────────────────────────────────────────────────────────────

// printScanStats reports graph size plus taint-hub warnings (high FLOWS in/out-degree nodes —
// the shared callees that cause super-linear blowup). It uses the graph already built for the
// scan; rebuilding here would double the work for `scan --stats`.
func printScanStats(w io.Writer, g usg.Store, stats extract.Stats) {
	if g == nil {
		fmt.Fprintln(w, "\n[stats] no graph built")
		return
	}
	nodes, _ := g.AllNodes()
	edges, srcCount, sinkCount := 0, 0, 0
	type deg struct {
		id        string
		in, out   int
		loc, path string
	}
	indeg := map[string]int{}
	var nodeDeg []deg
	onto := ontology.Seed()
	for _, n := range nodes {
		out := 0
		for _, et := range edgeTypes {
			es, _ := g.OutEdges(n.ID, et)
			out += len(es)
			for _, e := range es {
				if et == "FLOWS" {
					indeg[e.Dst]++
				}
			}
		}
		edges += out
		if isSource(onto, g, n.ID) {
			srcCount++
		}
		if isSink(onto, g, n.ID) {
			sinkCount++
		}
		nodeDeg = append(nodeDeg, deg{id: n.ID, out: out, loc: n.Prop("loc"), path: n.CalleeKey()})
	}
	for i := range nodeDeg {
		nodeDeg[i].in = indeg[nodeDeg[i].id]
	}
	fmt.Fprintf(w, "[stats] files %d | nodes %d | edges %d | sources %d | sinks %d\n",
		stats.TotalFiles(), len(nodes), edges, srcCount, sinkCount)

	// taint hubs: high FLOWS in-degree = a callee shared by many call sites; the cross-product
	// of in×out paths through such a node is what makes path-enumeration blow up.
	sort.Slice(nodeDeg, func(i, j int) bool { return nodeDeg[i].in > nodeDeg[j].in })
	shown := false
	for _, d := range nodeDeg {
		if d.in >= 8 {
			if !shown {
				fmt.Fprintln(w, "[stats] taint hubs (FLOWS in-degree ≥ 8 — shared callees, blowup risk):")
				shown = true
			}
			fmt.Fprintf(w, "  in=%-4d out=%-3d %-26s %s\n", d.in, d.out, d.path, d.loc)
		}
	}
	if !shown {
		fmt.Fprintln(w, "[stats] no taint hubs (max in-degree below 8) — graph is well-isolated")
	}
}

// compileBindingSources parses a binding corpus and compiles it, the two steps `vyql
// bindings` and `validate-binding` both need. The parser resolves the language; the
// binding layer decides what the declarations label.
func compileBindingSources(raw []parser.V2DefinitionSource) ([]*bindings.Set, error) {
	parsed, keep, err := parser.ParseV2Sources(raw, lowerNonCoreV2DefinitionSource)
	if err != nil {
		return nil, err
	}
	return bindings.CompileSources(parsed, keep)
}
