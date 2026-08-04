// Command vyql is the VyQL command-line scanner. It runs the full pipeline on
// real source: native frontend (go/ast) -> NIR -> shared lowering with
// import/type resolution -> framework bindings -> rule evaluation -> findings,
// rendered as a human report or SARIF 2.1.0.
//
// Usage:
//
//	vyql scan [flags] <path>...
//	  -rules <file|dir>   load rule(s) from .vyql file(s)
//	  -format text|sarif  output format (default: text)
//
// Other languages and a tree-sitter frontend are the documented next step; this
// build ships the native Go frontend.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/engine"
	"github.com/vyprai/vyql/extract/frontend"
	"github.com/vyprai/vyql/extract/lowering"
	"github.com/vyprai/vyql/extract/parsecache"
	"github.com/vyprai/vyql/findings"
	"github.com/vyprai/vyql/graphsync"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/profile"
	"github.com/vyprai/vyql/resultpolicy"
	"github.com/vyprai/vyql/risk"
	"github.com/vyprai/vyql/sarif"
	"github.com/vyprai/vyql/usg"
)

const version = "0.1.0"

type compiledRuleSet struct {
	onto     *ontology.Ontology
	compiled []*engine.CompiledRule
}

var compiledRulesCache sync.Map // map[rules source]compiledRuleSet

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	// Opt-in CPU profile for local performance work (explicit env, no behavior change):
	// VYQL_CPUPROFILE=/path/to/cpu.prof vyql scan ...
	if p := os.Getenv("VYQL_CPUPROFILE"); p != "" {
		f, err := os.Create(p)
		if err != nil {
			fmt.Fprintln(os.Stderr, "vyql: cpuprofile: "+err.Error())
			os.Exit(1)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			fmt.Fprintln(os.Stderr, "vyql: cpuprofile: "+err.Error())
			os.Exit(1)
		}
		defer pprof.StopCPUProfile()
	}
	// Opt-in heap profile for local memory work (explicit env, no behavior change):
	// VYQL_MEMPROFILE=/path/to/heap.prof vyql scan ...
	if p := os.Getenv("VYQL_MEMPROFILE"); p != "" {
		defer func() {
			f, err := os.Create(p)
			if err != nil {
				fmt.Fprintln(os.Stderr, "vyql: memprofile: "+err.Error())
				return
			}
			// The profile is written below, so a close failure can mean it was not
			// flushed -- say so rather than exiting quietly with a truncated file.
			defer func() {
				if cerr := f.Close(); cerr != nil {
					fmt.Fprintln(os.Stderr, "vyql: memprofile: "+cerr.Error())
				}
			}()
			runtime.GC()
			if err := pprof.WriteHeapProfile(f); err != nil {
				fmt.Fprintln(os.Stderr, "vyql: memprofile: "+err.Error())
			}
		}()
	}
	// the data dir (ontology/taxonomy/packs) is required; a missing one panics
	// deep in loading — recover into a clean message rather than a stack trace.
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(os.Stderr, "vyql: "+fmt.Sprint(r))
			os.Exit(1)
		}
	}()

	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "scan":
		err = cmdScan(args)
	case "trace":
		err = cmdTrace(args)
	case "explain":
		err = cmdExplain(args)
	case "match":
		err = cmdMatch(args)
	case "resolve":
		err = cmdResolve(args)
	case "query":
		err = cmdQuery(args)
	case "graph":
		err = cmdGraph(args)
	case "bindings":
		err = cmdBindings(args)
	case "definitions":
		err = cmdDefinitions(args)
	case "validate-binding":
		err = cmdValidateBinding(args)
	case "diff":
		err = cmdDiff(args)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vyql: "+err.Error())
		os.Exit(1)
	}
}

// cmdScan is the primary `vyql scan` command: full pipeline → findings report.
func cmdScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	rulesPath := fs.String("rules", "", "load rule(s) from a .vyql file or directory (default: vyql/packs)")
	format := fs.String("format", "text", "output format: text | sarif | json")
	profileName := fs.String("profile", "auto", "analysis profile: auto | "+profileNames())
	stats := fs.Bool("stats", false, "print scan profile: per-phase timing, node/edge counts, taint-hub warnings")
	allResults := fs.Bool("all", false, "include all result sections: findings and flags (json output becomes {findings, flags})")
	flagsOnly := fs.Bool("flags", false, "print flags only; replaces the old review command")
	flagCategory := fs.String("flag-category", "all", "flag category filter when flags are enabled")
	flagKind := fs.String("flag-kind", "all", "flag kind filter when flags are enabled: all | attention | target | check")
	flagLoc := fs.String("flag-loc", "", "flag location substring filter when flags are enabled")
	maxRAM := fs.String("max-ram", "", "soft RAM ceiling, e.g. 8GB / 16GiB (default: 80% of physical RAM)")
	bindingOverlay := fs.String("binding-overlay", "", "optional repo-local binding overlay directory")
	exclude := fs.String("exclude", "", "comma-separated path segments to skip, e.g. _vendor,node_modules,tests")
	cacheDir := fs.String("cache", "auto", "persistent scan cache: auto | off | <dir>")
	incrementalCache := fs.Bool("incremental-cache", false, "also populate per-file parse/lower/binding caches for edit-loop scans")
	_ = fs.Parse(args)
	paths := fs.Args()
	if len(paths) == 0 {
		usage()
		os.Exit(2)
	}
	cleanup := applyMaxRAM(*maxRAM)
	defer cleanup()
	cacheCleanup := applyScanCache(*cacheDir)
	defer cacheCleanup()
	oldOverlay := scanBindingOverlay
	scanBindingOverlay = strings.TrimSpace(*bindingOverlay)
	defer func() { scanBindingOverlay = oldOverlay }()
	oldExcludes := scanExcludes
	scanExcludes = parseExcludes(*exclude)
	defer func() { scanExcludes = oldExcludes }()
	return run(paths, *rulesPath, *format, *profileName, scanRunOptions{
		ShowStats:    *stats,
		IncludeFlags: *allResults,
		FlagsOnly:    *flagsOnly,
		FlagCategory: *flagCategory,
		FlagKind:     *flagKind,
		FlagLoc:      *flagLoc,
		GraphCache:   *incrementalCache,
	})
}

func applyScanCache(v string) func() {
	v = strings.TrimSpace(v)
	if v == "" || v == "auto" {
		base, err := os.UserCacheDir()
		if err != nil || base == "" {
			base = filepath.Join(os.TempDir(), "vyql-cache")
		}
		v = filepath.Join(base, "vyql", "scan-cache")
	}
	if v == "off" || v == "none" || v == "false" {
		return func() {}
	}
	if err := os.MkdirAll(v, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "vyql: scan cache disabled: %v\n", err)
		return func() {}
	}
	cache, err := parsecache.Open(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vyql: scan cache disabled: %v\n", err)
		return func() {}
	}
	restore := parsecache.SetShared(cache)
	return func() {
		restore()
		_ = cache.Close()
	}
}

// applyMaxRAM honors --max-ram: set the soft heap limit and route the graph
// through the disk-backed BadgerGraph store (graph on disk, RAM bounded by badger's cache, sized
// to ~half the budget) so a scan stays under the ceiling even when the graph exceeds it. Returns
// a cleanup func that removes the temporary graph db. Overrides the auto-80% default; an invalid
// value is reported and ignored.
func applyMaxRAM(v string) func() {
	noop := func() {}
	if v == "" {
		return noop
	}
	n, err := parseBytes(v)
	if err != nil || n <= 0 {
		fmt.Fprintf(os.Stderr, "vyql: invalid --max-ram %q (use e.g. 8GB, 16GiB)\n", v)
		return noop
	}
	dir, err := os.MkdirTemp("", "vyql-graph-")
	if err != nil {
		debug.SetMemoryLimit(n)
		lowering.UseIntStore = true // fallback: lower-footprint in-RAM store
		return noop
	}
	// Program-controlled budget: the graph lives on disk and RAM is bounded by badger's (off-heap)
	// cache, sized here — NOT by a tight GOMEMLIMIT, which would make the GC thrash whenever the
	// resident core approaches the limit. Most of the budget is the cache (the dominant, tunable
	// consumer); the resident structural core sits on top.
	lowering.DiskCacheBytes = n * 3 / 4
	lowering.DiskStorePath = dir
	return func() { _ = os.RemoveAll(dir) } // best-effort temp cleanup
}

// parseBytes parses a human size like "8GB", "512MiB", "2G", "1048576". Decimal (KB/MB/GB) and
// binary (KiB/MiB/GiB) units are accepted; a bare number is bytes.
func parseBytes(s string) (int64, error) {
	s = strings.TrimSpace(s)
	mult := int64(1)
	upper := strings.ToUpper(s)
	for _, u := range []struct {
		suf string
		m   int64
	}{
		{"KIB", 1 << 10}, {"MIB", 1 << 20}, {"GIB", 1 << 30}, {"TIB", 1 << 40},
		{"KB", 1e3}, {"MB", 1e6}, {"GB", 1e9}, {"TB", 1e12},
		{"K", 1 << 10}, {"M", 1 << 20}, {"G", 1 << 30}, {"T", 1 << 40},
		{"B", 1},
	} {
		if strings.HasSuffix(upper, u.suf) {
			mult = u.m
			s = strings.TrimSpace(s[:len(s)-len(u.suf)])
			break
		}
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, err
	}
	return int64(f * float64(mult)), nil
}

// applyProfile selects the analysis profile (explicit name or auto-detected),
// sets the active source families, and returns it for reporting.
func applyProfile(paths []string, name string) profile.Profile {
	profiles, err := profile.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "vyql: %v; using generic profile\n", err)
	}
	var p profile.Profile
	switch name {
	case "", "auto":
		p = profile.Detect(paths, profiles)
	default:
		var ok bool
		if p, ok = profile.ByName(profiles, name); !ok {
			fmt.Fprintf(os.Stderr, "vyql: unknown profile %q; using generic\n", name)
			p = profile.Profile{Name: "generic", Title: "Generic application"}
		}
	}
	frontend.SetActiveSources(p.ActiveSources())
	return p
}

func profileNames() string {
	profiles, err := profile.Load()
	if err != nil {
		return "generic"
	}
	var names []string
	for _, p := range profiles {
		names = append(names, p.Name)
	}
	return strings.Join(names, " | ")
}

// scanPaths runs the full pipeline (extract → lower → bindings → compile →
// evaluate) and returns the findings + a scan summary. Multi-language: each file
// is routed to its real frontend and the matching framework bindings.
func scanPaths(paths []string, ruleSources []parser.V2DefinitionSource) ([]*findings.Finding, scanStats, usg.Store, error) {
	return scanPathsWithProfile(paths, ruleSources, "")
}

func scanPathsWithProfile(paths []string, ruleSources []parser.V2DefinitionSource, profileName string) ([]*findings.Finding, scanStats, usg.Store, error) {
	return scanPathsWithProfileDemand(paths, ruleSources, profileName, false)
}

func scanPathsWithProfileDemand(paths []string, ruleSources []parser.V2DefinitionSource, profileName string, pruneBindings bool) ([]*findings.Finding, scanStats, usg.Store, error) {
	rules, err := compiledRulesFor(ruleSources)
	if err != nil {
		return nil, scanStats{}, nil, err
	}
	var bindingConcepts map[string]bool
	if pruneBindings {
		bindingConcepts = activeRuleBindingConcepts(rules, profileName)
	}
	g, stats, err := buildGraphWithOptions(paths, lowerCache(), graphBuildOptions{BindingConcepts: bindingConcepts})
	if err != nil {
		return nil, stats, nil, err
	}
	if g == nil {
		return nil, stats, nil, nil // recognized files, but nothing to analyze
	}
	eng := engine.New(rules.onto, g)
	var all []*findings.Finding
	tk := newTimer()
	ruleTimingOn := os.Getenv("VYQL_RULE_TIMING") != ""
	var activeRules []*engine.CompiledRule
	for _, cr := range rules.compiled {
		if !ruleActiveForProfile(cr, profileName) {
			continue
		}
		activeRules = append(activeRules, cr)
	}
	if err := eng.PrecomputeTaintFlows(activeRules); err != nil {
		return nil, stats, g, err
	}
	for _, cr := range activeRules {
		start := time.Now()
		got, err := eng.Evaluate(cr)
		if err != nil {
			return nil, stats, g, err
		}
		if ruleTimingOn {
			fmt.Fprintf(os.Stderr, "[rule] %-32s %7.1fms %6d finding(s)\n",
				scanRuleID(cr), float64(time.Since(start))/1e6, len(got))
		}
		all = append(all, got...)
	}
	tk.mark("evaluate")
	return all, stats, g, nil
}

func scanRuleID(cr *engine.CompiledRule) string {
	if cr == nil || cr.Rule == nil {
		return "<nil>"
	}
	if id, ok := cr.Rule.Meta["id"].(string); ok && strings.TrimSpace(id) != "" {
		return id
	}
	return cr.Rule.QualifiedName()
}

func activeRuleBindingConcepts(rules compiledRuleSet, profileName string) map[string]bool {
	out := map[string]bool{}
	add := func(concept string) {
		if strings.TrimSpace(concept) == "" {
			return
		}
		out[concept] = true
		for c := range rules.onto.Descendants(concept) {
			out[c] = true
		}
	}
	var addExpr func(parser.Expr)
	addException := func(ex parser.Exception) {
		switch x := ex.(type) {
		case parser.PathCoveredBy:
			add(x.Concept)
		case parser.EndpointCoveredBy:
			add(x.Concept)
		case parser.SameReceiverCoveredBy:
			add(x.Concept)
		case parser.SameScopeCoveredBy:
			add(x.Concept)
		case parser.GlobalCoveredBy:
			add(x.Concept)
		case parser.DominatesCoveredBy:
			add(x.Concept)
		case parser.PostDominatesCoveredBy:
			add(x.Concept)
		case parser.ExprException:
			addExpr(x.Expr)
		}
	}
	addExpr = func(expr parser.Expr) {
		switch x := expr.(type) {
		case parser.And:
			for _, part := range x.Parts {
				addExpr(part)
			}
		case parser.Or:
			for _, part := range x.Parts {
				addExpr(part)
			}
		case parser.Not:
			addExpr(x.Inner)
		case parser.SolverCall:
			for _, arg := range x.Args {
				add(arg.Ref.String())
			}
		case parser.HoldsAssetKind:
			add(x.Ref.String())
		case parser.Is:
			add(x.Concept)
			add(x.Ref.String())
		}
	}
	for _, cr := range rules.compiled {
		if !ruleActiveForProfile(cr, profileName) {
			continue
		}
		switch body := cr.Rule.Body.(type) {
		case *parser.FlowStmt:
			add(body.Src.Concept)
			add(body.Dst.Concept)
			for c := range cr.SourceConcepts {
				add(c)
			}
			for c := range cr.SinkConcepts {
				add(c)
			}
			for c := range cr.KillControls {
				add(c)
			}
		case *parser.MatchStmt:
			add(body.Concept)
			add(body.RelatedConcept)
		case *parser.OrderStmt:
			add(body.First.Concept)
			add(body.Second.Concept)
		}
		for _, cl := range cr.Rule.Clauses {
			if cl.Kind == "where" {
				addExpr(cl.Where)
			}
			if cl.Kind == "unless" {
				addException(cl.Unless)
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func ruleActiveForProfile(cr *engine.CompiledRule, profileName string) bool {
	if cr == nil || cr.Rule == nil {
		return false
	}
	required := stringListMeta(cr.Rule.Meta["required_profiles"])
	if len(required) == 0 || profileName == "" {
		return true
	}
	for _, name := range required {
		if name == profileName {
			return true
		}
	}
	return false
}

func stringListMeta(raw any) []string {
	switch xs := raw.(type) {
	case []string:
		return xs
	case []any:
		out := make([]string, 0, len(xs))
		for _, x := range xs {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if xs == "" {
			return nil
		}
		return []string{xs}
	default:
		return nil
	}
}

// sarifRulesMeta collects the per-rule metadata the SARIF writer publishes, keyed by
// the rule id findings carry. Consumers — GitHub code scanning, benchmark scorers —
// then read a finding's weakness class and severity from the tool's own output rather
// than parsing vyql/packs, whose layout and syntax are free to change.
//
// Best-effort: a rule set that fails to compile is a problem the scan itself reports,
// and emitting SARIF without rule metadata beats failing the run here.
func sarifRulesMeta(ruleSources []parser.V2DefinitionSource) map[string]map[string]any {
	rules, err := compiledRulesFor(ruleSources)
	if err != nil {
		return nil
	}
	out := make(map[string]map[string]any, len(rules.compiled))
	for _, cr := range rules.compiled {
		if cr.Rule == nil {
			continue
		}
		id, _ := cr.Rule.Meta["id"].(string)
		if strings.TrimSpace(id) == "" {
			continue
		}
		m := map[string]any{}
		if cwe, ok := cr.Rule.Meta["cwe"]; ok {
			m["cwe"] = cwe
		}
		sev := cr.Severity
		if s, ok := cr.Rule.Meta["severity"].(string); ok && s != "" {
			sev = s
		}
		if sev != "" {
			m["severity"] = sev
		}
		if len(m) > 0 {
			out[id] = m
		}
	}
	return out
}

func compiledRulesFor(ruleSources []parser.V2DefinitionSource) (compiledRuleSet, error) {
	cacheKey := compiledRulesCacheKey{src: ruleSourcesKey(ruleSources)}
	if cached, ok := compiledRulesCache.Load(cacheKey); ok {
		return cached.(compiledRuleSet), nil
	}
	decls, err := parser.ParseV2DefinitionSourcesSelected(v2DefinitionSourcesForRules(ruleSources), lowerNonCoreV2DefinitionSource)
	if err != nil {
		return compiledRuleSet{}, fmt.Errorf("rule parse: %w", err)
	}
	onto := ontology.Seed()
	compiled, cerrs := engine.CompileRules(decls, onto)
	if len(cerrs) != 0 {
		for _, e := range cerrs {
			fmt.Fprintln(os.Stderr, "rule error: "+e.Error())
		}
		return compiledRuleSet{}, fmt.Errorf("%d rule(s) failed to compile", len(cerrs))
	}
	rules := compiledRuleSet{onto: onto, compiled: compiled}
	actual, _ := compiledRulesCache.LoadOrStore(cacheKey, rules)
	return actual.(compiledRuleSet), nil
}

type compiledRulesCacheKey struct {
	src string
}

type scanRunOptions struct {
	ShowStats    bool
	IncludeFlags bool
	FlagsOnly    bool
	FlagCategory string
	FlagKind     string
	FlagLoc      string
	GraphCache   bool
}

func (o scanRunOptions) wantsFlags() bool {
	return o.IncludeFlags || o.FlagsOnly || o.FlagCategory != "" && o.FlagCategory != "all" || o.FlagKind != "" && o.FlagKind != "all" || o.FlagLoc != ""
}

func run(paths []string, rulesPath, format, profileName string, opts scanRunOptions) error {
	prof := applyProfile(paths, profileName)
	ruleSources, err := loadRules(rulesPath)
	if err != nil {
		return err
	}
	// whole-scan result cache: if an explicit process cache exists and nothing the output depends on
	// changed — no source file edit and no vyql/ data change — replay the cached findings and
	// skip the pipeline entirely. On a miss, the per-file parse cache still makes the rebuild
	// reparse only the files that actually changed.
	cache := parsecache.Shared()
	tk := newTimer()
	// Graph-DB change-feed: when requested, build the per-module delta during the scan. Force the
	// full pipeline (skip the whole-scan findings cache) so the collector is populated.
	syncPath := syncOutputPath()
	if syncPath != "" {
		syncCollector = graphsync.New()
	}
	var rkey string
	var all []*findings.Finding
	var stats scanStats
	var graph usg.Store
	hit := false
	wantsFlags := opts.wantsFlags()
	if cache != nil && syncCollector == nil && !wantsFlags {
		rkey = scanFingerprint(cache.Salt(), paths, ruleSources, prof.Name)
		if cs, ok := loadCachedScan(cache, rkey); ok {
			all, stats, hit = cs.Findings, scanStats{files: cs.Files, languages: cs.Languages}, true
		}
	}
	tk.mark("fingerprint")
	if !hit {
		if cache != nil && !opts.GraphCache {
			func() {
				restore := parsecache.SetShared(nil)
				defer restore()
				all, stats, graph, err = scanPathsWithProfileDemand(paths, ruleSources, prof.Name, !wantsFlags)
			}()
		} else {
			all, stats, graph, err = scanPathsWithProfileDemand(paths, ruleSources, prof.Name, !wantsFlags)
		}
		if err != nil {
			return err
		}
		if cache != nil && syncCollector == nil && !wantsFlags {
			storeCachedScan(cache, rkey, all, stats)
		}
	}
	if syncPath != "" {
		n, e, l, d, serr := writeSyncDelta(syncPath)
		if serr != nil {
			return fmt.Errorf("graph sync: %w", serr)
		}
		fmt.Fprintf(os.Stderr, "[sync] wrote %s: %d node, %d edge, %d label upserts; %d module tombstones\n",
			syncPath, n, e, l, d)
	}

	// output
	var flags []reviewItem
	if wantsFlags {
		if format == "sarif" {
			return fmt.Errorf("flags are supported with -format text or json")
		}
		flags = filterReviewItems(collectReviewItems(graph), opts.FlagCategory, opts.FlagKind, opts.FlagLoc)
	}
	switch format {
	case "sarif":
		doc := sarif.ToSARIF(all, version, sarifRulesMeta(ruleSources))
		b, _ := json.MarshalIndent(doc, "", "  ")
		fmt.Println(string(b))
	case "json":
		var payload any = findingsJSON(all)
		if opts.FlagsOnly {
			payload = scanFlagsJSON{Flags: flags}
		} else if wantsFlags {
			payload = scanAllJSON{Findings: findingsJSON(all), Flags: flags}
		}
		b, _ := json.MarshalIndent(payload, "", "  ")
		fmt.Println(string(b))
	default:
		fmt.Printf("analysis profile: %s (%s)\n\n", prof.Title, prof.Name)
		if !opts.FlagsOnly {
			printReport(all)
			if wantsFlags {
				fmt.Println()
			}
		}
		if wantsFlags {
			printScanFlags(flags)
		}
		printSummaryWithFlags(stats, len(all), len(flags), wantsFlags)
	}
	if opts.ShowStats {
		fmt.Printf("[stats] profile %s (%s)\n", prof.Name, prof.Title)
		printScanStats(graph, stats)
	}
	return nil
}

func loadRules(path string) ([]parser.V2DefinitionSource, error) {
	if path == "" {
		// Default scans load authored policies before the standalone rule packs.
		return loadDefaultRuleSources()
	}
	var out []parser.V2DefinitionSource
	policies, err := loadRuleSourcesUnder(filepath.Join(datadir.Root(), "policies"))
	if err != nil {
		return nil, err
	}
	out = append(out, policies...)
	sources, err := loadRuleSourcesUnder(path)
	if err != nil {
		return nil, err
	}
	out = append(out, sources...)
	return out, nil
}

func loadDefaultRuleSources() ([]parser.V2DefinitionSource, error) {
	var out []parser.V2DefinitionSource
	for _, dir := range []string{
		filepath.Join(datadir.Root(), "policies"),
		filepath.Join(datadir.Root(), "packs"),
	} {
		sources, err := loadRuleSourcesUnder(dir)
		if err != nil {
			return nil, err
		}
		out = append(out, sources...)
	}
	return out, nil
}

func loadRuleSourcesUnder(path string) ([]parser.V2DefinitionSource, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return []parser.V2DefinitionSource{{Name: sourceNameForPath(path), Source: string(b)}}, nil
	}
	var out []parser.V2DefinitionSource
	err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".vyql") {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			out = append(out, parser.V2DefinitionSource{Name: sourceNameForPath(p), Source: string(b)})
		}
		return nil
	})
	return out, err
}

func sourceNameForPath(path string) string {
	if rel, err := filepath.Rel(datadir.Root(), path); err == nil && !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel) {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(path)
}

func v2DefinitionSourcesForRules(ruleSources []parser.V2DefinitionSource) []parser.V2DefinitionSource {
	var out []parser.V2DefinitionSource
	if files, err := datadir.ReadVYQLDir("ontology/concepts"); err == nil {
		for _, file := range files {
			out = append(out, parser.V2DefinitionSource{Name: file.Name, Source: string(file.Data)})
		}
	}
	if files, err := datadir.ReadVYQLDir("ontology/threatkinds"); err == nil {
		for _, file := range files {
			out = append(out, parser.V2DefinitionSource{Name: file.Name, Source: string(file.Data)})
		}
	}
	if !v2SourcesContainPrefix(ruleSources, "policies/") {
		if files, err := datadir.ReadVYQLDir("policies"); err == nil {
			for _, file := range files {
				out = append(out, parser.V2DefinitionSource{Name: file.Name, Source: string(file.Data)})
			}
		}
	}
	out = append(out, ruleSources...)
	return out
}

func v2SourcesContainPrefix(sources []parser.V2DefinitionSource, prefix string) bool {
	for _, source := range sources {
		if strings.HasPrefix(source.Name, prefix) {
			return true
		}
	}
	return false
}

func ruleSourcesFromText(name, src string) []parser.V2DefinitionSource {
	return parser.V2DefinitionSourcesFromText(name, src)
}

func lowerNonCoreV2DefinitionSource(src parser.V2DefinitionSource) bool {
	return !strings.HasPrefix(src.Name, "ontology/")
}

func printReport(fs []*findings.Finding) {
	if len(fs) == 0 {
		fmt.Println("No findings.")
		return
	}
	type scored struct {
		f *findings.Finding
		s risk.Score
	}
	items := make([]scored, 0, len(fs))
	for _, f := range fs {
		items = append(items, scored{f, risk.Prioritize(f)})
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].s.Total > items[j].s.Total })

	fmt.Printf("%d finding(s):\n\n", len(fs))
	for _, it := range items {
		fmt.Printf("[%s] %s", it.s.Band, it.f.RenderWithFingerprint(resultpolicy.Fingerprint(it.f)))
		for _, fac := range it.s.Factors {
			fmt.Printf("    · %s\n", fac.Witness)
		}
		fmt.Println()
	}
}

type scanAllJSON struct {
	Findings []jsonFinding `json:"findings"`
	Flags    []reviewItem  `json:"flags"`
}

type scanFlagsJSON struct {
	Flags []reviewItem `json:"flags"`
}

func printScanFlags(rows []reviewItem) {
	if len(rows) == 0 {
		fmt.Println("No flags.")
		return
	}
	fmt.Printf("%d flag(s):\n", len(rows))
	for _, r := range rows {
		fmt.Printf("\nFLAG %-11s %s @ %s", r.Category, r.Concept, r.Loc)
		if r.Call != "" {
			fmt.Printf("  call=%s", r.Call)
		}
		if r.Provenance != "" {
			fmt.Printf("  via=%s", r.Provenance)
		}
		fmt.Println()
		if len(r.Expected) > 0 {
			fmt.Printf("  expects: %s\n", strings.Join(r.Expected, ", "))
		}
		if r.Review != "" {
			fmt.Printf("  review: %s\n", r.Review)
		}
	}
}

// printSummary reports what was scanned (languages + file counts) and the total.
func printSummary(stats scanStats, n int) {
	printSummaryWithFlags(stats, n, 0, false)
}

func printSummaryWithFlags(stats scanStats, findingsN, flagsN int, includeFlags bool) {
	var parts []string
	for _, lg := range stats.languages {
		parts = append(parts, fmt.Sprintf("%s:%d", lg, stats.files[lg]))
	}
	scanned := "no source"
	if len(parts) > 0 {
		scanned = strings.Join(parts, " ")
	}
	if includeFlags {
		fmt.Printf("scanned %s — %d finding(s), %d flag(s)\n", scanned, findingsN, flagsN)
		return
	}
	fmt.Printf("scanned %s — %d finding(s)\n", scanned, findingsN)
}

func usage() {
	fmt.Fprintln(os.Stderr, "vyql "+version+" — Vypr Query Language scanner")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "usage: vyql <command> [flags] <path>...")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "commands:")
	fmt.Fprintln(os.Stderr, "  scan       run rules and report findings/flags   [-rules -format text|sarif|json -profile -stats -all -flags -exclude _vendor,…]")
	fmt.Fprintln(os.Stderr, "  trace      trace taint source→sink; show the path or where it dead-ends   [-from -to]")
	fmt.Fprintln(os.Stderr, "  query      query the analysis graph by predicate   [-type -concept -call -loc -edges -count | -from -to]")
	fmt.Fprintln(os.Stderr, "  explain    run rules and print each finding's full proof tree + negation evidence")
	fmt.Fprintln(os.Stderr, "  match      list every node a binding labelled (what matched which concept)")
	fmt.Fprintln(os.Stderr, "  resolve    report interprocedural call resolution (which calls are unresolved)")
	fmt.Fprintln(os.Stderr, "  graph      dump the USG (nodes+edges), or -taint reachability")
	fmt.Fprintln(os.Stderr, "  bindings   list a binding set's source/sink/check/issue/advisory vocabulary   [-lang go]")
	fmt.Fprintln(os.Stderr, "  definitions inspect loaded VyQL concepts/rules/bindings/reviews; explain <concept|binding> traces a label's source; check-v2 verifies v2 definitions")
	fmt.Fprintln(os.Stderr, "  validate-binding parse and summarize a VyQL binding file   [-file binding.vyql]")
	fmt.Fprintln(os.Stderr, "  diff       diff two `scan -format json` outputs by fingerprint")
}
