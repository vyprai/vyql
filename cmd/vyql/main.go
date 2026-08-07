// Command vyql is a multi-language security scanner. It follows tainted data
// from where it enters a program to where it does something dangerous, and
// reports the neutralizing controls it looked for and did not find.
//
// The pipeline is: source -> frontend -> NIR -> lowering with import and type
// resolution -> framework bindings -> rule evaluation -> findings, rendered as
// a report, JSON or SARIF 2.1.0. Go has a native frontend; the other 21
// languages are parsed by tree-sitter.
//
// Usage:
//
//	vyql scan [flags] [path...]      # no path scans the working directory
//	  -fail-on   severity at or above which to exit non-zero (default: high)
//	  -format    text | sarif | json | graph-json
//	  -baseline  triaged findings to exclude from the report and the gate
//	  -coverage  report what was parsed, excluded and left unanalysed
//
//	vyql explain | trace | query | match | resolve | graph | diff | definitions
//
// Run vyql with no arguments for the full command list, or see
// https://github.com/vyprai/vyql for the guide.
//
// All security knowledge -- concepts, bindings, rule packs -- is loaded at
// startup from a vyql/ data directory rather than compiled in.
//
// The command is the supported interface. Everything under internal/ is
// deliberately not importable, so it stays free to change.
package main

import (
	"encoding/json"
	"errors"
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

	"github.com/vyprai/vyql/internal/datadir"
	"github.com/vyprai/vyql/internal/engine"
	"github.com/vyprai/vyql/internal/extract/frontend"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/extract/parsecache"
	"github.com/vyprai/vyql/internal/findings"
	"github.com/vyprai/vyql/internal/graphsync"
	"github.com/vyprai/vyql/internal/ontology"
	"github.com/vyprai/vyql/internal/parser"
	"github.com/vyprai/vyql/internal/profile"
	"github.com/vyprai/vyql/internal/resultpolicy"
	"github.com/vyprai/vyql/internal/risk"
	"github.com/vyprai/vyql/internal/sarif"
	"github.com/vyprai/vyql/internal/usg"
)

// version is the release version. A release build stamps it with
//
//	-ldflags "-X main.version=v1.2.3"
//
// so it is a var rather than a const. Builds that do not stamp it -- go install,
// go build, a local make -- report this default plus the VCS data the toolchain
// records, which is more honest than a version string nobody set.
var version = "0.1.0"

type compiledRuleSet struct {
	onto     *ontology.Ontology
	compiled []*engine.CompiledRule
}

var compiledRulesCache sync.Map // map[rules source]compiledRuleSet

func main() { os.Exit(vyqlMain()) }

// vyqlMain runs the CLI and RETURNS the process exit code rather than calling os.Exit.
// Everything that has to happen before the process goes away is deferred here — flushing
// the CPU and heap profiles above all. os.Exit does not run deferred functions, so exiting
// from inside wrote an empty cpu.prof and no heap profile at all on any scan that met its
// -fail-on threshold, which is to say on any codebase worth profiling.
func vyqlMain() (code int) {
	if len(os.Args) < 2 {
		usage()
		return 2
	}
	// Opt-in CPU profile for local performance work (explicit env, no behavior change):
	// VYQL_CPUPROFILE=/path/to/cpu.prof vyql scan ...
	if p := os.Getenv("VYQL_CPUPROFILE"); p != "" {
		f, err := os.Create(p)
		if err != nil {
			fmt.Fprintln(os.Stderr, "vyql: cpuprofile: "+err.Error())
			return 1
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			fmt.Fprintln(os.Stderr, "vyql: cpuprofile: "+err.Error())
			return 1
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
	// Registered last so it runs FIRST: the profile flushes above still happen.
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(os.Stderr, "vyql: "+fmt.Sprint(r))
			code = 1
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
	case "version", "--version", "-version":
		cmdVersion()
	default:
		usage()
		return 2
	}
	if err != nil {
		// A met -fail-on threshold is a successful scan with a non-zero status,
		// not a fault. It gets no "vyql:" diagnostic prefix and its own exit
		// code, so a pipeline can tell "this code has findings" apart from "the
		// scanner could not run".
		var gated *thresholdMet
		if errors.As(err, &gated) {
			fmt.Fprintln(os.Stderr, gated.Error())
			return gated.code
		}
		fmt.Fprintln(os.Stderr, "vyql: "+err.Error())
		return 1
	}
	return 0
}

// cmdScan is the primary `vyql scan` command: full pipeline → findings report.
func cmdScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	rulesPath := fs.String("rules", "", "load rule(s) from a .vyql file or directory (default: vyql/packs)")
	format := fs.String("format", "text", "output format: text | sarif | json | graph-json")
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
	failOn := fs.String("fail-on", defaultFailOn, "exit non-zero when a finding is at or above this severity: none | "+strings.Join(severityOrder, " | "))
	exitCode := fs.Int("exit-code", 1, "exit status to use when -fail-on is met")
	coverage := fs.Bool("coverage", false, "report what was parsed, excluded and left unanalysed")
	baseline := fs.String("baseline", "", "triaged findings to exclude from the report and the gate")
	baselineWrite := fs.String("baseline-write", "", "record every current finding as accepted, to adopt on an existing codebase")
	_ = fs.Parse(args)
	paths := fs.Args()
	if len(paths) == 0 {
		// Scanning the working directory is what a bare `vyql scan` almost always
		// means. Announced rather than assumed, so the report is never read as
		// covering somewhere else.
		fmt.Fprintln(os.Stderr, "path not specified, default to CWD")
		paths = []string{"."}
	}
	// Resolved before the scan runs. A typo here should cost nothing; finding
	// out after a multi-minute scan that the gate was never armed is the kind of
	// silent no-op this flag exists to prevent.
	failOnRank, err := parseFailOn(*failOn)
	if err != nil {
		return err
	}
	// Loaded up front for the same reason: a bad path or a bad verdict should
	// cost nothing, and finding out after the scan that the baseline never
	// applied is the silent no-op these checks exist to prevent.
	var baselineEntries map[string]baselineEntry
	if *baseline != "" {
		if baselineEntries, err = loadBaseline(*baseline); err != nil {
			return err
		}
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
		ShowStats:     *stats,
		IncludeFlags:  *allResults,
		FlagsOnly:     *flagsOnly,
		FlagCategory:  *flagCategory,
		FlagKind:      *flagKind,
		FlagLoc:       *flagLoc,
		GraphCache:    *incrementalCache,
		FailOnRank:    failOnRank,
		FailOnName:    strings.ToLower(strings.TrimSpace(*failOn)),
		ExitCode:      *exitCode,
		ShowCoverage:  *coverage,
		Baseline:      baselineEntries,
		BaselinePath:  *baseline,
		BaselineWrite: *baselineWrite,
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
	// Partition the budget ONCE across the pools that actually hold memory, and apply the
	// heap ceiling here too. Half to badger's off-heap block cache, a quarter to the on-heap
	// node-detail buffer, and the heap ceiling set to half — the detail buffer plus the
	// resident structural core live inside it. A scan whose core fits comfortably never
	// feels the limit; a tight limit sized to the whole flag would make the GC thrash
	// whenever the resident core neared it.
	lowering.DiskCacheBytes = n / 2
	lowering.DiskDetailBuf = n / 4
	lowering.DiskStorePath = dir
	prev := debug.SetMemoryLimit(-1)
	debug.SetMemoryLimit(n / 2)
	return func() {
		debug.SetMemoryLimit(prev)
		lowering.DiskStorePath = ""
		lowering.DiskCacheBytes, lowering.DiskDetailBuf = 0, 0
		_ = os.RemoveAll(dir) // best-effort temp cleanup
	}
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
	// Build gating. FailOnRank of 0 means -fail-on was not given, so the scan
	// reports and exits 0 exactly as it always has.
	FailOnRank int
	FailOnName string
	ExitCode   int
	// ShowCoverage prints the full parsed/excluded/unanalysed breakdown. The
	// warning about unanalysed files prints either way -- that one is not
	// something a reader should have to ask for.
	ShowCoverage bool
	// Baseline holds already-triaged findings by fingerprint. They are kept out
	// of both the report and the gate, so a run reports what is new.
	Baseline     map[string]baselineEntry
	BaselinePath string
	// BaselineWrite records the current findings instead of applying any.
	BaselineWrite string
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
	// graph-json serialises the live graph, which the whole-scan findings cache
	// cannot replay -- it stores findings, not the USG. Force the full pipeline,
	// exactly as the flag paths do.
	//
	// -stats belongs in this set because it reports node and edge counts, which
	// only exist while the graph is retained.
	needsGraph := wantsFlags || format == "graph-json" || opts.ShowStats
	if cache != nil && syncCollector == nil && !needsGraph {
		rkey = scanFingerprint(cache.Salt(), paths, ruleSources, prof.Name)
		if cs, ok := loadCachedScan(cache, rkey); ok {
			all, stats, hit = cs.Findings, scanStats{files: cs.Files, languages: cs.Languages, excluded: cs.Excluded, unmatched: cs.Unmatched}, true
		}
	}
	tk.mark("fingerprint")
	if !hit {
		if cache != nil && !opts.GraphCache {
			func() {
				restore := parsecache.SetShared(nil)
				defer restore()
				all, stats, graph, err = scanPathsWithProfileDemand(paths, ruleSources, prof.Name, !needsGraph)
			}()
		} else {
			all, stats, graph, err = scanPathsWithProfileDemand(paths, ruleSources, prof.Name, !needsGraph)
		}
		if err != nil {
			return err
		}
		if cache != nil && syncCollector == nil && !needsGraph {
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

	// Recording the current findings is an alternative to reporting them: it is
	// how a team adopts the scanner on a codebase that already has a backlog.
	if opts.BaselineWrite != "" {
		return writeBaseline(opts.BaselineWrite, all)
	}
	// Applied before output and before the gate, so a run reports and fails on
	// what is new rather than on what someone already looked at.
	var covered []*findings.Finding
	var staleBaseline []baselineEntry
	if len(opts.Baseline) > 0 {
		all, covered, staleBaseline = applyBaseline(all, opts.Baseline)
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
	case "graph-json":
		root := ""
		if len(paths) > 0 {
			root = paths[0]
		}
		doc := gjDocument{
			SchemaVersion: gjSchemaVersion,
			Tool:          gjTool{Name: "VyQL", Version: version},
			Concepts:      conceptLegend(),
			CodeMap:       gjCodeMap{Root: root},
		}
		if graph != nil {
			doc = buildGraphJSON(graph, all, sarifRulesMeta(ruleSources), root)
		}
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
		if opts.BaselinePath != "" {
			printBaselineSummary(opts.BaselinePath, covered, staleBaseline)
		}
	}
	if opts.ShowCoverage {
		printCoverage(stats)
	}
	if opts.ShowStats {
		fmt.Printf("[stats] profile %s (%s)\n", prof.Name, prof.Title)
		printScanStats(graph, stats)
	}
	// Gating is the last thing that happens: the report is already on stdout, so
	// a gated build still shows the operator what failed it.
	if opts.FailOnRank > 0 {
		if n, highest := gateFindings(all, opts.FailOnRank); n > 0 {
			return &thresholdMet{code: opts.ExitCode, count: n, highest: highest, failOn: opts.FailOnName}
		}
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
	} else {
		fmt.Printf("scanned %s — %d finding(s)\n", scanned, findingsN)
	}
	printCoverageWarning(stats)
}

// printCoverageWarning reports files no frontend read. It is unconditional: a
// report of zero findings over a tree that was mostly skipped reads as a clean
// bill of health, and the reader has no way to tell without this line.
func printCoverageWarning(stats scanStats) {
	n := stats.unmatchedTotal()
	if n == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "warning: %d file(s) matched no frontend and were not analysed (%s)\n",
		n, topKinds(stats.unmatched, 4))
	fmt.Fprintln(os.Stderr, "         run with -coverage for the breakdown")
}

// topKinds renders the most common file kinds, largest first, so the summary
// names what was missed rather than only how much.
func topKinds(m map[string]int, limit int) string {
	type kv struct {
		kind string
		n    int
	}
	var all []kv
	for k, v := range m {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].n != all[j].n {
			return all[i].n > all[j].n
		}
		return all[i].kind < all[j].kind
	})
	var parts []string
	for i, e := range all {
		if i == limit {
			parts = append(parts, fmt.Sprintf("+%d more", len(all)-limit))
			break
		}
		parts = append(parts, fmt.Sprintf("%s %d", e.kind, e.n))
	}
	return strings.Join(parts, ", ")
}

// printCoverage is the full account: what was read, what -exclude dropped, and
// what nothing claimed.
func printCoverage(stats scanStats) {
	fmt.Println("\ncoverage")
	if len(stats.languages) == 0 {
		fmt.Println("  parsed    nothing")
	} else {
		var parts []string
		for _, lg := range stats.languages {
			parts = append(parts, fmt.Sprintf("%s %d", lg, stats.files[lg]))
		}
		fmt.Printf("  parsed    %s\n", strings.Join(parts, " · "))
	}
	if stats.excluded > 0 {
		fmt.Printf("  excluded  %d file(s) dropped by -exclude\n", stats.excluded)
	}
	if n := stats.unmatchedTotal(); n > 0 {
		fmt.Printf("  unread    %d file(s) matched no frontend: %s\n", n, topKinds(stats.unmatched, 12))
	}
	// Depth is not uniform, and a clean result means different things across it.
	fmt.Println("  depth     java, python, javascript are the reference frontends;")
	fmt.Println("            other languages range down to call-and-concat coverage")
	fmt.Println("  note      a parse that partially fails still counts as parsed;")
	fmt.Println("            this does not yet report that")
}

// cmdVersion reports the version and everything needed to identify the exact
// build: the revision, whether the tree was dirty, the Go toolchain, and the
// platform. The VCS fields come from the toolchain, which stamps them for
// `go build` and `go install` from a repository.
func cmdVersion() {
	fmt.Printf("vyql %s\n", version)

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	settings := map[string]string{}
	for _, s := range info.Settings {
		settings[s.Key] = s.Value
	}
	if rev := settings["vcs.revision"]; rev != "" {
		dirty := ""
		if settings["vcs.modified"] == "true" {
			dirty = " (dirty)"
		}
		fmt.Printf("commit: %s%s\n", rev, dirty)
	}
	if t := settings["vcs.time"]; t != "" {
		fmt.Printf("built:  %s\n", t)
	}
	fmt.Printf("go:     %s\n", info.GoVersion)
	if osA, arch := settings["GOOS"], settings["GOARCH"]; osA != "" && arch != "" {
		fmt.Printf("platform: %s/%s\n", osA, arch)
	}
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
	fmt.Fprintln(os.Stderr, "  version    print the version, revision and build information")
}
