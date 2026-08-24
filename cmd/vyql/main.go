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
//	  -fail-on   severity at or above which to exit 3 (default: high; any new
//	             finding when -baseline is applied)
//	  -format    text | sarif | json | graph-json
//	  -exclude   skip paths matching this pattern; repeatable
//	  -baseline  triaged findings to exclude from the report and the gate
//	  -coverage  report what was parsed, excluded and left unanalysed
//
//	vyql explain | trace | query | match | resolve | graph | diff | definitions
//
// Exit codes are the same on every command: 0 the command run successfully, 1 vyql could
// not complete, 2 the invocation cannot mean anything, 3 the check ran and did
// not pass. stdout carries exactly one document in the requested format;
// diagnostics go to stderr.
//
// Run `vyql help` for the command list, `vyql help <command>` for one command's
// flags, or see https://github.com/vyprai/vyql for the guide.
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
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/vyprai/vyql/internal/bindings"

	"github.com/vyprai/vyql/internal/datadir"
	"github.com/vyprai/vyql/internal/engine"
	"github.com/vyprai/vyql/internal/extract"
	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
	"github.com/vyprai/vyql/internal/extract/parsecache"
	"github.com/vyprai/vyql/internal/findings"
	"github.com/vyprai/vyql/internal/graphjson"
	"github.com/vyprai/vyql/internal/graphsync"
	"github.com/vyprai/vyql/internal/ontology"
	"github.com/vyprai/vyql/internal/parser"
	"github.com/vyprai/vyql/internal/profile"
	"github.com/vyprai/vyql/internal/report"
	"github.com/vyprai/vyql/internal/resultpolicy"
	"github.com/vyprai/vyql/internal/review"
	"github.com/vyprai/vyql/internal/risk"
	"github.com/vyprai/vyql/internal/sarif"
	"github.com/vyprai/vyql/internal/timing"
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
		// Failing to name a command is a usage error, unlike asking for help.
		usageTo(os.Stderr)
		return exitUsage
	}
	// The data directory (ontology/taxonomy/packs) is required, and a missing one
	// panics deep in loading. Recover into a clean message rather than a stack
	// trace. The frontend registry builds itself on first use rather than at
	// package initialization, so this recover is reached for that case too.
	//
	// Profiles are flushed by the deferred cleanup each command installs from its
	// own -cpuprofile / -memprofile flags, which runs before this.
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(os.Stderr, "vyql: "+fmt.Sprint(r))
			code = exitFailed
		}
	}()

	cmd, args := os.Args[1], os.Args[2:]

	// Asking for help is not an error, so it prints on stdout and exits 0. Some
	// CI wrappers treat a non-zero help as a broken tool.
	switch cmd {
	case "help", "-h", "--help":
		if len(args) > 0 {
			return exitCodeFor(helpForCommand(args[0]))
		}
		usageTo(os.Stdout)
		return exitOK
	case "version", "--version", "-version", "-v":
		cmdVersion()
		return exitOK
	}

	run, ok := commands[cmd]
	if !ok {
		return exitCodeFor(unknownCommand(cmd))
	}
	// Before the command builds its flagset, because building one reads the data
	// directory and that decides which one the whole run loads.
	if err := applyDataFlagEarly(args); err != nil {
		return exitCodeFor(err)
	}
	// go install ships the engine only. Commands that load packs or the ontology
	// require a data directory, except help (which must answer without it),
	// cache, and update (which install or inspect the bundle themselves). On a
	// terminal, ensureDataDirectory offers to download the free channel before
	// failing.
	if commandNeedsData(cmd) && !wantsHelp(args) {
		if err := ensureDataDirectory(); err != nil {
			return exitCodeFor(err)
		}
	}
	// Installed for the commands that do work, not for help or version.
	watchForInterrupt()
	err := run(args)
	if errors.Is(err, errHelpRequested) {
		return exitOK
	}
	return exitCodeFor(err)
}

// commands is the dispatch table. It doubles as the set `help` lists and the
// candidate set an unknown command is matched against, so a command cannot be
// reachable without being discoverable.
var commands = map[string]func([]string) error{
	"scan":        cmdScan,
	"trace":       cmdTrace,
	"explain":     cmdExplain,
	"match":       cmdMatch,
	"resolve":     cmdResolve,
	"query":       cmdQuery,
	"graph":       cmdGraph,
	"definitions": cmdDefinitions,
	"diff":        cmdDiff,
	"cache":       cmdCache,
	"update":      cmdUpdate,
}

// movedCommands names where a retired command's job is done now. Each was retired
// because another surface answers the same question at least as well, so the message
// says which one rather than only that this name is gone.
var movedCommands = map[string]string{
	"bindings":         "a language's vocabulary is `vyql definitions -kind bindings -lang <lang>`",
	"validate-binding": "binding validation is `vyql definitions validate <path>`",
	"review":           "review flags are `vyql scan -flags only`",
}

func unknownCommand(cmd string) error {
	names := make([]string, 0, len(commands)+2)
	for name := range commands {
		names = append(names, name)
	}
	names = append(names, "help", "version")
	sort.Strings(names)
	hints := []string{}
	if s := suggest(names, cmd); len(s) > 0 {
		hints = append(hints, "did you mean: "+strings.Join(s, ", ")+"?")
	}
	if to, ok := movedCommands[cmd]; ok {
		hints = []string{to}
	}
	hints = append(hints, "run `vyql help` for the command list")
	return usageWith(fmt.Sprintf("unknown command %q", cmd), hints...)
}

// helpForCommand runs a command with -h so its own flagset renders the help,
// keeping one source for a command's flags rather than a second listing here.
func helpForCommand(name string) error {
	run, ok := commands[name]
	if !ok {
		return unknownCommand(name)
	}
	if err := run([]string{"-h"}); err != nil && !errors.Is(err, errHelpRequested) {
		return err
	}
	return nil
}

// cmdScan is the primary `vyql scan` command: full pipeline → findings report.
func cmdScan(args []string) error {
	fs := newFlagSet("scan")
	rulesPath := addRules(fs)
	format := addFormat(fs, "text", "sarif", "json", "graph-json")
	profileName := addProfile(fs)
	stats := addStats(fs)
	flagsMode := addEnum(fs, "flags", "off", "review flags in the report", []string{"off", "with", "only"})
	flagCategory := fs.String("flag-category", "all", "review flag category filter")
	flagKind := addEnum(fs, "flag-kind", "all", "review flag kind filter", []string{"all", "attention", "target", "check"})
	flagLoc := fs.String("flag-loc", "", "review flag location substring filter")
	maxRAM := fs.String("max-ram", "", "hard limit on memory use; the scan stops if it is passed, e.g. 8GB / 16GiB (default: 80% of available RAM)")
	bindingsPath := fs.String("bindings", "", "optional repo-local binding overlay directory")
	exclude := addExclude(fs)
	maxFileSize := fs.String("max-file-size", "", "skip source files larger than this during tree walks, e.g. 4MB (default 2MiB; 0 disables)")
	cacheDir := fs.String("cache", "auto", "persistent scan cache: auto | off | <dir>")
	cacheIncremental := fs.Bool("cache-incremental", false, "also populate per-file parse/lower/binding caches for edit-loop scans")
	failOn := fs.String("fail-on", defaultFailOn, "exit "+strconv.Itoa(exitCheckFail)+" when a finding is at or above this severity: none | "+strings.Join(severityOrder, " | "))
	coverage := fs.Bool("coverage", false, "report what was parsed, excluded and left unanalysed")
	baseline := fs.String("baseline", "", "triaged findings to exclude from the report and the gate")
	baselineWrite := fs.String("baseline-write", "", "record every current finding as accepted, to adopt on an existing codebase")
	runOpts := addRunFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	stopProfiling, err := runOpts.apply()
	if err != nil {
		return err
	}
	defer stopProfiling()
	paths := fs.Args()
	if len(paths) == 0 {
		// Scanning the working directory is what a bare `vyql scan` almost always
		// means. Announced rather than assumed, so the report is never read as
		// covering somewhere else.
		warnf("no path given; scanning the working directory")
		paths = []string{"."}
	}
	// A filter that cannot reach the output is a filter the operator expected to
	// work. Rejected here rather than accepted and ignored.
	if err := checkFlagFilters(flagsMode.value, *flagCategory, flagKind.value, *flagLoc); err != nil {
		return err
	}
	// Resolved before the scan runs. A typo here should cost nothing; finding
	// out after a multi-minute scan that the gate was never armed is the kind of
	// silent no-op this flag exists to prevent.
	failOnRank, err := parseFailOn(*failOn)
	if err != nil {
		return err
	}
	// Whether the operator asked for a threshold, as opposed to inheriting one.
	// A baseline run reads the two differently, and the flag's value alone cannot
	// tell them apart.
	explicitFailOn := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "fail-on" {
			explicitFailOn = true
		}
	})
	// Checked up front for the same reason: a combination that cannot mean what
	// the user hoped should cost nothing to discover.
	if err := checkBaselineFlags(*baseline, *baselineWrite); err != nil {
		return err
	}
	// Loaded up front for the same reason: a bad path or a bad verdict should
	// cost nothing, and finding out after the scan that the baseline never
	// applied is the silent no-op these checks exist to prevent.
	var baselineEntries map[string]baselineEntry
	failOnName := strings.ToLower(strings.TrimSpace(*failOn))
	if *baseline != "" {
		if baselineEntries, err = loadBaseline(*baseline); err != nil {
			return err
		}
		failOnRank, failOnName = gateForBaseline(failOnRank, failOnName, explicitFailOn)
	}
	cleanup := onExit(applyMaxRAM(*maxRAM))
	defer cleanup()
	defer armMemoryWatch(*maxRAM)()
	cacheCleanup := onExit(applyScanCache(*cacheDir))
	defer cacheCleanup()
	if v := strings.TrimSpace(*maxFileSize); v != "" {
		ceiling, err := parseBytes(v)
		if err != nil || ceiling < 0 {
			return fmt.Errorf("invalid -max-file-size %q (use e.g. 4MB, 512KiB, or 0 to disable)", v)
		}
		oldCeiling := treesitter.MaxFileBytes()
		treesitter.SetMaxFileBytes(ceiling)
		defer treesitter.SetMaxFileBytes(oldCeiling)
	}
	stats.apply()
	if stats.rulePhase() {
		ruleTimingOn = true
	}
	return run(paths, *rulesPath, format.value, *profileName, scanRunOptions{
		BindingOverlay: strings.TrimSpace(*bindingsPath),
		Excludes:       exclude.compiled,
		ShowStats:      stats.on,
		RuleTiming:     stats.rulePhase(),
		IncludeFlags:   flagsMode.value == "with",
		FlagsOnly:      flagsMode.value == "only",
		FlagCategory:   *flagCategory,
		FlagKind:       flagKind.value,
		FlagLoc:        *flagLoc,
		GraphCache:     *cacheIncremental,
		FailOnRank:     failOnRank,
		FailOnName:     failOnName,
		ShowCoverage:   *coverage,
		Baseline:       baselineEntries,
		BaselinePath:   *baseline,
		BaselineWrite:  *baselineWrite,
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

// applyMaxRAM honors --max-ram: it partitions the budget across the pools a scan provisions,
// applies the heap ceiling, and routes the graph through the disk-backed BadgerGraph store so
// node detail can leave RAM. Returns a cleanup func that removes the graph db. Overrides the
// auto-80% default; an invalid value is reported and ignored.
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
	dir, err := newGraphStoreDir()
	if err != nil {
		debug.SetMemoryLimit(n)
		lowering.UseIntStore = true // fallback: lower-footprint in-RAM store
		return noop
	}
	// The flag names a ceiling on the whole process, so every pool is carved out of the one
	// figure and the heap ceiling is that figure less a reserve for the memory the Go runtime
	// does not account for: tree-sitter's C parse trees and badger's mapped tables.
	//
	// The detail buffer gets a quarter. A buffer large enough to hold the whole scan's node
	// detail means nothing ever spills and no blob is ever read back, which is by far the
	// cheapest outcome.
	//
	// Badger's block cache gets a sixteenth and no more than half a gigabyte. It is ordinary Go
	// heap, because ristretto holds decoded blocks as Go values, so it is spent from the same
	// ceiling as the graph itself, and it only earns anything after a spill. A cache sized as a large
	// share of the budget fills the ceiling before a node is stored, leaving the collector to
	// run against memory it may not release.
	lowering.DiskCacheBytes = clampBytes(n/16, 64<<20, 512<<20)
	lowering.DiskDetailBuf = clampBytes(n/4, 64<<20, 4<<30)
	lowering.DiskStorePath = dir
	prev := debug.SetMemoryLimit(-1)
	debug.SetMemoryLimit(n - cgoReserve(n))
	return func() {
		debug.SetMemoryLimit(prev)
		lowering.DiskStorePath = ""
		lowering.DiskCacheBytes, lowering.DiskDetailBuf = 0, 0
		_ = os.RemoveAll(dir) // best-effort temp cleanup
	}
}

// clampBytes returns want, held between lo and hi. A budget small enough that a
// share of it would be useless still funds the pool at lo, and a budget large
// enough that a share of it would be wasteful stops at hi.
func clampBytes(want, lo, hi int64) int64 {
	if want < lo {
		return lo
	}
	if want > hi {
		return hi
	}
	return want
}

// cgoReserve is the part of the budget held back from the Go heap ceiling for
// memory the Go runtime never sees: tree-sitter's C parse trees, badger's
// mmapped tables, and the allocator's own fragmentation. An eighth, capped at
// 1 GiB, because the C-side cost tracks the largest file being parsed rather
// than the size of the budget.
func cgoReserve(n int64) int64 { return clampBytes(n/8, 32<<20, 1<<30) }

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
	bindings.SetActiveSources(p.ActiveSources())
	return p
}

func profileNames() string {
	// Registering a flag must not require the data directory: -data is the flag that
	// says where it is, and -h has to answer whether or not any of it is in place.
	if _, ok := datadir.Lookup(); !ok {
		return "generic"
	}
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
func scanPaths(paths []string, ruleSources []parser.V2DefinitionSource) ([]*findings.Finding, extract.Stats, usg.Store, error) {
	return scanPathsWithProfile(paths, ruleSources, "")
}

func scanPathsWithProfile(paths []string, ruleSources []parser.V2DefinitionSource, profileName string) ([]*findings.Finding, extract.Stats, usg.Store, error) {
	return scanPathsWithProfileDemand(paths, ruleSources, profileName, false, extract.Options{})
}

func scanPathsWithProfileDemand(paths []string, ruleSources []parser.V2DefinitionSource, profileName string, pruneBindings bool, build extract.Options) ([]*findings.Finding, extract.Stats, usg.Store, error) {
	rules, err := compiledRulesFor(ruleSources)
	if err != nil {
		return nil, extract.Stats{}, nil, err
	}
	var bindingConcepts map[string]bool
	if pruneBindings {
		bindingConcepts = engine.BindingConcepts(rules.onto, rules.compiled, profileName)
	}
	build.BindingConcepts = bindingConcepts
	build.Sync = syncCollector
	g, stats, err := extract.BuildGraph(paths, extract.SharedDeltaCache(), build)
	if err != nil {
		return nil, stats, nil, err
	}
	if g == nil {
		return nil, stats, nil, nil // recognized files, but nothing to analyze
	}
	eng := engine.New(rules.onto, g)
	var all []*findings.Finding
	tk := timing.New()
	var activeRules []*engine.CompiledRule
	for _, cr := range rules.compiled {
		if !engine.RuleActiveForProfile(cr, profileName) {
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
	tk.Mark("evaluate")
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
	// BindingOverlay and Excludes travel with the run rather than in package-level variables the
	// pipeline reads behind the caller's back.
	BindingOverlay string
	Excludes       extract.Excludes

	ShowStats bool
	// RuleTiming prints each rule's evaluation time, selected by -stats=rule.
	RuleTiming   bool
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
	tk := timing.New()
	// Graph-DB change-feed: when requested, build the per-module delta during the scan. Force the
	// full pipeline (skip the whole-scan findings cache) so the collector is populated.
	syncPath := syncOutputPath()
	if syncPath != "" {
		syncCollector = graphsync.New()
	}
	var rkey string
	var all []*findings.Finding
	var stats extract.Stats
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
		rkey = scanFingerprint(cache.Salt(), paths, ruleSources, prof.Name, opts.BindingOverlay, opts.Excludes)
		if cs, ok := loadCachedScan(cache, rkey); ok {
			all, stats, hit = cs.Findings, statsFromCachedScan(cs), true
			restoreExcludeCounts(cs, opts.Excludes)
		}
	}
	tk.Mark("fingerprint")
	if !hit {
		if cache != nil && !opts.GraphCache {
			func() {
				restore := parsecache.SetShared(nil)
				defer restore()
				all, stats, graph, err = scanPathsWithProfileDemand(paths, ruleSources, prof.Name, !needsGraph, extract.Options{BindingOverlay: opts.BindingOverlay, Excludes: opts.Excludes})
			}()
		} else {
			all, stats, graph, err = scanPathsWithProfileDemand(paths, ruleSources, prof.Name, !needsGraph, extract.Options{BindingOverlay: opts.BindingOverlay, Excludes: opts.Excludes})
		}
		if err != nil {
			return err
		}
		if cache != nil && syncCollector == nil && !needsGraph {
			storeCachedScan(cache, rkey, all, stats, opts.Excludes)
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

	// A run that only records is exempt from applying and from gating. What it
	// just wrote covers every finding, so applying it would report an empty scan
	// and leave the operator nothing to review, and failing on the backlog the
	// flag exists to absorb would make adoption impossible in the pipeline that
	// needs it. A run that also applies a baseline is not exempt: what it reports
	// is exactly what that baseline did not already cover.
	//
	// The test is BaselinePath, not the entry count. A baseline file with no
	// entries is still an applied baseline, and treating it as a recording run
	// would silently disable the gate.
	recordingOnly := opts.BaselineWrite != "" && opts.BaselinePath == ""

	// Recording the current findings is how a team adopts the scanner on a
	// codebase that already has a backlog. It happens before the report so a
	// path that cannot be written fails the run outright: a report that implies
	// the record was kept is worse than no report. The gate rank is withheld from
	// an adoption run, whose whole purpose is to record the backlog including
	// whatever meets the gate.
	if opts.BaselineWrite != "" {
		recordRank := opts.FailOnRank
		if recordingOnly {
			recordRank = 0
		}
		if err := writeBaseline(opts.BaselineWrite, all, opts.Baseline, recordRank); err != nil {
			return err
		}
	}
	// Applied before output and before the gate, so a run reports and fails on
	// what is new rather than on what someone already looked at.
	var covered []*findings.Finding
	var staleBaseline []baselineEntry
	if opts.BaselinePath != "" {
		all, covered, staleBaseline = applyBaseline(all, opts.Baseline)
	}

	// output
	var flags []review.Item
	if wantsFlags {
		if format == "sarif" {
			return fmt.Errorf("flags are supported with -format text or json")
		}
		flags = review.Filter(review.Collect(graph), opts.FlagCategory, opts.FlagKind, opts.FlagLoc)
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
		doc := graphjson.Document{
			SchemaVersion: graphjson.SchemaVersion,
			Tool:          graphjson.Tool{Name: "VyQL", Version: version},
			Concepts:      graphjson.ConceptLegend(),
			CodeMap:       graphjson.CodeMap{Root: root},
		}
		if graph != nil {
			doc = graphjson.Build(graph, all, sarifRulesMeta(ruleSources), root, version)
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
	// Diagnostics go to stderr in every format. stdout carries exactly one
	// document, so `scan -format sarif -coverage . > results.sarif` writes SARIF
	// rather than SARIF followed by a coverage report no parser accepts.
	if opts.ShowCoverage {
		printCoverage(os.Stderr, stats, opts.Excludes)
	}
	if opts.ShowStats {
		fmt.Fprintf(os.Stderr, "[stats] profile %s (%s)\n", prof.Name, prof.Title)
		printScanStats(os.Stderr, graph, stats)
	}
	// Gating is the last thing that happens: the report is already on stdout, so
	// a gated build still shows the operator what failed it.
	//
	// An adoption run is exempt. Every finding it reported was just accepted into
	// the baseline, and failing the build on the backlog the flag exists to
	// absorb would make adoption impossible in the pipeline that needs it. A run
	// that also applies a baseline gates normally, because what it reported is
	// what that baseline did not cover.
	if opts.FailOnRank > 0 && !recordingOnly {
		if n, highest := gateFindings(all, opts.FailOnRank); n > 0 {
			return thresholdMet(n, opts.FailOnName, highest)
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
		fmt.Printf("[%s] %s", it.s.Band, report.Finding(it.f, resultpolicy.Fingerprint(it.f)))
		for _, fac := range it.s.Factors {
			fmt.Printf("  · %s\n", fac.Witness)
		}
		fmt.Println()
	}
}

type scanAllJSON struct {
	Findings []jsonFinding `json:"findings"`
	Flags    []review.Item `json:"flags"`
}

type scanFlagsJSON struct {
	Flags []review.Item `json:"flags"`
}

func printScanFlags(rows []review.Item) {
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

func printSummaryWithFlags(stats extract.Stats, findingsN, flagsN int, includeFlags bool) {
	var parts []string
	for _, lg := range stats.Languages {
		parts = append(parts, fmt.Sprintf("%s:%d", lg, stats.Files[lg]))
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
func printCoverageWarning(stats extract.Stats) {
	n := stats.UnmatchedTotal()
	if n == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "warning: %d file(s) matched no frontend and were not analysed (%s)\n",
		n, topKinds(stats.Unmatched, 4))
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
// what nothing claimed. It writes to the caller's stream, which is stderr: it
// describes the run rather than being the document the run produced.
func printCoverage(w io.Writer, stats extract.Stats, excludes extract.Excludes) {
	fmt.Fprintln(w, "\ncoverage")
	if len(stats.Languages) == 0 {
		fmt.Fprintln(w, "  parsed    nothing")
	} else {
		var parts []string
		for _, lg := range stats.Languages {
			parts = append(parts, fmt.Sprintf("%s %d", lg, stats.Files[lg]))
		}
		fmt.Fprintf(w, "  parsed    %s\n", strings.Join(parts, " · "))
	}
	if stats.Excluded > 0 || len(excludes) > 0 {
		prunedDirs := 0
		for _, e := range excludes {
			prunedDirs += e.PrunedDirs
		}
		if prunedDirs > 0 {
			// A pruned directory is never descended, so its files are never
			// listed and cannot be counted. Reporting the directories is what
			// the walk actually knows, and claiming a file count it does not
			// have would be worse than naming the unit honestly.
			fmt.Fprintf(w, "  excluded  %d file(s) and %d director(ies) dropped by -exclude\n",
				stats.Excluded, prunedDirs)
		} else {
			fmt.Fprintf(w, "  excluded  %d file(s) dropped by -exclude\n", stats.Excluded)
		}
		// Per-pattern counts, because a pattern that excluded nothing is a filter
		// the operator believes is working. Excluding a directory this repository
		// happens not to have is legitimate in a shared config, so a zero is
		// marked rather than treated as an error.
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, e := range excludes {
			count := fmt.Sprintf("%d file(s)", e.Matched)
			if e.PrunedDirs > 0 {
				count = fmt.Sprintf("%d dir(s)", e.PrunedDirs)
			}
			note := ""
			if e.Matched == 0 && e.PrunedDirs == 0 {
				note = "\t← matched nothing"
			}
			fmt.Fprintf(tw, "              %s\t%s%s\n", e.Raw, count, note)
		}
		_ = tw.Flush()
	}
	if stats.Oversized > 0 {
		fmt.Fprintf(w, "  oversized %d file(s) skipped over the -max-file-size ceiling;\n", stats.Oversized)
		fmt.Fprintln(w, "            raise it or pass 0 to scan them")
	}
	if n := stats.UnmatchedTotal(); n > 0 {
		fmt.Fprintf(w, "  unread    %d file(s) matched no frontend: %s\n", n, topKinds(stats.Unmatched, 12))
	}
	// Depth is not uniform, and a clean result means different things across it.
	fmt.Fprintln(w, "  depth     java, python, javascript are the reference frontends;")
	fmt.Fprintln(w, "            other languages range down to call-and-concat coverage")
	fmt.Fprintln(w, "  note      a parse that partially fails still counts as parsed;")
	fmt.Fprintln(w, "            this does not yet report that")
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

// commandHelp is the one-line summary each command shows in the command list.
// Flags are not repeated here: `vyql help <command>` renders them from the
// command's own flagset, so this list cannot drift from what the flags are.
var commandHelp = []struct{ name, summary string }{
	{"scan", "run rules and report findings"},
	{"trace", "trace taint source→sink: the path, or where it dead-ends"},
	{"query", "list graph nodes by type, concept, callee or location"},
	{"explain", "print each finding's full proof tree and negation evidence"},
	{"match", "list every node a binding labelled, and which binding did it"},
	{"resolve", "report interprocedural call resolution"},
	{"graph", "dump the USG (nodes and edges)"},
	{"definitions", "inspect, search and validate the loaded VyQL definitions"},
	{"diff", "diff two `scan -format json` outputs by fingerprint"},
	{"cache", "inspect or clear the persistent scan cache"},
	{"update", "download or refresh the free definitions bundle from dl.vyprsec.ai"},
	{"version", "print the version, revision and build information"},
	{"help", "print this list, or `help <command>` for one command's flags"},
}

// usageTo writes the command list. The destination is the caller's: a requested
// help goes to stdout, a usage error to stderr.
func usageTo(w io.Writer) {
	fmt.Fprintf(w, "vyql %s — Vypr Query Language scanner\n\n", version)
	fmt.Fprintln(w, "usage: vyql <command> [flags] <path>...")
	fmt.Fprintln(w, "\ncommands:")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, c := range commandHelp {
		fmt.Fprintf(tw, "  %s\t%s\n", c.name, c.summary)
	}
	_ = tw.Flush()
	fmt.Fprintln(w, "\nrun `vyql help <command>` for a command's flags.")
}
