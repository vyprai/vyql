// Command vyql is the VyQL command-line scanner. It runs the full pipeline on
// real source: native frontend (go/ast) -> NIR -> shared lowering with
// import/type resolution -> framework adapters -> rule evaluation -> findings,
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
	"runtime/debug"
	"sort"
	"strconv"
	"strings"

	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/engine"
	"github.com/vyprai/vyql/extract/frontend"
	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/lowering"
	"github.com/vyprai/vyql/extract/parsecache"
	"github.com/vyprai/vyql/findings"
	"github.com/vyprai/vyql/graphsync"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/profile"
	"github.com/vyprai/vyql/risk"
	"github.com/vyprai/vyql/sarif"
	"github.com/vyprai/vyql/usg"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
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
	case "adapters":
		err = cmdAdapters(args)
	case "definitions":
		err = cmdDefinitions(args)
	case "validate-adapter":
		err = cmdValidateAdapter(args)
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
	format := fs.String("format", "text", "output format: text | sarif | json | graph-json")
	profileName := fs.String("profile", "auto", "analysis profile: auto | "+profileNames())
	stats := fs.Bool("stats", false, "print scan profile: per-phase timing, node/edge counts, taint-hub warnings")
	allResults := fs.Bool("all", false, "include all result sections: findings and flags (json output becomes {findings, flags})")
	flagsOnly := fs.Bool("flags", false, "print flags only; replaces the old review command")
	flagCategory := fs.String("flag-category", "all", "flag category filter when flags are enabled")
	flagKind := fs.String("flag-kind", "all", "flag kind filter when flags are enabled: all | attention | target | check")
	flagLoc := fs.String("flag-loc", "", "flag location substring filter when flags are enabled")
	maxRAM := fs.String("max-ram", "", "soft RAM ceiling, e.g. 8GB / 16GiB (default: 80% of physical RAM)")
	exclude := fs.String("exclude", "", "comma-separated glob patterns to skip, layered on the built-in deps/build skips (e.g. test,examples,*.spec.js)")
	adapterOverlay := fs.String("adapter-overlay", "", "optional repo-local adapter overlay directory")
	_ = fs.Parse(args)
	treesitter.SetExcludes(strings.Split(*exclude, ","))
	paths := fs.Args()
	if len(paths) == 0 {
		usage()
		os.Exit(2)
	}
	cleanup := applyMaxRAM(*maxRAM)
	defer cleanup()
	oldOverlay := scanAdapterOverlay
	scanAdapterOverlay = strings.TrimSpace(*adapterOverlay)
	defer func() { scanAdapterOverlay = oldOverlay }()
	return run(paths, *rulesPath, *format, *profileName, scanRunOptions{
		ShowStats:    *stats,
		IncludeFlags: *allResults,
		FlagsOnly:    *flagsOnly,
		FlagCategory: *flagCategory,
		FlagKind:     *flagKind,
		FlagLoc:      *flagLoc,
	})
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
	return func() { os.RemoveAll(dir) }
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
	profiles, _ := profile.Load()
	var p profile.Profile
	switch {
	case name == "" || name == "auto":
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
	profiles, _ := profile.Load()
	var names []string
	for _, p := range profiles {
		names = append(names, p.Name)
	}
	return strings.Join(names, " | ")
}

// scanPaths runs the full pipeline (extract → lower → adapters → compile →
// evaluate) and returns the findings + a scan summary + the lowered graph. Multi-language:
// each file is routed to its real frontend and the matching framework adapters.
func scanPaths(paths []string, rulesSrc string) ([]*findings.Finding, scanStats, usg.Store, error) {
	all, g, _, stats, err := scanPathsFull(paths, rulesSrc)
	return all, stats, g, err
}

// scanPathsFull is scanPaths plus the per-rule meta (keyed by the finding's RuleID), which
// the graph-json export needs for CWE. Same pipeline — it just retains the rule meta map.
func scanPathsFull(paths []string, rulesSrc string) ([]*findings.Finding, usg.Store, map[string]map[string]any, scanStats, error) {
	g, stats, err := buildGraph(paths)
	if err != nil {
		return nil, nil, nil, stats, err
	}
	if g == nil {
		return nil, nil, nil, stats, nil // recognized files, but nothing to analyze
	}
	onto := ontology.Seed()
	decls, err := parser.Parse(rulesSrc)
	if err != nil {
		return nil, nil, nil, stats, fmt.Errorf("rule parse: %w", err)
	}
	compiled, cerrs := engine.CompileRules(decls, onto)
	if len(cerrs) != 0 {
		for _, e := range cerrs {
			fmt.Fprintln(os.Stderr, "rule error: "+e.Error())
		}
		return nil, nil, nil, stats, fmt.Errorf("%d rule(s) failed to compile", len(cerrs))
	}
	eng := engine.New(onto, g)
	var all []*findings.Finding
	meta := map[string]map[string]any{}
	tk := newTimer()
	for _, cr := range compiled {
		id, _ := cr.Rule.Meta["id"].(string)
		if id == "" {
			id = cr.Rule.QualifiedName()
		}
		meta[id] = cr.Rule.Meta
		got, err := eng.Evaluate(cr)
		if err != nil {
			return nil, nil, nil, stats, err
		}
		all = append(all, got...)
	}
	tk.mark("evaluate")
	return all, g, meta, stats, nil
}

type scanRunOptions struct {
	ShowStats    bool
	IncludeFlags bool
	FlagsOnly    bool
	FlagCategory string
	FlagKind     string
	FlagLoc      string
}

func (o scanRunOptions) wantsFlags() bool {
	return o.IncludeFlags || o.FlagsOnly || o.FlagCategory != "" && o.FlagCategory != "all" || o.FlagKind != "" && o.FlagKind != "all" || o.FlagLoc != ""
}

func run(paths []string, rulesPath, format, profileName string, opts scanRunOptions) error {
	prof := applyProfile(paths, profileName)
	src, err := loadRules(rulesPath)
	if err != nil {
		return err
	}
	var all []*findings.Finding
	var stats scanStats
	var graph usg.Store
	var ruleMeta map[string]map[string]any
	wantsFlags := opts.wantsFlags()

	if format == "graph-json" {
		// graph-json needs the live graph + per-rule meta; the whole-scan findings cache can't
		// serve those, so always run the full pipeline for it (no cache replay).
		all, graph, ruleMeta, stats, err = scanPathsFull(paths, src)
		if err != nil {
			return err
		}
	} else {
		// whole-scan result cache (opt-in via $VYQL_CACHE): if nothing the output depends on
		// changed — no source file edit and no vyql/ data change — replay the cached findings and
		// skip the pipeline entirely. On a miss, the per-file parse cache still makes the rebuild
		// reparse only the files that actually changed. Flags need the live graph, so they also
		// bypass the findings cache.
		cache := parsecache.Shared()
		tk := newTimer()
		// Graph-DB change-feed: when requested, build the per-module delta during the scan. Force
		// the full pipeline (skip the whole-scan findings cache) so the collector is populated.
		syncPath := syncOutputPath()
		if syncPath != "" {
			syncCollector = graphsync.New()
		}
		var rkey string
		hit := false
		if cache != nil && syncCollector == nil && !wantsFlags {
			rkey = scanFingerprint(cache.Salt(), paths, src, prof.Name)
			if cs, ok := loadCachedScan(cache, rkey); ok {
				all, stats, hit = cs.Findings, scanStats{files: cs.Files, languages: cs.Languages}, true
			}
		}
		tk.mark("fingerprint")
		if !hit {
			all, stats, graph, err = scanPaths(paths, src)
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
		doc := sarif.ToSARIF(all, version, nil)
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
	case "graph-json":
		root := ""
		if len(paths) > 0 {
			root = paths[0]
		}
		var doc gjDocument
		if graph != nil {
			doc = buildGraphJSON(graph, all, ruleMeta, root)
		} else {
			doc = gjDocument{SchemaVersion: gjSchemaVersion, Tool: gjTool{Name: "VyQL", Version: version}, Concepts: conceptLegend(), CodeMap: gjCodeMap{Root: root}}
		}
		b, _ := json.MarshalIndent(doc, "", "  ")
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

func loadRules(path string) (string, error) {
	if path == "" {
		// default: the standalone rule packs under <data root>/packs
		path = filepath.Join(datadir.Root(), "packs")
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		b, err := os.ReadFile(path)
		return string(b), err
	}
	var sb strings.Builder
	err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".vyql") {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			sb.Write(b)
			sb.WriteString("\n")
		}
		return nil
	})
	return sb.String(), err
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
		fmt.Printf("[%s] %s", it.s.Band, it.f.Render())
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
	fmt.Fprintln(os.Stderr, "  scan       run rules and report findings/flags   [-rules -format text|sarif|json|graph-json -profile -stats -all -flags -exclude]")
	fmt.Fprintln(os.Stderr, "  trace      trace taint source→sink; show the path or where it dead-ends   [-from -to]")
	fmt.Fprintln(os.Stderr, "  query      query the analysis graph by predicate   [-type -concept -call -loc -edges -count | -from -to]")
	fmt.Fprintln(os.Stderr, "  explain    run rules and print each finding's full proof tree + negation evidence")
	fmt.Fprintln(os.Stderr, "  match      list every node an adapter labelled (what matched which concept)")
	fmt.Fprintln(os.Stderr, "  resolve    report interprocedural call resolution (which calls are unresolved)")
	fmt.Fprintln(os.Stderr, "  graph      dump the USG (nodes+edges), or -taint reachability")
	fmt.Fprintln(os.Stderr, "  adapters   list an adapter's source/sink/control/mark/assume vocabulary   [-lang go]")
	fmt.Fprintln(os.Stderr, "  definitions inspect loaded VyQL concepts/rules/adapters/reviews   [-kind all -query TEXT -format text|json]")
	fmt.Fprintln(os.Stderr, "  validate-adapter parse and summarize a VyQL adapter file   [-file adapter.vyql]")
	fmt.Fprintln(os.Stderr, "  diff       diff two `scan -format json` outputs by fingerprint")
}
