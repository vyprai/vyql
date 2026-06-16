// Command vyql is the VyQL command-line scanner. It runs the full pipeline on
// real source: native frontend (go/ast) -> NIR -> shared lowering with
// import/type resolution -> framework adapters -> rule evaluation -> findings,
// rendered as a human report or SARIF 2.1.0.
//
// Usage:
//
//	vyql scan [flags] <path>...
//	  -rules <file|dir>   load rule(s) from .vyql file(s) (default: built-in SQLi)
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
	"runtime/pprof"
	"sort"
	"strings"

	"github.com/vyprai/vyql/datadir"
	"github.com/vyprai/vyql/engine"
	"github.com/vyprai/vyql/extract/frontend"
	"github.com/vyprai/vyql/extract/parsecache"
	"github.com/vyprai/vyql/findings"
	"github.com/vyprai/vyql/ontology"
	"github.com/vyprai/vyql/parser"
	"github.com/vyprai/vyql/profile"
	"github.com/vyprai/vyql/risk"
	"github.com/vyprai/vyql/sarif"
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
	case "validate-adapter":
		err = cmdValidateAdapter(args)
	case "diff":
		err = cmdDiff(args)
	case "cache":
		err = cmdCache(args)
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
	profileName := fs.String("profile", "auto", "application threat-model profile: auto | "+profileNames())
	stats := fs.Bool("stats", false, "print scan profile: per-phase timing, node/edge counts, taint-hub warnings")
	_ = fs.Parse(args)
	paths := fs.Args()
	if len(paths) == 0 {
		usage()
		os.Exit(2)
	}
	return run(paths, *rulesPath, *format, *profileName, *stats)
}

// applyProfile selects the threat-model profile (explicit name or auto-detected),
// sets the source trust boundary, and returns it for reporting.
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
// evaluate) and returns the findings + a scan summary. Multi-language: each file
// is routed to its real frontend and the matching framework adapters.
func scanPaths(paths []string, rulesSrc string) ([]*findings.Finding, scanStats, error) {
	g, stats, err := buildGraph(paths)
	if err != nil {
		return nil, stats, err
	}
	if g == nil {
		return nil, stats, nil // recognized files, but nothing to analyze
	}
	onto := ontology.Seed()
	decls, err := parser.Parse(rulesSrc)
	if err != nil {
		return nil, stats, fmt.Errorf("rule parse: %w", err)
	}
	compiled, cerrs := engine.CompileRules(decls, onto)
	if len(cerrs) != 0 {
		for _, e := range cerrs {
			fmt.Fprintln(os.Stderr, "rule error: "+e.Error())
		}
		return nil, stats, fmt.Errorf("%d rule(s) failed to compile", len(cerrs))
	}
	eng := engine.New(onto, g)
	var all []*findings.Finding
	tk := newTimer()
	for _, cr := range compiled {
		got, err := eng.Evaluate(cr)
		if err != nil {
			return nil, stats, err
		}
		all = append(all, got...)
	}
	tk.mark("evaluate")
	return all, stats, nil
}

func run(paths []string, rulesPath, format, profileName string, showStats bool) error {
	if cp := os.Getenv("VYQL_CPUPROFILE"); cp != "" {
		f, _ := os.Create(cp)
		_ = pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}
	prof := applyProfile(paths, profileName)
	src, err := loadRules(rulesPath)
	if err != nil {
		return err
	}
	// whole-scan result cache (opt-in via $VYQL_CACHE): if nothing the output depends on
	// changed — no source file edit and no vyql/ data change — replay the cached findings and
	// skip the pipeline entirely. On a miss, the per-file parse cache still makes the rebuild
	// reparse only the files that actually changed.
	cache := parsecache.Shared()
	tk := newTimer()
	var rkey string
	var all []*findings.Finding
	var stats scanStats
	hit := false
	if cache != nil {
		rkey = scanFingerprint(cache.Salt(), paths, src, prof.Name)
		if cs, ok := loadCachedScan(cache, rkey); ok {
			all, stats, hit = cs.Findings, scanStats{files: cs.Files, languages: cs.Languages}, true
		}
	}
	tk.mark("fingerprint")
	if !hit {
		all, stats, err = scanPaths(paths, src)
		if err != nil {
			return err
		}
		if cache != nil {
			storeCachedScan(cache, rkey, all, stats)
		}
	}

	// output
	switch format {
	case "sarif":
		doc := sarif.ToSARIF(all, version, nil)
		b, _ := json.MarshalIndent(doc, "", "  ")
		fmt.Println(string(b))
	case "json":
		b, _ := json.MarshalIndent(findingsJSON(all), "", "  ")
		fmt.Println(string(b))
	default:
		fmt.Printf("threat model: %s (%s)\n\n", prof.Title, prof.Name)
		printReport(all)
		printSummary(stats, len(all))
	}
	if showStats {
		fmt.Printf("[stats] profile %s (%s)\n", prof.Name, prof.Title)
		printScanStats(paths)
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

// printSummary reports what was scanned (languages + file counts) and the total.
func printSummary(stats scanStats, n int) {
	var parts []string
	for _, lg := range stats.languages {
		parts = append(parts, fmt.Sprintf("%s:%d", lg, stats.files[lg]))
	}
	scanned := "no source"
	if len(parts) > 0 {
		scanned = strings.Join(parts, " ")
	}
	fmt.Printf("scanned %s — %d finding(s)\n", scanned, n)
}

func usage() {
	fmt.Fprintln(os.Stderr, "vyql "+version+" — Vypr Query Language scanner")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "usage: vyql <command> [flags] <path>...")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "commands:")
	fmt.Fprintln(os.Stderr, "  scan       run rules and report findings   [-rules -format text|sarif|json -profile -stats]")
	fmt.Fprintln(os.Stderr, "  trace      trace taint source→sink; show the path or where it dead-ends   [-from -to]")
	fmt.Fprintln(os.Stderr, "  query      query the analysis graph by predicate   [-type -concept -call -loc -edges -count | -from -to]")
	fmt.Fprintln(os.Stderr, "  explain    run rules and print each finding's full proof tree + negation evidence")
	fmt.Fprintln(os.Stderr, "  match      list every node an adapter labelled (what matched which concept)")
	fmt.Fprintln(os.Stderr, "  resolve    report interprocedural call resolution (which calls are unresolved)")
	fmt.Fprintln(os.Stderr, "  graph      dump the USG (nodes+edges), or -taint reachability")
	fmt.Fprintln(os.Stderr, "  adapters   list an adapter's source/sink/control/mark/assume vocabulary   [-lang go]")
	fmt.Fprintln(os.Stderr, "  validate-adapter parse and summarize a VyQL adapter file   [-file adapter.vyql]")
	fmt.Fprintln(os.Stderr, "  diff       diff two `scan -format json` outputs by fingerprint")
}
