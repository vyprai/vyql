package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/pprof"
	"slices"
	"strconv"
	"strings"

	"github.com/vyprai/vyql/internal/bindings"
	"github.com/vyprai/vyql/internal/datadir"
	"github.com/vyprai/vyql/internal/extract"
	"github.com/vyprai/vyql/internal/review"
	"github.com/vyprai/vyql/internal/timing"
)

// One registrar per shared flag. Each owns the flag's name, default, help text
// and validation, so the same flag cannot acquire a second spelling or a second
// description by being declared in another command.
//
// Values outside a flag's set are rejected here rather than absorbed. A filter
// that can never match reports an empty result, and an empty result from a
// security scanner reads as a clean bill of health.

// newFlagSet builds a flagset that reports errors instead of exiting on them, so
// the exit-code contract decides the status rather than the flag package.
//
// Output is discarded because the package prints its own message and then the
// whole usage block; both are replaced by the diagnostics below.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parseFlags parses and routes the two outcomes the flag package folds together.
// Asking for help is not an error: it prints the command's flags on stdout and
// exits 0. Anything else is a usage error.
func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printCommandHelp(fs)
			return errHelpRequested
		}
		return &usageError{msg: err.Error(), hints: movedFlagHint(fs.Name(), err)}
	}
	return nil
}

// movedFlags names where a flag's job is done now, keyed by "command -flag". A
// flag that answers the same question somewhere else should say so: the
// invocation exists in scripts, and "flag provided but not defined" leaves the
// reader to guess whether the capability is gone or merely spelled differently.
var movedFlags = map[string]string{
	"query -from":  "reachability is `vyql trace -from X -to Y`; add -brief for one line per pair",
	"query -to":    "reachability is `vyql trace -from X -to Y`; add -brief for one line per pair",
	"graph -taint": "reachability is `vyql trace`, which also reports where taint stops",
	"scan -all":    "use -flags with (findings and flags) or -flags only",
	"scan -exit-code": "the gate exits " + strconv.Itoa(exitCheckFail) +
		"; 1 means vyql could not run and 2 means the invocation was wrong",
	"scan -binding-overlay":   "the flag is -bindings, matching -rules",
	"scan -incremental-cache": "the flag is -cache-incremental",
	"definitions -max":        "the flag is -limit; it counts rows, not bytes",
	"definitions -in":         "the path is positional: `vyql definitions validate <path>`",
}

func movedFlagHint(command string, err error) []string {
	const prefix = "flag provided but not defined: "
	msg := err.Error()
	if !strings.HasPrefix(msg, prefix) {
		return nil
	}
	if to, ok := movedFlags[command+" "+strings.TrimSpace(strings.TrimPrefix(msg, prefix))]; ok {
		return []string{to}
	}
	return nil
}

// errHelpRequested unwinds a help request to main, which exits 0. It is not
// reported as a diagnostic.
var errHelpRequested = errors.New("help requested")

func printCommandHelp(fs *flag.FlagSet) {
	fmt.Printf("usage: vyql %s [flags] <path>...\n\nflags:\n", fs.Name())
	fs.SetOutput(os.Stdout)
	fs.PrintDefaults()
	fs.SetOutput(io.Discard)
}

// enumValue is a flag whose value must come from a fixed set. It validates on
// assignment, so a bad value is reported before the command does any work.
type enumValue struct {
	name    string
	value   string
	allowed []string
}

func (e *enumValue) String() string {
	if e == nil {
		return ""
	}
	return e.value
}

func (e *enumValue) Set(v string) error {
	got := strings.ToLower(strings.TrimSpace(v))
	if slices.Contains(e.allowed, got) {
		e.value = got
		return nil
	}
	msg := fmt.Sprintf("unknown -%s %q", e.name, v)
	if s := suggest(e.allowed, got); len(s) > 0 {
		msg += "\n  did you mean: " + strings.Join(s, ", ") + "?"
	}
	return fmt.Errorf("%s\n  valid: %s", msg, strings.Join(e.allowed, " | "))
}

func addEnum(fs *flag.FlagSet, name, def, help string, allowed []string) *enumValue {
	v := &enumValue{name: name, value: def, allowed: allowed}
	fs.Var(v, name, help+": "+strings.Join(allowed, " | "))
	return v
}

// ── shared registrars ───────────────────────────────────────────────────────

func addProfile(fs *flag.FlagSet) *string {
	return fs.String("profile", "auto", "analysis profile: auto | "+profileNames())
}

// addFormat takes the formats the command actually renders. `scan` produces four
// and `definitions` two; a shared list would let a command advertise an output
// it cannot produce.
func addFormat(fs *flag.FlagSet, allowed ...string) *enumValue {
	return addEnum(fs, "format", allowed[0], "output format", allowed)
}

func addRules(fs *flag.FlagSet) *string {
	return fs.String("rules", "", "load rule(s) from a .vyql file or directory (default: vyql/packs)")
}

// applyDataFlagEarly applies -data before any command builds its flagset.
//
// Registering a command's flags reads the data directory: naming the available
// profiles means loading them. That fixes the resolved root, and where there is no
// data directory to find it fails outright — both before the flag that says where
// to look has been parsed. So -data has to be applied ahead of registration to
// have any effect at all.
//
// The value is still declared per command by addRunFlags, so it parses like any
// other flag and appears in that command's help.
func applyDataFlagEarly(args []string) error {
	dir, given := dataFlagValue(args)
	if !given {
		return nil
	}
	if strings.TrimSpace(dir) == "" {
		return usageWith("-data needs a directory",
			"usage: -data <path to the vyql/ data directory>")
	}
	if err := os.Setenv("VYQL_HOME", strings.TrimSpace(dir)); err != nil {
		return fmt.Errorf("-data: %w", err)
	}
	datadir.Reset()
	return nil
}

// dataFlagValue finds -data in a raw argument list, in every spelling the flag
// package accepts. It reports whether the flag was given at all, so an empty value
// is a usage error rather than a silent fallback to the default directory.
func dataFlagValue(args []string) (value string, given bool) {
	for i, arg := range args {
		if arg == "--" {
			return "", false
		}
		if arg == "-data" || arg == "--data" {
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", true
		}
		for _, prefix := range []string{"-data=", "--data="} {
			if strings.HasPrefix(arg, prefix) {
				return strings.TrimPrefix(arg, prefix), true
			}
		}
	}
	return "", false
}

// addRunFlags registers the settings that reach an ordinary run and otherwise
// have only an environment variable. They are per-command rather than global
// because dispatch reads os.Args[1] directly, and a global flag would have to be
// parsed before the command is known.
type runFlags struct {
	cpuProfile *string
	memProfile *string
}

func addRunFlags(fs *flag.FlagSet) runFlags {
	addDataFlag(fs)
	return runFlags{
		cpuProfile: fs.String("cpuprofile", "", "write a CPU profile to this path"),
		memProfile: fs.String("memprofile", "", "write a heap profile to this path"),
	}
}

// addDataFlag declares -data on a command that reads the data directory but takes
// none of the other run flags.
//
// Nothing reads the value it registers. applyDataFlagEarly has already taken it
// from the raw arguments, because a flagset cannot be built without reading the
// data directory first. Declaring it here is what makes the flag parse rather than
// be rejected, and what puts it in the command's help.
func addDataFlag(fs *flag.FlagSet) {
	fs.String("data", "", "the vyql/ data directory (default: $VYQL_HOME, then the search path)")
}

// statsValue is `-stats`, which reports what the run did: graph counts, taint-hub
// warnings and per-phase timing.
//
// It carries an optional phase list so the per-phase detail has one switch with a
// discoverable value set rather than five environment variables:
//
//	-stats                     counts, hubs, per-phase totals
//	-stats=rule,binding,sink   per-phase detail
//
// IsBoolFlag is what lets the bare form parse; without it `-stats .` would consume
// the path as the flag's value.
type statsValue struct {
	on     bool
	phases map[string]bool
}

var statsPhases = []string{"rule", "binding", "sink", "index", "flag", "all"}

func (s *statsValue) String() string {
	if s == nil || !s.on {
		return "false"
	}
	return "true"
}

func (s *statsValue) IsBoolFlag() bool { return true }

func (s *statsValue) Set(v string) error {
	s.on = true
	if v == "true" || v == "" {
		return nil
	}
	s.phases = map[string]bool{}
	for _, p := range strings.Split(v, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if !slices.Contains(statsPhases, p) {
			msg := fmt.Sprintf("unknown -stats phase %q", p)
			if sg := suggest(statsPhases, p); len(sg) > 0 {
				msg += "\n  did you mean: " + strings.Join(sg, ", ") + "?"
			}
			return fmt.Errorf("%s\n  valid: %s", msg, strings.Join(statsPhases, " | "))
		}
		if p == "all" {
			for _, a := range statsPhases[:len(statsPhases)-1] {
				s.phases[a] = true
			}
			continue
		}
		s.phases[p] = true
	}
	return nil
}

func addStats(fs *flag.FlagSet) *statsValue {
	v := &statsValue{}
	fs.Var(v, "stats", "report graph counts, taint hubs and per-phase timing; "+
		"-stats=<phases> for detail: "+strings.Join(statsPhases, " | "))
	return v
}

// apply turns the parsed timing selection on. Both packages read their switches once at
// init, so this runs after parsing and before the pipeline.
func (s *statsValue) apply() {
	if !s.on {
		return
	}
	timing.SetEnabled(true)
	if len(s.phases) > 0 {
		bindings.SetTimingPhases(s.phases)
	}
}

func (s *statsValue) rulePhase() bool { return s.phases["rule"] }

// ruleTimingOn prints each rule's evaluation time. It is process-wide like the switches
// in internal/timing and internal/bindings, and set from -stats=rule for the same reason:
// the evaluation loop is hot enough that reading the environment per rule would show up
// in what it measures.
var ruleTimingOn = os.Getenv("VYQL_RULE_TIMING") != ""

// apply resolves the settings that otherwise have only an environment variable, and
// returns the cleanup that flushes the heap profile.
//
// The data directory is resolved first and before any scan work: a missing one used to
// surface as a goroutine dump from package initialization rather than as the diagnostic
// this reports.
func (r runFlags) apply() (func(), error) {
	// -data is applied by applyDataFlagEarly, before any flagset is built. Setting
	// it again here would be too late to matter and is left out for that reason.
	var stops []func()
	if p := firstNonEmpty(*r.cpuProfile, os.Getenv("VYQL_CPUPROFILE")); p != "" {
		f, err := os.Create(p)
		if err != nil {
			return func() {}, fmt.Errorf("-cpuprofile: %w", err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			return func() {}, fmt.Errorf("-cpuprofile: %w", err)
		}
		stops = append(stops, pprof.StopCPUProfile)
	}
	if p := firstNonEmpty(*r.memProfile, os.Getenv("VYQL_MEMPROFILE")); p != "" {
		stops = append(stops, func() { writeHeapProfile(p) })
	}
	return func() {
		for _, stop := range stops {
			stop()
		}
	}, nil
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

func writeHeapProfile(path string) {
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vyql: memprofile: "+err.Error())
		return
	}
	// The profile is written below, so a close failure can mean it was not flushed --
	// say so rather than exiting quietly with a truncated file.
	defer func() {
		if cerr := f.Close(); cerr != nil {
			fmt.Fprintln(os.Stderr, "vyql: memprofile: "+cerr.Error())
		}
	}()
	runtime.GC()
	if err := pprof.WriteHeapProfile(f); err != nil {
		fmt.Fprintln(os.Stderr, "vyql: memprofile: "+err.Error())
	}
}

// excludeValue is `-exclude`, which is repeatable and takes exactly one pattern
// per occurrence. Splitting on comma would make a brace alternation
// (`**/*.{test,spec}.ts`) parse as two patterns that match nothing.
//
// Each pattern is compiled on assignment, so a malformed glob is a usage error
// before any file is read.
type excludeValue struct {
	raw      []string
	compiled extract.Excludes
}

func (x *excludeValue) String() string {
	if x == nil {
		return ""
	}
	return strings.Join(x.raw, " ")
}

func (x *excludeValue) Set(v string) error {
	e, err := extract.ParseExclusion(v)
	if err != nil {
		return err
	}
	x.raw = append(x.raw, v)
	x.compiled = append(x.compiled, e)
	return nil
}

func addExclude(fs *flag.FlagSet) *excludeValue {
	v := &excludeValue{}
	fs.Var(v, "exclude", "skip paths matching this pattern; repeat for more. "+
		"A bare name means that directory at any depth (node_modules); "+
		"anything else is a glob against the scan-relative path (**/*_templ.go, src/gen/**)")
	return v
}

// checkFlagFilters rejects a review-flag filter that cannot reach the output. Accepting
// it would silently drop the operator's intent, which is the failure this file exists to
// prevent -- so the message names the flag that turns the output on.
func checkFlagFilters(mode, category, kind, loc string) error {
	// Checked whatever the mode is: a category that names nothing is wrong when the
	// flags are on, and wrong in the same way when they are not.
	if err := checkFlagCategory(category); err != nil {
		return err
	}
	if mode != "off" {
		return nil
	}
	var set []string
	if category != "" && category != "all" {
		set = append(set, "-flag-category")
	}
	if kind != "" && kind != "all" {
		set = append(set, "-flag-kind")
	}
	if loc != "" {
		set = append(set, "-flag-loc")
	}
	if len(set) == 0 {
		return nil
	}
	return usageWith(strings.Join(set, ", ")+" set while -flags is off",
		"add -flags only (flags alone) or -flags with (findings and flags)")
}

// checkFlagCategory rejects a -flag-category naming a category no review declares.
//
// The categories come from the data rather than a fixed list, so this cannot be an
// enum on the flag itself: the valid set is not known until the data directory is
// resolved. Checking it here keeps a mistyped category from reporting an empty
// result, which is what -flag-kind already gets from its enum.
func checkFlagCategory(category string) error {
	category = strings.ToLower(strings.TrimSpace(category))
	if category == "" || category == "all" {
		return nil
	}
	known := review.Categories()
	if len(known) == 0 || slices.Contains(known, category) {
		return nil
	}
	msg := fmt.Sprintf("unknown -flag-category %q", category)
	if s := suggest(known, category); len(s) > 0 {
		msg += "\n  did you mean: " + strings.Join(s, ", ") + "?"
	}
	return usageWith(msg, "valid: all | "+strings.Join(known, " | "))
}

// requirePaths returns the positional paths, or a usage error naming the command.
// A command that needs a path and is given none cannot mean anything, so it is
// reported before any work rather than after a scan of nothing.
func requirePaths(fs *flag.FlagSet, usage string) ([]string, error) {
	paths := fs.Args()
	if len(paths) == 0 {
		return nil, usageWith("no path given", "usage: "+usage)
	}
	return paths, nil
}
