package main

// -data must select the data directory the command actually loads. Asserting that
// the flag sets $VYQL_HOME is not enough: it does that already, and the command
// still reads the default directory. These tests point -data at a directory with
// no VyQL data in it, so a command that honours the flag fails and a command that
// ignores it succeeds against the real data.
//
// They run the built binary rather than calling the command functions, because
// several packages cache what they read from the data directory in package-level
// state. In a real invocation each run is a fresh process, so that caching is
// correct; in-process it would let one case decide the next one's answer.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var (
	buildOnce sync.Once
	builtPath string
	buildErr  error
)

// vyqlBinary builds the command once per package run and returns its path.
func vyqlBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "vyql-cli-test")
		if err != nil {
			buildErr = err
			return
		}
		builtPath = filepath.Join(dir, "vyql")
		out, err := exec.Command("go", "build", "-o", builtPath, "github.com/vyprai/vyql/cmd/vyql").CombinedOutput()
		if err != nil {
			buildErr = err
			builtPath = string(out)
		}
	})
	if buildErr != nil {
		t.Fatalf("build vyql: %v\n%s", buildErr, builtPath)
	}
	return builtPath
}

// runVyql runs the built binary with the ambient data directory unset, so only the
// arguments decide which one it loads.
func runVyql(t *testing.T, args ...string) (exitCode int, output string) {
	t.Helper()
	cmd := exec.Command(vyqlBinary(t), args...)
	cmd.Env = append(os.Environ(), "VYQL_HOME=")
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	var exit *exec.ExitError
	if ok := asExitError(err, &exit); ok {
		return exit.ExitCode(), string(out)
	}
	t.Fatalf("run vyql %v: %v", args, err)
	return 0, ""
}

func asExitError(err error, target **exec.ExitError) bool {
	e, ok := err.(*exec.ExitError)
	if ok {
		*target = e
	}
	return ok
}

// repoDataDir is the data directory that ships in this repository. Tests that need
// the real knowledge base pass it explicitly, because runVyql clears $VYQL_HOME and
// runs from a temporary directory, so nothing else would find it.
func repoDataDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd() // cmd/vyql
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(wd, "..", "..", "vyql")
	if _, err := os.Stat(filepath.Join(dir, "ontology")); err != nil {
		t.Fatalf("data directory not found at %s: %v", dir, err)
	}
	return dir
}

func writeGoSource(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := "package main\n\nfunc main() {\n\tprintln(\"hello\")\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/x\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// Every command that offers -data reads the data directory, so every one of them
// has to honour it. They share a registrar, so they break together and are fixed
// together; this pins that rather than trusting it.
func TestEveryCommandOfferingDataHonoursIt(t *testing.T) {
	for _, name := range []string{"scan", "trace", "explain", "match", "resolve", "query", "graph", "definitions"} {
		t.Run(name, func(t *testing.T) {
			empty := t.TempDir()
			src := writeGoSource(t)

			code, out := runVyql(t, name, "-data", empty, src)

			if code == 0 {
				t.Fatalf("%s -data <directory with no VyQL data> exited 0, so it loaded the default data directory instead:\n%s", name, out)
			}
			if !strings.Contains(out, empty) {
				t.Fatalf("%s failed without naming the directory it was given, so this does not prove -data was read:\n%s", name, out)
			}
		})
	}
}

// Asking for help is not an error. A command that exits non-zero on -h reads as a
// broken tool to a CI wrapper that checks the status.
func TestEveryCommandExitsZeroOnHelp(t *testing.T) {
	for _, name := range []string{"scan", "trace", "explain", "match", "resolve", "query", "graph", "definitions", "diff", "cache"} {
		t.Run(name, func(t *testing.T) {
			code, out := runVyql(t, name, "-h")

			if code != 0 {
				t.Fatalf("%s -h exited %d:\n%s", name, code, out)
			}
		})
	}
}

// A filter that cannot match reports an empty result, and an empty result from a
// security scanner reads as a clean bill of health. -flag-kind is rejected when it
// names nothing; -flag-category has to behave the same way.
func TestUnknownFlagCategoryIsRejected(t *testing.T) {
	src := writeGoSource(t)
	data := repoDataDir(t)

	code, out := runVyql(t, "scan", "-data", data, "-flags", "only", "-flag-category", "atuh", "-cache", "off", src)

	if code == 0 {
		t.Fatalf("scan -flag-category atuh exited 0, reporting an empty result for a category that does not exist:\n%s", out)
	}
	if !strings.Contains(out, "atuh") {
		t.Fatalf("the failure does not name the rejected value, so it does not tell the operator what to fix:\n%s", out)
	}
}

// A known category still has to be accepted, so the check cannot be a blanket
// rejection of anything unusual.
func TestKnownFlagCategoryIsAccepted(t *testing.T) {
	src := writeGoSource(t)
	data := repoDataDir(t)

	code, out := runVyql(t, "scan", "-data", data, "-flags", "only", "-flag-category", "auth", "-cache", "off", src)

	if code != 0 {
		t.Fatalf("scan -flag-category auth exited %d, but auth is a category the shipped reviews declare:\n%s", code, out)
	}
}

// go install puts the engine in GOBIN with no vyql/ beside it. A data root
// under GOMODCACHE is not used, so scan exits 1.
func TestScanWithoutDataDirectoryExitsOne(t *testing.T) {
	modcache := t.TempDir()
	stale := filepath.Join(modcache, "github.com", "vyprai", "vyql@v0.3.1", "vyql")
	for _, d := range []string{"taxonomy", "packs", filepath.Join("ontology", "concepts")} {
		if err := os.MkdirAll(filepath.Join(stale, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	src := writeGoSource(t)
	cmd := exec.Command(vyqlBinary(t), "scan", "-fail-on", "none", src)
	cmd.Env = append(os.Environ(), "VYQL_HOME=", "GOMODCACHE="+modcache)
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !asExitError(err, &exit) {
			t.Fatalf("run scan: %v\n%s", err, out)
		}
		code = exit.ExitCode()
	}
	if code != 1 {
		t.Fatalf("scan with no data directory exited %d, want 1:\n%s", code, out)
	}
	if !strings.Contains(string(out), "go install installs the engine only") {
		t.Fatalf("missing data must say go install is the engine only:\n%s", out)
	}
	if !strings.Contains(string(out), "dl.vyprsec.ai") {
		t.Fatalf("missing data must name dl.vyprsec.ai:\n%s", out)
	}
}

func TestVersionWithoutDataDirectoryExitsZero(t *testing.T) {
	code, out := runVyql(t, "version")
	if code != 0 {
		t.Fatalf("version with no data directory exited %d:\n%s", code, out)
	}
}

func TestCachePathWithoutDataDirectoryExitsZero(t *testing.T) {
	code, out := runVyql(t, "cache", "path")
	if code != 0 {
		t.Fatalf("cache path with no data directory exited %d:\n%s", code, out)
	}
}

// A directory that yields no concepts, rules, bindings or reviews is not a
// knowledge base. Reporting zero of each and exiting 0 reads as "loaded, and there
// is nothing in it" — which is the same shape as a clean scan, from a tool whose
// whole job is to say whether something is there.
func TestDefinitionsFailsWhenTheDataDirectoryHasNothingInIt(t *testing.T) {
	empty := t.TempDir()

	code, out := runVyql(t, "definitions", "-data", empty)

	if code == 0 {
		t.Fatalf("definitions on a directory with no VyQL data exited 0:\n%s", out)
	}
}

// The subcommands under `definitions` all read the data directory, so each one
// has to accept -data. Rejecting it as an unknown flag leaves no way to point them
// anywhere but the default.
func TestDefinitionsSubcommandsAcceptTheDataFlag(t *testing.T) {
	for _, sub := range []string{"search", "refs", "show-policy", "show-mechanic", "validate", "validate-binding", "explain"} {
		t.Run(sub, func(t *testing.T) {
			empty := t.TempDir()

			_, out := runVyql(t, "definitions", sub, "-data", empty)

			if strings.Contains(out, "flag provided but not defined: -data") {
				t.Fatalf("definitions %s rejects -data, so it can only ever read the default data directory:\n%s", sub, out)
			}
		})
	}
}
