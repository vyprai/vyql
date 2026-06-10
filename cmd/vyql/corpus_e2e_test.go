package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/findings"
)

// Precision corpus — a measured regression gate over real third-party repos.
// Network-gated: set VYQL_E2E=1 to run (clones a few known-vulnerable repos).
// Without it the offline unit suite stays green. Every precision change should be
// re-measured here: true-positive counts and confidence tiers must hold.
func TestPrecisionCorpus(t *testing.T) {
	if os.Getenv("VYQL_E2E") != "1" {
		t.Skip("set VYQL_E2E=1 to run the network corpus test (clones real repos)")
	}
	rules, err := loadRules("")
	if err != nil {
		t.Fatalf("loadRules: %v", err)
	}

	clone := func(url, dir string) bool {
		c := exec.Command("git", "clone", "--depth", "1", url, dir)
		c.Stderr = os.Stderr
		return c.Run() == nil
	}
	scan := func(paths ...string) []*findings.Finding {
		fs, _, err := scanPaths(paths, rules)
		if err != nil {
			t.Fatalf("scan %v: %v", paths, err)
		}
		return fs
	}
	byRule := func(fs []*findings.Finding) map[string]int {
		m := map[string]int{}
		for _, f := range fs {
			m[f.RuleID]++
		}
		return m
	}
	confOf := func(fs []*findings.Finding, ruleID string) string {
		for _, f := range fs {
			if f.RuleID == ruleID {
				return f.Confidence
			}
		}
		return ""
	}

	tmp := t.TempDir()

	// --- vulpy (Flask/Python): interprocedural SQLi ---
	vulpy := filepath.Join(tmp, "vulpy")
	if !clone("https://github.com/fportantier/vulpy", vulpy) {
		t.Skip("could not clone vulpy (no network?)")
	}
	bad := scan(filepath.Join(vulpy, "bad"))
	if len(bad) < 6 {
		t.Errorf("vulpy/bad: expected >=6 SQLi, got %d", len(bad))
	}
	for _, f := range bad {
		if f.RuleID != "VYQL-INJ-001" {
			t.Errorf("vulpy/bad: unexpected rule %s (expected all SQLi)", f.RuleID)
		}
	}
	if good := scan(filepath.Join(vulpy, "good")); len(good) != 0 {
		t.Errorf("vulpy/good (parameterized): expected 0, got %d", len(good))
	}

	// --- dvna (Express/Node): SQLi + command + deser + redirect ---
	dvna := filepath.Join(tmp, "dvna")
	if clone("https://github.com/appsecco/dvna", dvna) {
		fs := scan(dvna)
		r := byRule(fs)
		// INJ-003 = mathjs.eval(req.body.eqn) code injection (matched via suffix)
		for _, want := range []string{"VYQL-INJ-001", "VYQL-INJ-002", "VYQL-INJ-003", "VYQL-DESER-001", "VYQL-RF-002"} {
			if r[want] == 0 {
				t.Errorf("dvna: missing %s (got %v)", want, r)
			}
		}
		// precision tiers: command-injection via dotted path (child_process.exec)
		// is high; the SQLi is `db.sequelize.query(...)` — the most-specific-sink
		// rule matches the resolved `sequelize.query` PATH (not the generic `query`
		// method), so it's correctly high confidence.
		if c := confOf(fs, "VYQL-INJ-002"); c != "high" {
			t.Errorf("dvna command-injection should be high, got %q", c)
		}
		if c := confOf(fs, "VYQL-INJ-001"); c != "high" {
			t.Errorf("dvna SQLi (sequelize.query path) should be high, got %q", c)
		}
	}

	// --- railsgoat (Rails/Ruby): SQLi + deser(Marshal) + path + redirect ---
	rg := filepath.Join(tmp, "railsgoat")
	if clone("https://github.com/OWASP/railsgoat", rg) {
		r := byRule(scan(filepath.Join(rg, "app")))
		for _, want := range []string{"VYQL-INJ-001", "VYQL-DESER-001", "VYQL-PATH-001", "VYQL-RF-002"} {
			if r[want] == 0 {
				t.Errorf("railsgoat: missing %s (got %v)", want, r)
			}
		}
	}
}
