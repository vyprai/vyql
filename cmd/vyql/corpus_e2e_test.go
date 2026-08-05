package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/datadir"
	"github.com/vyprai/vyql/internal/findings"
)

type corpusSpec struct {
	Cases []corpusCase `json:"cases"`
}

type corpusCase struct {
	Name     string       `json:"name"`
	Repo     string       `json:"repo"`
	Required bool         `json:"required"`
	Scans    []corpusScan `json:"scans"`
}

type corpusScan struct {
	Name        string            `json:"name"`
	Paths       []string          `json:"paths"`
	ExpectRules []string          `json:"expect_rules"`
	AllowRules  []string          `json:"allow_rules"`
	MinCounts   map[string]int    `json:"min_counts"`
	MaxFindings *int              `json:"max_findings"`
	Confidence  map[string]string `json:"confidence"`
}

// Precision corpus — a measured regression gate over real third-party repos.
// Network-gated: set VYQL_E2E=1 to run. Expected outcomes live in
// vyql/tests/corpus_e2e.json; this file is only the generic runner.
func TestPrecisionCorpus(t *testing.T) {
	if os.Getenv("VYQL_E2E") != "1" {
		t.Skip("set VYQL_E2E=1 to run the network corpus test")
	}
	spec := loadCorpusSpec(t)
	rules, err := loadRules("")
	if err != nil {
		t.Fatalf("loadRules: %v", err)
	}
	tmp := t.TempDir()
	for _, tc := range spec.Cases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			repoDir := filepath.Join(tmp, tc.Name)
			if !cloneCorpusRepo(tc.Repo, repoDir) {
				if tc.Required {
					t.Skipf("could not clone required corpus repo %s", tc.Repo)
				}
				t.Skipf("could not clone optional corpus repo %s", tc.Repo)
			}
			for _, sc := range tc.Scans {
				sc := sc
				t.Run(sc.Name, func(t *testing.T) {
					paths := make([]string, 0, len(sc.Paths))
					for _, p := range sc.Paths {
						if p == "." || p == "" {
							paths = append(paths, repoDir)
						} else {
							paths = append(paths, filepath.Join(repoDir, p))
						}
					}
					fs, _, _, err := scanPaths(paths, rules)
					if err != nil {
						t.Fatalf("scan %v: %v", paths, err)
					}
					checkCorpusScan(t, sc, fs)
				})
			}
		})
	}
}

func loadCorpusSpec(t *testing.T) corpusSpec {
	t.Helper()
	path := filepath.Join(datadir.Root(), "tests", "corpus_e2e.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var spec corpusSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return spec
}

func cloneCorpusRepo(url, dir string) bool {
	c := exec.Command("git", "clone", "--depth", "1", url, dir)
	c.Stderr = os.Stderr
	return c.Run() == nil
}

func checkCorpusScan(t *testing.T, sc corpusScan, fs []*findings.Finding) {
	t.Helper()
	byRule := map[string]int{}
	conf := map[string]string{}
	allowed := map[string]bool{}
	for _, r := range sc.AllowRules {
		allowed[r] = true
	}
	for _, f := range fs {
		byRule[f.RuleID]++
		if conf[f.RuleID] == "" {
			conf[f.RuleID] = f.Confidence
		}
		if len(allowed) > 0 && !allowed[f.RuleID] {
			t.Errorf("unexpected rule %s; allowed=%v", f.RuleID, sc.AllowRules)
		}
	}
	if sc.MaxFindings != nil && len(fs) > *sc.MaxFindings {
		t.Errorf("expected at most %d finding(s), got %d", *sc.MaxFindings, len(fs))
	}
	for _, want := range sc.ExpectRules {
		if byRule[want] == 0 {
			t.Errorf("missing expected rule %s; got %v", want, byRule)
		}
	}
	for ruleID, min := range sc.MinCounts {
		if byRule[ruleID] < min {
			t.Errorf("expected rule %s count >= %d, got %d", ruleID, min, byRule[ruleID])
		}
	}
	for ruleID, want := range sc.Confidence {
		if got := conf[ruleID]; got != want {
			t.Errorf("rule %s confidence: got %q want %q", ruleID, got, want)
		}
	}
}
