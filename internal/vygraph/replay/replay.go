// Package replay is the v3 conversion gate: for a corpus rank (a real
// repository at its vulnerable and fixed commits), run the v3 pipeline with a
// v3 knowledge base on both sides and require the differential — the same
// rule, at the same file, firing on the vulnerable side and silent on the
// fixed side. This is the rolling per-batch replay; the full spec parity
// replay is the later cutover gate, not this one.
package replay

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/vyprai/vyql/internal/vygraph/pipeline"
)

// Rank is one corpus row: repository, owner, host, CVE, the fix commit, the
// rank number, and the language.
type Rank struct {
	Rank  int
	Repo  string
	Owner string
	Host  string
	CVE   string
	Fix   string
	Lang  string
}

// ParsePool reads the corpus pool (tab-separated: repo, owner, host, CVE,
// fix commit, rank, language), filtered to the given languages (empty = all).
func ParsePool(path string, langs ...string) ([]Rank, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, l := range langs {
		if l != "" {
			want[l] = true
		}
	}
	var out []Rank
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 7 {
			return nil, fmt.Errorf("pool line %d: want 7 fields, got %d", i+1, len(f))
		}
		r, err := strconv.Atoi(strings.TrimSpace(f[5]))
		if err != nil {
			return nil, fmt.Errorf("pool line %d: bad rank %q", i+1, f[5])
		}
		rk := Rank{Repo: f[0], Owner: f[1], Host: f[2], CVE: f[3], Fix: f[4], Rank: r, Lang: strings.TrimSpace(f[6])}
		if len(want) > 0 && !want[rk.Lang] {
			continue
		}
		out = append(out, rk)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rank < out[j].Rank })
	return out, nil
}

// URL renders the clone URL for the rank's host.
func (r Rank) URL() string {
	host := r.Host
	if host == "" {
		host = "github.com"
	}
	return fmt.Sprintf("https://%s/%s/%s.git", host, r.Owner, r.Repo)
}

// Loc is a finding location: rule id + file (the source node's file).
type Loc struct {
	Rule string
	File string
}

// Outcome is one rank's differential replay.
type Outcome struct {
	Rank  Rank
	Pass  bool
	Vuln  map[Loc]int
	Fixed map[Loc]int
	Note  string
}

// RunRank clones (or reuses a cached clone of) the rank's repository, checks
// out the fix commit and its parent into worktrees, runs the pipeline on both,
// and applies the differential gate: some (rule, file) present on the
// vulnerable side and absent on the fixed side.
func RunRank(rk Rank, kbDir, cacheDir string, opts pipeline.Options) (*Outcome, error) {
	repoDir := filepath.Join(cacheDir, slug(rk.Owner+"-"+rk.Repo))
	if _, err := os.Stat(repoDir); err != nil {
		if out, err := exec.Command("git", "clone", "--depth=1", "--filter=blob:none", "--no-checkout", rk.URL(), repoDir).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("clone %s: %v: %s", rk.URL(), err, strings.TrimSpace(string(out)))
		}
	}
	// Ensure both commits exist locally.
	for _, rev := range []string{rk.Fix, rk.Fix + "^"} {
		if err := exec.Command("git", "-C", repoDir, "cat-file", "-e", rev+"^{commit}").Run(); err != nil {
			if out, err2 := exec.Command("git", "-C", repoDir, "fetch", "--filter=blob:none", "origin", rev).CombinedOutput(); err2 != nil {
				// Fall back to a full fetch of the ref range.
				if out2, err3 := exec.Command("git", "-C", repoDir, "fetch", "--unshallow").CombinedOutput(); err3 != nil {
					return nil, fmt.Errorf("fetch %s: %v / %v: %s %s", rev, err2, err3,
						strings.TrimSpace(string(out)), strings.TrimSpace(string(out2)))
				}
			}
		}
	}
	vulnSHA, err := rev(repoDir, rk.Fix+"^")
	if err != nil {
		return nil, fmt.Errorf("resolve vulnerable parent: %w", err)
	}
	fixSHA, err := rev(repoDir, rk.Fix)
	if err != nil {
		return nil, fmt.Errorf("resolve fix: %w", err)
	}
	vulnDir, err := worktree(repoDir, fmt.Sprintf("r%d-vuln", rk.Rank), vulnSHA)
	if err != nil {
		return nil, err
	}
	fixDir, err := worktree(repoDir, fmt.Sprintf("r%d-fix", rk.Rank), fixSHA)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = exec.Command("git", "-C", repoDir, "worktree", "remove", "--force", vulnDir).Run()
		_ = exec.Command("git", "-C", repoDir, "worktree", "remove", "--force", fixDir).Run()
	}()

	vulnRes, err := pipeline.Run(vulnDir, kbDir, opts)
	if err != nil {
		return nil, fmt.Errorf("vulnerable run: %w", err)
	}
	fixRes, err := pipeline.Run(fixDir, kbDir, opts)
	if err != nil {
		return nil, fmt.Errorf("fixed run: %w", err)
	}

	// The focused differential: only findings in files the fix commit touched
	// count. Unrelated noise elsewhere survives on both sides — the same
	// tolerance v2's own rank review records.
	touched, err := diffFiles(repoDir, vulnSHA, fixSHA)
	if err != nil {
		return nil, err
	}
	oc := &Outcome{Rank: rk, Vuln: map[Loc]int{}, Fixed: map[Loc]int{}}
	collect := func(res *pipeline.Result, into map[Loc]int) {
		for _, f := range res.Output.Findings {
			file := fileOf(f.Source)
			if !touched[file] {
				continue
			}
			into[Loc{Rule: f.RuleID, File: file}]++
		}
	}
	collect(vulnRes, oc.Vuln)
	collect(fixRes, oc.Fixed)

	for loc := range oc.Vuln {
		if oc.Fixed[loc] == 0 {
			oc.Pass = true
			oc.Note = fmt.Sprintf("%s @ %s fires on vulnerable, silent on fixed", loc.Rule, loc.File)
			return oc, nil
		}
	}
	oc.Note = fmt.Sprintf("%d vuln findings, all still present on fixed", len(oc.Vuln))
	return oc, nil
}

// diffFiles lists the files a fix commit changed.
func diffFiles(repoDir, vuln, fix string) (map[string]bool, error) {
	out, err := exec.Command("git", "-C", repoDir, "diff", "--name-only", vuln, fix).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("diff --name-only: %v", err)
	}
	files := map[string]bool{}
	for _, f := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if f != "" {
			files[f] = true
		}
	}
	return files, nil
}

// diffHunks maps changed files to their changed line ranges (the fix
// location). A finding counts only if its sink sits inside a changed hunk —
// unrelated findings elsewhere in the touched file are noise the same way
// v2's rank review tolerates them.
func diffHunks(repoDir, vuln, fix string) (map[string][][2]int, error) {
	out, err := exec.Command("git", "-C", repoDir, "diff", "-U0", vuln, fix).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("diff -U0: %v", err)
	}
	hunks := map[string][][2]int{}
	curFile := ""
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "+++ b/") {
			curFile = strings.TrimPrefix(line, "+++ b/")
			continue
		}
		if strings.HasPrefix(line, "@@") && curFile != "" {
			// Parse @@ -start,count +start,count @@
			plus := line[strings.Index(line, "+"):]
			plus = strings.TrimPrefix(plus, "+")
			// Stop at the first space (the rest is @@ context).
			if sp := strings.IndexByte(plus, ' '); sp >= 0 {
				plus = plus[:sp]
			}
			start := 0
			count := 1
			if i := strings.IndexByte(plus, ','); i >= 0 {
				start, _ = strconv.Atoi(plus[:i])
				count, _ = strconv.Atoi(plus[i+1:])
			} else {
				start, _ = strconv.Atoi(plus)
			}
			if count == 0 {
				count = 1
			}
			hunks[curFile] = append(hunks[curFile], [2]int{start, start + count - 1})
		}
	}
	return hunks, nil
}

// lineOf extracts the line number from a node id (file:line:col:type).
func lineOf(nodeID string) int {
	parts := strings.SplitN(nodeID, ":", 3)
	if len(parts) < 2 {
		return 0
	}
	n, _ := strconv.Atoi(parts[1])
	return n
}

// fileOf extracts the file from a node id (file:line:col:type).
func fileOf(nodeID string) string {
	parts := strings.SplitN(nodeID, ":", 2)
	if len(parts) < 2 {
		return nodeID
	}
	return parts[0]
}

func rev(dir, rev string) (string, error) {
	out, err := exec.Command("git", "-C", dir, "rev-parse", rev).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("rev-parse %s: %v", rev, err)
	}
	return strings.TrimSpace(string(out)), nil
}

func worktree(repoDir, name, sha string) (string, error) {
	dir := filepath.Join(repoDir, ".wt", name)
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return "", err
	}
	_ = exec.Command("git", "-C", repoDir, "worktree", "remove", "--force", dir).Run()
	if out, err := exec.Command("git", "-C", repoDir, "worktree", "add", "--detach", dir, sha).CombinedOutput(); err != nil {
		return "", fmt.Errorf("worktree %s: %v: %s", name, err, strings.TrimSpace(string(out)))
	}
	return dir, nil
}

func slug(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		}
		return -1
	}, s)
}
