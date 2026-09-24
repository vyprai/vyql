// Package replay is the v3 conversion gate: for a corpus rank (a real
// repository at its vulnerable and fixed commits), run the v3 pipeline with a
// v3 knowledge base on both sides and require the differential — the same
// rule, at the same file, firing on the vulnerable side and silent on the
// fixed side. This is the rolling per-batch replay; the full spec parity
// replay is the later cutover gate, not this one.
package replay

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

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
	// Tarball-based replay: download the two trees directly from the host's
	// archive endpoint instead of git-cloning — large repos (the java corpus)
	// bottleneck on clone metadata even blobless; an archive fetch is
	// proportional to the tree size alone.
	key := slug(rk.Owner + "-" + rk.Repo + "-" + rk.CVE)
	vulnDir := filepath.Join(cacheDir, key+"-vuln")
	fixDir := filepath.Join(cacheDir, key+"-fix")
	for _, dl := range []struct {
		dir string
		rev string
	}{
		{vulnDir, rk.Fix + "^"},
		{fixDir, rk.Fix},
	} {
		if _, err := os.Stat(filepath.Join(dl.dir, ".replay-done")); err == nil {
			continue // cached from a prior run
		}
		if err := os.RemoveAll(dl.dir); err != nil {
			return nil, err
		}
		// The fix SHA is already known (from the pool); only the parent
		// needs resolving, via the GitHub commit API (ls-remote cannot
		// resolve raw SHAs or sha^ expressions).
		var sha string
		var err error
		if strings.HasSuffix(dl.rev, "^") {
			sha, err = parentSHA(rk.Owner, rk.Repo, rk.Fix)
			if err != nil {
				return nil, fmt.Errorf("resolve parent of %s: %w", rk.Fix, err)
			}
		} else {
			sha = rk.Fix
		}
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", dl.rev, err)
		}
		tarURL := fmt.Sprintf("https://%s/%s/%s/archive/%s.tar.gz", rk.Host, rk.Owner, rk.Repo, sha)
		if err := fetchTarball(tarURL, dl.dir); err != nil {
			return nil, fmt.Errorf("fetch %s: %w", tarURL, err)
		}
		if err := os.WriteFile(filepath.Join(dl.dir, ".replay-done"), []byte(sha), 0o644); err != nil {
			return nil, err
		}
	}

	vulnRes, err := pipeline.Run(vulnDir, kbDir, opts)
	if err != nil {
		return nil, fmt.Errorf("vulnerable run: %w", err)
	}
	fixRes, err := pipeline.Run(fixDir, kbDir, opts)
	if err != nil {
		return nil, fmt.Errorf("fixed run: %w", err)
	}

	// The focused differential: only findings in files that differ between
	// the two trees count. Unrelated noise elsewhere survives on both sides.
	touched, err := diffTrees(vulnDir, fixDir)
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

// diffTrees returns the set of files that differ between two directory trees.
func diffTrees(aDir, bDir string) (map[string]bool, error) {
	files := map[string]bool{}
	var walk func(rel string, dir string, into map[string]string) error
	walk = func(rel string, dir string, into map[string]string) error {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil // unreadable subtree: skip
		}
		for _, e := range entries {
			name := rel
			if name == "" {
				name = e.Name()
			} else {
				name = name + "/" + e.Name()
			}
			full := filepath.Join(dir, e.Name())
			if e.IsDir() {
				if err := walk(name, full, into); err != nil {
					return err
				}
				continue
			}
			data, err := os.ReadFile(full)
			if err != nil {
				continue
			}
			into[name] = string(data)
		}
		return nil
	}
	aFiles := map[string]string{}
	bFiles := map[string]string{}
	if err := walk("", aDir, aFiles); err != nil {
		return nil, err
	}
	if err := walk("", bDir, bFiles); err != nil {
		return nil, err
	}
	for name, aData := range aFiles {
		bData, ok := bFiles[name]
		if !ok || aData != bData {
			files[name] = true
		}
	}
	for name := range bFiles {
		if _, ok := aFiles[name]; !ok {
			files[name] = true
		}
	}
	return files, nil
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

// revRemote resolves a rev to a SHA via ls-remote (no clone needed).
func revRemote(url, rev string) (string, error) {
	out, err := exec.Command("git", "ls-remote", url, rev).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ls-remote %s %s: %v", url, rev, err)
	}
	line := strings.TrimSpace(string(out))
	if line == "" {
		return "", fmt.Errorf("ls-remote: no ref %s", rev)
	}
	return strings.Fields(line)[0], nil
}

// parentSHA resolves a commit's first parent SHA via the GitHub API,
// retrying with backoff on rate-limit 403s (unauthenticated: 60/hour).
var apiMu sync.Mutex // serialize API calls to avoid burst rate-limiting

func parentSHA(owner, repo, sha string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits/%s", owner, repo, sha)
	var resp *http.Response
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		apiMu.Lock()
		resp, err = http.Get(url)
		apiMu.Unlock()
		if err != nil {
			return "", err
		}
		if resp.StatusCode == 200 {
			break
		}
		if resp.StatusCode == 403 || resp.StatusCode == 429 {
			resp.Body.Close()
			time.Sleep(time.Duration(attempt+1) * 5 * time.Second)
			continue
		}
		resp.Body.Close()
		return "", fmt.Errorf("GitHub API HTTP %d", resp.StatusCode)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("GitHub API HTTP %d after retries", resp.StatusCode)
	}
	var commit struct {
		Parents []struct {
			SHA string `json:"sha"`
		} `json:"parents"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&commit); err != nil {
		return "", err
	}
	if len(commit.Parents) == 0 {
		return "", fmt.Errorf("commit %s has no parent (root commit)", sha)
	}
	return commit.Parents[0].SHA, nil
}

// fetchTarball downloads and extracts a GitHub archive tarball into dir.
func fetchTarball(url, dir string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		// The tarball has a top-level directory (repo-sha); strip it.
		name := hdr.Name
		if i := strings.IndexByte(name, '/'); i >= 0 {
			name = name[i+1:]
		} else {
			continue // the top-level directory entry itself
		}
		if name == "" {
			continue
		}
		target := filepath.Join(dir, filepath.FromSlash(name))
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.Create(target)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		case tar.TypeSymlink:
			_ = os.Symlink(hdr.Linkname, target)
		}
	}
	return nil
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
