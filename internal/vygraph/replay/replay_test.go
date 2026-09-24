package replay

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/vyprai/vyql/internal/vygraph/pipeline"
)

// The unit gate: a synthetic vulnerable/fixed pair in a local git repository.
// The vulnerable side concatenates untrusted input into a query; the fixed
// side parameterizes it. The differential must fire and silence.
func TestRunRankDifferentialOnSyntheticPair(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	kbDir, err := filepath.Abs("../pipeline/testdata/kb")
	if err != nil {
		t.Fatal(err)
	}

	vulnSrc := `import flask
from db import session

@flask.route("/users")
def list_users(req):
    q = req.args.get("q")
    rows = session.execute("SELECT * FROM users WHERE name = " + q)
    return rows
`
	fixSrc := `import flask
from db import session

@flask.route("/users")
def list_users(req):
    q = req.args.get("q")
    rows = session.execute("SELECT * FROM users WHERE name = :name", {"name": q})
    return rows
`
	cache := filepath.Join(t.TempDir(), "cache")
	vulnDir := filepath.Join(cache, "r1-vuln")
	fixDir := filepath.Join(cache, "r1-fix")
	for d, src := range map[string]string{vulnDir: vulnSrc, fixDir: fixSrc} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "app.py"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, ".replay-done"), []byte("test"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rk := Rank{Rank: 1, Repo: "test", Owner: "local", Host: "", CVE: "CVE-0000-0000", Fix: "unused", Lang: "python"}

	oc, err := RunRank(rk, kbDir, cache, pipeline.Options{})
	if err != nil {
		t.Fatalf("RunRank: %v", err)
	}
	if !oc.Pass {
		t.Fatalf("differential must pass:\n%+v\nnote=%s", oc.Vuln, oc.Note)
	}
	if !strings.Contains(oc.Note, "FULL-INJ-001") {
		t.Fatalf("the firing rule must be the SQL injection family: %s", oc.Note)
	}
}

// The corpus driver: env-gated, never needed by CI.
//
//	VYGRAPH_REPLAY_POOL=/path/to/pool.tsv \
//	VYGRAPH_REPLAY_KB=/path/to/v3-kb \
//	VYGRAPH_REPLAY_LANGS=python \
//	VYGRAPH_REPLAY_LIMIT=20 \
//	  go test -count=1 ./internal/vygraph/replay/ -run TestReplayCorpus -v -timeout 3600s
func TestReplayCorpus(t *testing.T) {
	poolPath := os.Getenv("VYGRAPH_REPLAY_POOL")
	kbDir := os.Getenv("VYGRAPH_REPLAY_KB")
	if poolPath == "" || kbDir == "" {
		t.Skip("corpus replay not configured (VYGRAPH_REPLAY_POOL + VYGRAPH_REPLAY_KB)")
	}
	langs := strings.Split(os.Getenv("VYGRAPH_REPLAY_LANGS"), ",")
	ranks, err := ParsePool(poolPath, langs...)
	if err != nil {
		t.Fatalf("ParsePool: %v", err)
	}
	limit := 0
	if s := os.Getenv("VYGRAPH_REPLAY_LIMIT"); s != "" {
		if limit, err = strconv.Atoi(s); err != nil {
			t.Fatalf("bad VYGRAPH_REPLAY_LIMIT: %v", err)
		}
	}
	cache := os.Getenv("VYGRAPH_REPLAY_CACHE")
	if cache == "" {
		cache = "/tmp/vygraph-replay"
	}
	if err := os.MkdirAll(cache, 0o755); err != nil {
		t.Fatal(err)
	}

	// Concurrent rank execution: 4 ranks in parallel multiplies throughput
	// (the per-rank pipeline is CPU-bound on tree-sitter parsing; running
	// ranks concurrently uses the remaining cores).
	concurrency := 4
	if s := os.Getenv("VYGRAPH_REPLAY_CONCURRENCY"); s != "" {
		if c, err := strconv.Atoi(s); err == nil && c > 0 {
			concurrency = c
		}
	}
	if limit > 0 && limit < len(ranks) {
		ranks = ranks[:limit]
	}
	type result struct {
		rk  Rank
		oc  *Outcome
		err error
	}
	results := make([]result, len(ranks))
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	for i, rk := range ranks {
		wg.Add(1)
		go func(idx int, r Rank) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			oc, err := RunRank(r, kbDir, cache, pipeline.Options{})
			results[idx] = result{rk: r, oc: oc, err: err}
		}(i, rk)
	}
	wg.Wait()

	pass, fail, errN := 0, 0, 0
	for _, res := range results {
		if res.err != nil {
			errN++
			fmt.Printf("rank %-5d %-14s ERROR %v\n", res.rk.Rank, res.rk.CVE, res.err)
			continue
		}
		status := "FAIL"
		if res.oc.Pass {
			status = "PASS"
			pass++
		} else {
			fail++
		}
		fmt.Printf("rank %-5d %-14s %s %s\n", res.rk.Rank, res.rk.CVE, status, res.oc.Note)
	}
	fmt.Printf("TOTAL ranks=%d pass=%d fail=%d error=%d rate=%.1f%%\n",
		pass+fail+errN, pass, fail, errN, 100.0*float64(pass)/float64(pass+fail+errN+1))
}

func initRepo(t *testing.T, files map[string]string, msg string) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, strings.TrimSpace(string(out)))
		}
	}
	run("init", "-q")
	run("config", "user.email", "t@t")
	run("config", "user.name", "t")
	run("config", "commit.gpgsign", "false")
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run("add", "-A")
	run("commit", "-q", "-m", msg)
	return dir
}

func commit(t *testing.T, dir, name, content, msg string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, strings.TrimSpace(string(out)))
		}
	}
	run("add", "-A")
	run("commit", "-q", "-m", msg)
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}
