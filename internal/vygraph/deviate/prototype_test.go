package deviate

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	fegolang "github.com/vyprai/vyql/internal/vygraph/frontend/golang"
	fejava "github.com/vyprai/vyql/internal/vygraph/frontend/java"
	fejs "github.com/vyprai/vyql/internal/vygraph/frontend/javascript"
	fepython "github.com/vyprai/vyql/internal/vygraph/frontend/python"
	"github.com/vyprai/vyql/internal/vygraph/graph"
	"github.com/vyprai/vyql/internal/vygraph/nir"
)

// The prototype-first gate: run the deviation miner's core arithmetic against
// real repositories before the peer-group schema freezes. Gated behind an env
// var so CI never needs the corpus; the quoted numbers land in the committing
// message.
//
//	VYGRAPH_DEVIATE_CORPUS=/tmp/proto-corpus:~/parked-rebase207/.stress-corpora \
//	  go test -count=1 ./internal/vygraph/deviate/ -run TestPrototypeOnRealRepos -v

var guardSeeds = []Hint{
	{Glob: "*auth*", Concept: "AuthorizationCheck"},
	{Glob: "*permission*", Concept: "AuthorizationCheck"},
	{Glob: "*login*", Concept: "AuthenticationCheck"},
	{Glob: "*session*", Concept: "AuthenticationCheck"},
	{Glob: "*csrf*", Concept: "CsrfCheck"},
	{Glob: "*verify*", Concept: "VerificationCheck"},
	{Glob: "*check*", Concept: "GuardCheck"},
	{Glob: "*secure*", Concept: "SecureCheck"},
}

func TestPrototypeOnRealRepos(t *testing.T) {
	roots := os.Getenv("VYGRAPH_DEVIATE_CORPUS")
	if roots == "" {
		t.Skip("prototype corpus not configured (VYGRAPH_DEVIATE_CORPUS)")
	}
	var repos []string
	for _, root := range strings.Split(roots, ":") {
		root = expandHome(root)
		if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
			continue
		}
		if strings.Contains(root, "proto-corpus") {
			entries, _ := os.ReadDir(root)
			for _, e := range entries {
				if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
					repos = append(repos, filepath.Join(root, e.Name()))
				}
			}
			continue
		}
		// stress corpora: one repo per language dir
		for _, lang := range []string{"python", "javascript", "go", "java"} {
			p := filepath.Join(root, lang)
			if fi, err := os.Stat(p); err == nil && fi.IsDir() {
				repos = append(repos, p)
			}
		}
	}
	if len(repos) < 5 {
		t.Fatalf("prototype needs >=5 real repos, found %d", len(repos))
	}

	totalGroups, qualifying, outliers, largest := 0, 0, 0, 0
	for _, repo := range repos {
		g := extractRepo(t, repo)
		// Members: functions. Peer key candidates: (a) the enclosing module
		// (file), (b) the enclosing class. Feature: any call in the function
		// whose callee matches a guard seed.
		fnFile := map[string]string{}
		for _, fd := range g.NodesOfType("code.FuncDef") {
			fv, _ := fd.Fields.Get("file")
			nv, _ := fd.Fields.Get("name")
			fnFile[fd.ID] = fv.S
			_ = nv
		}
		guardCallees := map[string]bool{}
		for _, c := range g.NodesOfType("code.Call") {
			cv, _ := c.Fields.Get("callee")
			for _, h := range guardSeeds {
				if HintMatches(strings.ToLower(cv.S), h.Glob) {
					guardCallees[c.ID] = true
				}
			}
		}
		// Function-scoped feature detection: a call carries the feature for the
		// function whose region prefix encloses it (per-function, not per-file —
		// the coarse file grouping produced zero qualifying groups in the first
		// run, which is the prototype's own verdict on granularity).
		fnCarries := map[string]bool{}
		funcs := g.NodesOfType("code.FuncDef")
		for cid := range guardCallees {
			c, ok := g.Node(cid)
			if !ok {
				continue
			}
			cv, _ := c.Fields.Get("file")
			cr, _ := c.Fields.Get("region")
			for _, f := range funcs {
				fv, _ := f.Fields.Get("file")
				fr, _ := f.Fields.Get("region")
				if fv.S != cv.S || fr.S == "" {
					continue
				}
				if cr.S == fr.S || strings.HasPrefix(cr.S, fr.S+"/") {
					fnCarries[f.ID] = true
				}
			}
		}

		var members []string
		for id := range fnFile {
			members = append(members, id)
		}
		res := Deviate(members,
			func(m string) string { return fnFile[m] },
			func(m string) bool { return fnCarries[m] },
			Params{MinGroup: 8, Threshold: 0.8},
		)
		groups := map[string][]string{}
		for _, m := range members {
			k := fnFile[m]
			if k == "" {
				continue
			}
			groups[k] = append(groups[k], m)
		}
		totalGroups += len(groups)
		qualifying += countQualifying(groups, fnCarries, fnFile)
		outliers += len(res)
		for _, mem := range groups {
			if len(mem) > largest {
				largest = len(mem)
			}
		}
		carry := 0
		for _, m := range members {
			if fnCarries[m] {
				carry++
			}
		}
		fmt.Printf("repo %-45s funcs=%-5d files=%-5d guardcalls=%-5d carrying=%-5d outliers=%d\n",
			filepath.Base(repo), len(members), len(groups), len(guardCallees), carry, len(res))
	}
	fmt.Printf("TOTAL groups=%d qualifying=%d outliers=%d largest_group=%d\n",
		totalGroups, qualifying, outliers, largest)
	if totalGroups == 0 {
		t.Fatal("no peer groups formed — the corpus did not exercise grouping")
	}
}

func countQualifying(groups map[string][]string, hasGuard map[string]bool, fnFile map[string]string) int {
	n := 0
	for _, mem := range groups {
		if len(mem) < 8 {
			continue
		}
		c := 0
		for _, m := range mem {
			if hasGuard[fnFile[m]] {
				c++
			}
		}
		if float64(c)/float64(len(mem)) >= 0.8 {
			n++
		}
	}
	return n
}

func extractRepo(t *testing.T, repo string) *graph.Store {
	t.Helper()
	s := graph.NewSchemas()
	if err := nir.Register(s); err != nil {
		t.Fatal(err)
	}
	g := graph.New(s)
	lang := detectLang(repo)
	var files []string
	filepath.Walk(repo, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			if fi != nil && fi.IsDir() && (strings.HasPrefix(fi.Name(), ".") || fi.Name() == "node_modules" || fi.Name() == "vendor" || fi.Name() == "test") {
				return filepath.SkipDir
			}
			return nil
		}
		if len(files) >= 400 {
			return filepath.SkipAll
		}
		switch filepath.Ext(p) {
		case exts[lang]:
			files = append(files, p)
		}
		return nil
	})
	sort.Strings(files)
	for i, p := range files {
		if i >= 250 {
			break
		}
		src, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		rel, _ := filepath.Rel(repo, p)
		switch lang {
		case "python":
			if fe := fepython.New(g); fe.Extract(rel, src) != nil {
				continue
			}
		case "javascript":
			if fe := fejs.New(g); fe.Extract(rel, src) != nil {
				continue
			}
		case "go":
			if fe := fegolang.New(g); fe.Extract(rel, src) != nil {
				continue
			}
		case "java":
			if fe := fejava.New(g); fe.Extract(rel, src) != nil {
				continue
			}
		}
	}
	return g
}

var exts = map[string]string{
	"python": ".py", "javascript": ".js", "go": ".go", "java": ".java",
}

func detectLang(repo string) string {
	base := strings.ToLower(filepath.Base(repo))
	parent := strings.ToLower(filepath.Base(filepath.Dir(repo)))
	switch {
	case parent == "python" || strings.Contains(base, "flask") || strings.Contains(base, "drf") ||
		strings.Contains(base, "certbot") || strings.Contains(base, "cpython"):
		return "python"
	case parent == "javascript" || strings.Contains(base, "express") || strings.Contains(base, "npm"):
		return "javascript"
	case parent == "go" || strings.Contains(base, "gin") || strings.Contains(base, "kubernetes") || strings.Contains(base, "etcd"):
		return "go"
	case parent == "java":
		return "java"
	}
	return "python"
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, strings.TrimPrefix(p, "~"))
	}
	return p
}
