package parser

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestAdaptersAvoidLegacyStructuredTokenHasSyntax(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	adapterRoot := filepath.Join(root, "vyql", "adapters")
	legacy := regexp.MustCompile(`\b(?:has|lacks)\s+"(?:call_path|literal|selector|identifier|function_name|class_name|class_base|class_bases|attr_path|decorator_path|decorator_method|param_name|param_type|param_index|var_name|return):`)

	var hits []string
	err := filepath.WalkDir(adapterRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".vyql" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		for i, line := range strings.Split(string(data), "\n") {
			if legacy.MatchString(line) {
				hits = append(hits, rel+":"+strconv.Itoa(i+1)+": "+strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) > 0 {
		t.Fatalf("use structured flag predicates such as `call path`, `literal`, `selector`, `function`, or `token <name>` instead of legacy structured-token has/lacks:\n%s", strings.Join(hits, "\n"))
	}
}
