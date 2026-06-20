package golang_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	gofrontend "github.com/vyprai/vyql/extract/frontend/golang"
	"github.com/vyprai/vyql/extract/lowering"
)

func TestGoFunctionContextIncludesIndexAndSliceTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mysql.go")
	src := []byte(`package mysql

import "fmt"

func parse(readBuffer []byte) string {
	capabilities := fmt.Sprintf("%08b", uint32(readBuffer[4]))
	return string(capabilities[8]) + string(readBuffer[36:][0])
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := gofrontend.Extract([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.function.context" {
			continue
		}
		tokens := n.Prop("str_args")
		if strings.Contains(tokens, "function_name:parse") &&
			strings.Contains(tokens, "index:readBuffer:4") &&
			strings.Contains(tokens, "index:capabilities:8") &&
			strings.Contains(tokens, "slice:readBuffer:36:") {
			return
		}
	}
	t.Fatalf("Go function context did not include index/slice tokens; nodes=%#v", nodes)
}
