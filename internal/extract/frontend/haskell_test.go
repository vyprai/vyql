package frontend_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend"
	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/lowering"
)

// A Haskell .hs file has to be claimed by a registered frontend and parsed into
// calls. Until one was, the file fell through every language filter, contributed
// no module, and no call inside it could be labelled a source or a sink — so no
// binding, and no rule, reached any of it.
func TestHaskellFilesAreClaimedAndParsedIntoCalls(t *testing.T) {
	dir := t.TempDir()
	src := `module Upload.Handler where

import qualified Data.Text as T
import Database.MySQL.Simple (query)

handleUpload cfg raw = do
  let name = T.unpack raw
      greeting = "upload " ++ name
  rows <- query conn "insert into files values (?)" [greeting]
  report rows
`
	path := filepath.Join(dir, "Handler.hs")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	entries := treesitter.ListAllFiles(dir)
	class := frontend.ClassifyEntries(entries)
	var claimed []string
	var lang frontend.Language
	for _, lg := range frontend.Languages() {
		for _, f := range lg.FilesFor(entries, class) {
			if f == path {
				claimed = append(claimed, lg.Name)
				lang = lg
			}
		}
	}
	if len(claimed) != 1 {
		t.Fatalf("%d frontends claim %s (%v); a .hs file is left unparsed", len(claimed), filepath.Base(path), claimed)
	}

	prog, err := lang.Extract([]string{path}, dir)
	if err != nil {
		t.Fatalf("%s frontend: %v", lang.Name, err)
	}
	if len(prog.Modules) != 1 {
		t.Fatalf("%s frontend produced %d modules, want 1", lang.Name, len(prog.Modules))
	}

	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	calls, _ := g.NodesOfType("code.Call")
	var paths []string
	for _, id := range calls {
		n, _, _ := g.GetNode(id)
		paths = append(paths, n.Prop("callee_path"))
	}
	for _, want := range []string{"T.unpack", "query", "report"} {
		found := false
		for _, p := range paths {
			if strings.Contains(p, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s frontend produced no call matching %q; got %v", lang.Name, want, paths)
		}
	}
}
