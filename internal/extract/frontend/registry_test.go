package frontend_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend"
	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/nir"
)

// A Flash .as file has to be claimed by a registered frontend and parsed into calls.
// Until one was, the file was left entirely unparsed: it fell through every language
// filter, contributed no module, and nothing in it could be labelled a source or a
// sink — so no binding and no rule could reach CVE-2013-1942's ExternalInterface.call.
func TestActionScriptFilesAreClaimedAndParsedIntoCalls(t *testing.T) {
	dir := t.TempDir()
	src := `package happyworm.jPlayer {
	import flash.external.ExternalInterface;
	public class Jplayer extends Sprite {
		private var jQuery:String;
		public function Jplayer() {
			jQuery = loaderInfo.parameters.jQuery + "('#" + loaderInfo.parameters.id + "').jPlayer";
			ExternalInterface.call(jQuery, "jPlayerFlashEvent");
		}
	}
}
`
	path := filepath.Join(dir, "Jplayer.as")
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
	if len(claimed) == 0 {
		t.Fatalf("no registered frontend claims %s; a .as file is left unparsed", filepath.Base(path))
	}

	prog, err := lang.Extract([]string{path}, dir)
	if err != nil {
		t.Fatalf("%s frontend: %v", lang.Name, err)
	}
	if len(prog.Modules) != 1 {
		t.Fatalf("%s frontend produced %d modules, want 1", lang.Name, len(prog.Modules))
	}

	seen := map[string]bool{}
	var expr func(nir.Expr)
	var body func([]nir.Stmt)
	expr = func(e nir.Expr) {
		switch x := e.(type) {
		case nir.Call:
			seen["call "+x.Path] = true
			for _, a := range x.Args {
				expr(a)
			}
		case nir.Attr:
			seen["attr "+x.Path] = true
			expr(x.Base)
		case nir.Format:
			for _, p := range x.Parts {
				expr(p)
			}
		}
	}
	body = func(sts []nir.Stmt) {
		for _, st := range sts {
			switch s := st.(type) {
			case nir.ClassDef:
				body(s.Body)
			case nir.FuncDef:
				body(s.Body)
			case nir.Assign:
				expr(s.Value)
			case nir.ExprStmt:
				expr(s.Value)
			}
		}
	}
	body(prog.Modules[0].Body)

	for _, want := range []string{"call ExternalInterface.call", "attr loaderInfo.parameters.jQuery"} {
		if !seen[want] {
			t.Errorf("%s frontend did not produce %q; got %v", lang.Name, want, seen)
		}
	}
}
