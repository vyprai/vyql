package treesitter_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/nir"
)

func TestRubySingletonClassMethodsAreExtracted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bibliography.rb")
	src := []byte(`class Bibliography
  class << self
    def open(path, options = {})
      parse(Kernel.open(path, 'r:UTF-8').read, options)
    end
  end
end
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractRuby([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !rubyHasFuncWithParam(prog.Modules, "open", "path") {
		t.Fatalf("singleton class method open(path) was not extracted; program=%#v", prog)
	}
}

func rubyHasFuncWithParam(mods []nir.Module, name, param string) bool {
	var walk func([]nir.Stmt) bool
	walk = func(stmts []nir.Stmt) bool {
		for _, st := range stmts {
			switch x := st.(type) {
			case nir.FuncDef:
				if x.Name == name {
					for _, p := range x.Params {
						if p == param {
							return true
						}
					}
				}
				if walk(x.Body) {
					return true
				}
			case nir.ClassDef:
				if walk(x.Body) {
					return true
				}
			case nir.Block:
				if walk(x.Stmts) {
					return true
				}
			}
		}
		return false
	}
	for _, mod := range mods {
		if walk(mod.Body) {
			return true
		}
	}
	return false
}
