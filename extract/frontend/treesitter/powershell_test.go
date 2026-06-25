package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/nir"
)

func TestPowerShellForeachStaticInvocationsAreExtracted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "win_unzip.ps1")
	src := []byte(`
Function Extract-Zip($src, $dest) {
    foreach ($entry in $archive.Entries) {
        $archive_name = $entry.FullName
        $entry_target_path = [System.IO.Path]::Combine($dest, $archive_name)
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $entry_target_path, $true)
    }
}
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractPowerShell([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fn, ok := findFuncDef(prog, "Extract-Zip")
	if !ok {
		t.Fatalf("Extract-Zip was not extracted; program=%#v", prog)
	}

	paths := psCallPaths(fn.Body)
	if !containsPathSuffix(paths, "System.IO.Path.Combine") {
		t.Fatalf("foreach body did not include System.IO.Path.Combine; paths=%v body=%#v", paths, fn.Body)
	}
	if !containsPathSuffix(paths, "System.IO.Compression.ZipFileExtensions.ExtractToFile") {
		t.Fatalf("foreach body did not include System.IO.Compression.ZipFileExtensions.ExtractToFile; paths=%v body=%#v", paths, fn.Body)
	}
}

func psCallPaths(stmts []nir.Stmt) []string {
	var out []string
	var walkExpr func(nir.Expr)
	walkExpr = func(e nir.Expr) {
		switch v := e.(type) {
		case nir.Call:
			out = append(out, v.Path)
			for _, arg := range v.Args {
				walkExpr(arg)
			}
		case nir.Attr:
			walkExpr(v.Base)
		case nir.Format:
			for _, part := range v.Parts {
				walkExpr(part)
			}
		case nir.Seq:
			for _, part := range v.Parts {
				walkExpr(part)
			}
		case nir.Thru:
			walkExpr(v.Inner)
		}
	}
	var walkStmts func([]nir.Stmt)
	walkStmts = func(items []nir.Stmt) {
		for _, st := range items {
			switch s := st.(type) {
			case nir.Assign:
				walkExpr(s.Value)
			case nir.ExprStmt:
				walkExpr(s.Value)
			case nir.Return:
				walkExpr(s.Value)
			case nir.Block:
				walkStmts(s.Stmts)
			case nir.If:
				walkStmts(s.Then)
				walkStmts(s.Else)
			case nir.Loop:
				walkStmts(s.Body)
			case nir.Try:
				walkStmts(s.Body)
				for _, h := range s.Handlers {
					walkStmts(h)
				}
			}
		}
	}
	walkStmts(stmts)
	return out
}

func containsPathSuffix(paths []string, suffix string) bool {
	for _, path := range paths {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}
