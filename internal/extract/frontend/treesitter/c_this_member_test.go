package treesitter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// cppFieldStoreCall finds the call with the given path anywhere in the program,
// descending through class bodies the C helper does not visit.
func cppFieldStoreCall(prog nir.Program, path string) (nir.Call, bool) {
	var found nir.Call
	ok := false
	var walkStmts func([]nir.Stmt)
	walkExpr := func(e nir.Expr) {
		call, isCall := e.(nir.Call)
		if isCall && call.Path == path {
			found, ok = call, true
		}
	}
	walkStmts = func(stmts []nir.Stmt) {
		for _, s := range stmts {
			switch st := s.(type) {
			case nir.ExprStmt:
				walkExpr(st.Value)
			case nir.Assign:
				walkExpr(st.Value)
			case nir.FuncDef:
				walkStmts(st.Body)
			case nir.ClassDef:
				walkStmts(st.Body)
			case nir.Block:
				walkStmts(st.Stmts)
			case nir.If:
				walkStmts(st.Then)
				walkStmts(st.Else)
			}
		}
	}
	for _, m := range prog.Modules {
		walkStmts(m.Body)
	}
	return found, ok
}

// extractCPPSource parses one C++ source of the package's tests.
func extractCPPSource(t *testing.T, name, src string) nir.Program {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, name)
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := ExtractCPP([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(prog.Modules) != 1 {
		t.Fatalf("modules = %d, want 1", len(prog.Modules))
	}
	return prog
}

// `this` inside a C++ method is the implicit receiver every member selection runs
// through. It used to fall through c.expr's switch to the Seq catch-all, so each
// occurrence minted a fresh empty node: `this->data = v` stored into a container
// nothing else could name and `this->data` read a different one, in the same
// method as much as across methods. Lowered as the self NAME the other
// implicit-this frontends use, it resolves to the class's one stable self node.
func TestCPPThisIsTheSelfName(t *testing.T) {
	prog := extractCPPSource(t, "codec.cpp", `
class Codec {
    int m_frameSize;
public:
    void Init(FILE *fp) {
        this->m_frameSize = read_int(fp);
    }
};
`)
	store, ok := cppFieldStoreCall(prog, "this.m_frameSize")
	if !ok {
		t.Fatalf("no field-write call for this->m_frameSize: %#v", prog.Modules[0].Body)
	}
	attr, ok := store.Callee.(nir.Attr)
	if !ok || attr.Attr != "m_frameSize" {
		t.Fatalf("field write callee = %#v, want an Attr naming the field", store.Callee)
	}
	base, ok := attr.Base.(nir.Name)
	if !ok || base.ID != "this" {
		t.Fatalf("field write base = %#v, want the self name `this`", attr.Base)
	}
}

// A class's declared data members ride on its ClassDef, which is what a bare
// member reference in a method resolves against. Method declarations are
// field_declarations too and must not contribute.
func TestCPPClassCarriesItsDataMemberNames(t *testing.T) {
	prog := extractCPPSource(t, "codec.cpp", `
class Codec {
    int m_frameSize;
    char *m_name, *m_desc;
    void Init(FILE *fp);
public:
    int m_channels;
};
`)
	var cd nir.ClassDef
	found := false
	for _, s := range prog.Modules[0].Body {
		if c, ok := s.(nir.ClassDef); ok {
			cd, found = c, true
		}
	}
	if !found {
		t.Fatalf("no ClassDef for Codec: %#v", prog.Modules[0].Body)
	}
	want := map[string]bool{"m_frameSize": true, "m_name": true, "m_desc": true, "m_channels": true}
	seen := map[string]bool{}
	for _, m := range cd.Members {
		seen[m] = true
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("member %q missing from ClassDef; got %v", name, cd.Members)
		}
	}
	for _, m := range cd.Members {
		if m == "Init" {
			t.Errorf("method declaration %q recorded as a data member; got %v", m, cd.Members)
		}
	}
}

// A struct spells the same members with struct_specifier, and its ClassDef
// carries them the same way.
func TestCPPStructCarriesItsDataMemberNames(t *testing.T) {
	prog := extractCPPSource(t, "fmt.cpp", `
struct Format {
    int frameSize;
    int channels;
    void setup();
};
`)
	for _, s := range prog.Modules[0].Body {
		if cd, ok := s.(nir.ClassDef); ok && cd.Name == "Format" {
			seen := map[string]bool{}
			for _, m := range cd.Members {
				seen[m] = true
			}
			if !seen["frameSize"] || !seen["channels"] {
				t.Fatalf("struct members = %v, want frameSize and channels", cd.Members)
			}
			if seen["setup"] {
				t.Fatalf("method declaration recorded as a data member: %v", cd.Members)
			}
			return
		}
	}
	t.Fatalf("no ClassDef for Format: %#v", prog.Modules[0].Body)
}
