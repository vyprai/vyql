package lowering

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vyprai/vyql/internal/extract/frontend/treesitter"
	"github.com/vyprai/vyql/internal/extract/nir"
	"github.com/vyprai/vyql/internal/usg"
)

// A member call on a receiver whose type nothing declares — Ruby's `def handle(repo, params)`
// calling `repo.checkout(params)` — has no typed route left: the receiver is not a known class,
// not a declared local, not a module global. What remains is the unique-method-name fallback,
// and a class that declares a CLASS-LEVEL method of the name beside an INSTANCE one (`def
// self.checkout` beside `def checkout`) makes the name two declarations in the language, so the
// fallback refused as ambiguous and taint stopped at the call. For a receiver that is not the
// class itself the class-level half is not a candidate at all, so the fallback takes the
// instance declaration, exactly as it takes a name the program declares once.
func TestUntypedReceiverResolvesTheInstanceHalfOfAStaticInstancePair(t *testing.T) {
	prog := nir.Program{SelfName: "self", Modules: []nir.Module{{
		Key:  "",
		File: "app/repo.rb",
		Body: []nir.Stmt{
			nir.ClassDef{Name: "Repo", Loc: "app/repo.rb:1", Body: []nir.Stmt{
				nir.FuncDef{Name: "checkout", Static: true, Params: []string{"url"}, Loc: "app/repo.rb:2", Body: []nir.Stmt{
					nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: "system", Loc: "app/repo.rb:3"},
						Args:   []nir.Expr{nir.Name{ID: "url", Loc: "app/repo.rb:3"}},
						Path:   "system", Method: "system", Loc: "app/repo.rb:3",
					}},
				}},
				// the instance method, declared last so it is the one a name-keyed table keeps
				nir.FuncDef{Name: "checkout", Params: []string{"name"}, Loc: "app/repo.rb:6", Body: []nir.Stmt{
					nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: "log", Loc: "app/repo.rb:7"},
						Args:   []nir.Expr{nir.Name{ID: "name", Loc: "app/repo.rb:7"}},
						Path:   "log", Method: "log", Loc: "app/repo.rb:7",
					}},
				}},
			}},
			// `repo` is a parameter nothing types: the receiver's class is unknown at the call
			nir.FuncDef{Name: "handle", Params: []string{"repo", "params"}, Loc: "app/repo.rb:11", Body: []nir.Stmt{
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Attr{Base: nir.Name{ID: "repo", Loc: "app/repo.rb:12"},
						Attr: "checkout", Path: "repo.checkout", Loc: "app/repo.rb:12"},
					Args: []nir.Expr{nir.Name{ID: "params", Loc: "app/repo.rb:12"}},
					Path: "repo.checkout", Method: "checkout", Loc: "app/repo.rb:12",
				}},
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	src := findNodeID(t, g, "code.Param", "name", "params", "func", "handle")
	reachable, err := usg.BFS(g, src, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[findNodeID(t, g, "code.Arg", "loc", "app/repo.rb:7")] {
		t.Fatalf("repo.checkout's argument did not reach the instance declaration's body: the " +
			"class-level method of the same name made the fallback refuse and taint stopped at the call")
	}
	if reachable[findNodeID(t, g, "code.Arg", "loc", "app/repo.rb:3")] {
		t.Fatalf("repo.checkout's argument reached the class-level declaration's body, which no " +
			"instance receiver can invoke")
	}
}

// The halves need not share a class. `View#render` beside `Other.render` is two classes each
// declaring the name, and the class-level one is still not a candidate for `view.render(...)` —
// no instance of anything invokes it — so the unique instance declaration is what the fallback
// takes, as it would were `Other.render` named something else entirely.
func TestUntypedReceiverIgnoresAClassLevelDeclarationOnAnotherClass(t *testing.T) {
	prog := nir.Program{SelfName: "self", Modules: []nir.Module{{
		Key:  "",
		File: "app/view.rb",
		Body: []nir.Stmt{
			nir.ClassDef{Name: "View", Loc: "app/view.rb:1", Body: []nir.Stmt{
				nir.FuncDef{Name: "render", Params: []string{"name"}, Loc: "app/view.rb:2", Body: []nir.Stmt{
					nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: "log", Loc: "app/view.rb:3"},
						Args:   []nir.Expr{nir.Name{ID: "name", Loc: "app/view.rb:3"}},
						Path:   "log", Method: "log", Loc: "app/view.rb:3",
					}},
				}},
			}},
			nir.ClassDef{Name: "Other", Loc: "app/view.rb:6", Body: []nir.Stmt{
				nir.FuncDef{Name: "render", Static: true, Params: []string{"url"}, Loc: "app/view.rb:7", Body: []nir.Stmt{
					nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: "system", Loc: "app/view.rb:8"},
						Args:   []nir.Expr{nir.Name{ID: "url", Loc: "app/view.rb:8"}},
						Path:   "system", Method: "system", Loc: "app/view.rb:8",
					}},
				}},
			}},
			nir.FuncDef{Name: "handle", Params: []string{"view", "params"}, Loc: "app/view.rb:11", Body: []nir.Stmt{
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Attr{Base: nir.Name{ID: "view", Loc: "app/view.rb:12"},
						Attr: "render", Path: "view.render", Loc: "app/view.rb:12"},
					Args: []nir.Expr{nir.Name{ID: "params", Loc: "app/view.rb:12"}},
					Path: "view.render", Method: "render", Loc: "app/view.rb:12",
				}},
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	src := findNodeID(t, g, "code.Param", "name", "params", "func", "handle")
	reachable, err := usg.BFS(g, src, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[findNodeID(t, g, "code.Arg", "loc", "app/view.rb:3")] {
		t.Fatalf("view.render's argument did not reach View#render, the only instance declaration " +
			"of the name: the class-level declaration on another class still made the fallback refuse")
	}
	if reachable[findNodeID(t, g, "code.Arg", "loc", "app/view.rb:8")] {
		t.Fatalf("view.render's argument reached Other.render's body, which no instance receiver " +
			"can invoke")
	}
}

// The uniqueness guard itself is untouched: two INSTANCE declarations of the name, on any
// classes, still leave the call unresolved, because there the receiver really could run either
// body and a name-keyed guess would be a vote between two.
func TestUntypedReceiverKeepsRefusingTwoInstanceDeclarations(t *testing.T) {
	prog := nir.Program{SelfName: "self", Modules: []nir.Module{{
		Key:  "",
		File: "app/view.rb",
		Body: []nir.Stmt{
			nir.ClassDef{Name: "View", Loc: "app/view.rb:1", Body: []nir.Stmt{
				nir.FuncDef{Name: "render", Params: []string{"name"}, Loc: "app/view.rb:2", Body: []nir.Stmt{
					nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: "log", Loc: "app/view.rb:3"},
						Args:   []nir.Expr{nir.Name{ID: "name", Loc: "app/view.rb:3"}},
						Path:   "log", Method: "log", Loc: "app/view.rb:3",
					}},
				}},
			}},
			nir.ClassDef{Name: "Other", Loc: "app/view.rb:6", Body: []nir.Stmt{
				nir.FuncDef{Name: "render", Params: []string{"url"}, Loc: "app/view.rb:7", Body: []nir.Stmt{
					nir.ExprStmt{Value: nir.Call{
						Callee: nir.Name{ID: "system", Loc: "app/view.rb:8"},
						Args:   []nir.Expr{nir.Name{ID: "url", Loc: "app/view.rb:8"}},
						Path:   "system", Method: "system", Loc: "app/view.rb:8",
					}},
				}},
			}},
			nir.FuncDef{Name: "handle", Params: []string{"view", "params"}, Loc: "app/view.rb:11", Body: []nir.Stmt{
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Attr{Base: nir.Name{ID: "view", Loc: "app/view.rb:12"},
						Attr: "render", Path: "view.render", Loc: "app/view.rb:12"},
					Args: []nir.Expr{nir.Name{ID: "params", Loc: "app/view.rb:12"}},
					Path: "view.render", Method: "render", Loc: "app/view.rb:12",
				}},
			}},
		},
	}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	src := findNodeID(t, g, "code.Param", "name", "params", "func", "handle")
	reachable, err := usg.BFS(g, src, "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if reachable[findNodeID(t, g, "code.Arg", "loc", "app/view.rb:3")] {
		t.Fatalf("view.render resolved to View#render although a second class declares an " +
			"instance method of the name")
	}
	if reachable[findNodeID(t, g, "code.Arg", "loc", "app/view.rb:8")] {
		t.Fatalf("view.render resolved to Other#render although a second class declares an " +
			"instance method of the name")
	}
}

// The same shape spelled in the language itself, so the frontend's part in it — `def self.x`
// arriving flagged as a class-level declaration, and `repo.checkout(...)` arriving as a member
// call on a receiver nothing types — is pinned beside the lowering's.
func TestRubySourceUntypedReceiverResolvesTheInstanceHalfOfAStaticInstancePair(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "repo.rb")
	src := `class Repo
  def self.checkout(url)
    system("git", url)
  end

  def checkout(name)
    log(name)
  end
end

def handle(repo, params)
  repo.checkout(params)
end
`
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractRuby([]string{file}, dir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	reachable, err := usg.BFS(g, findNodeID(t, g, "code.Param", "name", "params", "func", "handle"), "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[findNodeID(t, g, "code.Param", "name", "name", "func", "checkout")] {
		t.Fatalf("repo.checkout's argument did not reach the instance checkout's parameter: the " +
			"class-level method of the same name made the fallback refuse and taint stopped at the call")
	}
	if reachable[findNodeID(t, g, "code.Param", "name", "url", "func", "checkout")] {
		t.Fatalf("repo.checkout's argument reached the class-level checkout's parameter, which no " +
			"instance receiver can invoke")
	}
}

// Rank 3385's own spelling. The instance method is declared inside a `Struct.new(...) do … end`
// block, which the frontend attributes to the enclosing module, so the two declarations of the
// name sit on DIFFERENT classes and a same-class rule would not reach the pair at all; and the
// receiver is an `each` block parameter, which nothing types. The call that carries the request
// into the instance body is the one the fallback has to answer.
func TestRubySourceStructBlockInstanceMethodResolvesOverTheEigenclassCollision(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "database.rb")
	src := `module SequenceServer
  Database = Struct.new(:name, :title) do
    def retrieve(accession, coords = nil)
      log(accession)
    end
  end

  class Database
    class << self
      def retrieve(loci)
        loci.split(',').each do |locus|
          accession, coords = locus.split(':')
          each do |database|
            database.retrieve(accession, coords)
          end
        end
      end
    end
  end
end
`
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractRuby([]string{file}, dir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	reachable, err := usg.BFS(g, findNodeID(t, g, "code.Param", "name", "loci"), "FLOWS", 40)
	if err != nil {
		t.Fatal(err)
	}
	if !reachable[findNodeID(t, g, "code.Param", "name", "accession", "func", "retrieve")] {
		t.Fatalf("database.retrieve(accession, coords) did not carry its argument into the instance " +
			"retrieve's parameter: the eigenclass method of the same name made the fallback refuse")
	}
}
