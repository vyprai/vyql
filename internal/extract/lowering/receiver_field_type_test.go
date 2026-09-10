package lowering

import (
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// phpPropertyWrite is the NIR PHP's frontend lowers `$this->field = <expr>` to: a
// Method-less call on the accessed property, so path mappings can match writes.
func phpPropertyWrite(loc, field string, value nir.Expr) nir.Stmt {
	return nir.ExprStmt{Value: nir.Call{
		Callee: nir.Attr{Base: nir.Name{ID: "$this", Loc: loc}, Attr: field, Path: "$this." + field, Loc: loc},
		Args:   []nir.Expr{value},
		Path:   "$this." + field, Loc: loc,
	}}
}

// phpPropertyRead is the receiver half of `$this->field->method()` — the property access the
// method call is made on.
func phpPropertyRead(loc, field string) nir.Expr {
	return nir.Attr{Base: nir.Name{ID: "$this", Loc: loc}, Attr: field, Path: "$this." + field, Loc: loc}
}

// pdoCtor is `new PDO(...)`: a construction whose callee path a binding's ReceiverType fact
// names, so the lowering knows the type of what it returns.
func pdoCtor(loc string) nir.Expr {
	return nir.Call{Callee: nir.Name{ID: "PDO", Loc: loc}, Path: "PDO", Method: "PDO", Loc: loc, IsCtor: true}
}

// phpClassWithTypedProperty lowers a class whose constructor builds a PDO into `$this->pdo`
// and whose `q` method calls through that property. `writes` replaces the constructor body's
// single property write, so a test can vary what the field is built from.
func phpClassWithTypedProperty(writes ...nir.Stmt) nir.Program {
	return nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "Repo.php",
		Body: []nir.Stmt{
			nir.ClassDef{Name: "Repo", Members: []string{"pdo"}, Body: []nir.Stmt{
				nir.FuncDef{Name: "__construct", Body: writes, Loc: "Repo.php:3"},
				nir.FuncDef{Name: "q", Params: []string{"s"}, Body: []nir.Stmt{
					nir.Return{Value: nir.Call{
						Callee: nir.Attr{Base: phpPropertyRead("Repo.php:7", "pdo"), Attr: "query", Path: "$this.pdo.query", Loc: "Repo.php:7"},
						Args:   []nir.Expr{nir.Name{ID: "s", Loc: "Repo.php:7"}},
						Path:   "$this.pdo.query", Method: "query", Loc: "Repo.php:7",
					}},
				}, Loc: "Repo.php:6"},
			}, Loc: "Repo.php:2"},
		},
	}}}
}

// The shape every PHP framework writes: an object built in one method is stored on `$this`
// and called through that property in another. The property read is a value whose type the
// construction on the write side determines, so the method call carries that type and a
// binding may constrain its receiver by it — the same stamp a plain local holding the
// constructor's result already gets.
func TestLowerTypesAReceiverReadOffAPropertyBuiltByAKnownConstructor(t *testing.T) {
	prog := phpClassWithTypedProperty(phpPropertyWrite("Repo.php:4", "pdo", pdoCtor("Repo.php:4")))
	g, err := LowerTyped(prog, true, map[string]string{"PDO": "PDO"})
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	id := findNodeID(t, g, "code.Call", "callee_path", "$this.pdo.query")
	n, _, _ := g.GetNode(id)
	if got := n.Prop("recv_type"); got != "PDO" {
		t.Fatalf("recv_type = %q, want PDO; props=%+v", got, n.Props)
	}
}

// A construction the scan itself declares types the field the same way, under the class's own
// name — the controller-holds-its-model shape.
func TestLowerTypesAPropertyBuiltByADeclaredClassConstructor(t *testing.T) {
	ctor := nir.Call{Callee: nir.Name{ID: "Item_model", Loc: "C.php:4"}, Path: "Item_model", Method: "Item_model", Loc: "C.php:4", IsCtor: true}
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "C.php",
		Body: []nir.Stmt{
			nir.ClassDef{Name: "Item_model", Body: []nir.Stmt{
				nir.FuncDef{Name: "list_items", Params: []string{"q"}, Body: []nir.Stmt{
					nir.Return{Value: nir.Name{ID: "q", Loc: "M.php:2"}},
				}, Loc: "M.php:1"},
			}, Loc: "M.php:1"},
			nir.ClassDef{Name: "Items", Members: []string{"model"}, Body: []nir.Stmt{
				nir.FuncDef{Name: "__construct", Body: []nir.Stmt{
					phpPropertyWrite("C.php:4", "model", ctor),
				}, Loc: "C.php:3"},
				nir.FuncDef{Name: "index", Params: []string{"q"}, Body: []nir.Stmt{
					nir.Return{Value: nir.Call{
						Callee: nir.Attr{Base: phpPropertyRead("C.php:7", "model"), Attr: "list_items", Path: "$this.model.list_items", Loc: "C.php:7"},
						Args:   []nir.Expr{nir.Name{ID: "q", Loc: "C.php:7"}},
						Path:   "$this.model.list_items", Method: "list_items", Loc: "C.php:7",
					}},
				}, Loc: "C.php:6"},
			}, Loc: "C.php:2"},
		},
	}}}
	g, err := LowerTyped(prog, true, nil)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	id := findNodeID(t, g, "code.Call", "callee_path", "$this.model.list_items")
	n, _, _ := g.GetNode(id)
	if got := n.Prop("recv_type"); got != "Item_model" {
		t.Fatalf("recv_type = %q, want Item_model; props=%+v", got, n.Props)
	}
}

// A field any write builds from something else is not a field of one type, and a type
// withheld is the only honest answer: a sink reading this stamp to REJECT a receiver must
// never reject one on a type the field may not have.
func TestLowerWithholdsAPropertyTypeItsWritesDisagreeOn(t *testing.T) {
	prog := phpClassWithTypedProperty(
		phpPropertyWrite("Repo.php:4", "pdo", pdoCtor("Repo.php:4")),
		phpPropertyWrite("Repo.php:5", "pdo", nir.Name{ID: "other", Loc: "Repo.php:5"}),
	)
	g, err := LowerTyped(prog, true, map[string]string{"PDO": "PDO"})
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	id := findNodeID(t, g, "code.Call", "callee_path", "$this.pdo.query")
	n, _, _ := g.GetNode(id)
	if got := n.Prop("recv_type"); got != "" {
		t.Fatalf("recv_type = %q, want empty: the field is also written from a value with no known type", got)
	}
}

// A construction the constructor table does not name is no evidence of a type, so the field
// stays untyped rather than inheriting one.
func TestLowerWithholdsAPropertyTypeNoConstructorNames(t *testing.T) {
	prog := phpClassWithTypedProperty(phpPropertyWrite("Repo.php:4", "pdo",
		nir.Call{Callee: nir.Name{ID: "fopen", Loc: "Repo.php:4"}, Path: "fopen", Method: "fopen", Loc: "Repo.php:4"}))
	g, err := LowerTyped(prog, true, map[string]string{"PDO": "PDO"})
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	id := findNodeID(t, g, "code.Call", "callee_path", "$this.pdo.query")
	n, _, _ := g.GetNode(id)
	if got := n.Prop("recv_type"); got != "" {
		t.Fatalf("recv_type = %q, want empty: no constructor fact names fopen's result", got)
	}
}

// A subclass reads the property its base class's constructor built: the field the write names
// belongs to the base, so the lookup walks up to the class that writes it.
func TestLowerTypesAPropertyInheritedFromTheBaseThatBuildsIt(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "Base.php",
		Body: []nir.Stmt{
			nir.ClassDef{Name: "Base_Controller", Members: []string{"db"}, Body: []nir.Stmt{
				nir.FuncDef{Name: "__construct", Body: []nir.Stmt{
					phpPropertyWrite("Base.php:4", "db", pdoCtor("Base.php:4")),
				}, Loc: "Base.php:3"},
			}, Loc: "Base.php:2"},
			nir.ClassDef{Name: "Items", Bases: []string{"Base_Controller"}, Body: []nir.Stmt{
				nir.FuncDef{Name: "q", Params: []string{"s"}, Body: []nir.Stmt{
					nir.Return{Value: nir.Call{
						Callee: nir.Attr{Base: phpPropertyRead("Items.php:3", "db"), Attr: "query", Path: "$this.db.query", Loc: "Items.php:3"},
						Args:   []nir.Expr{nir.Name{ID: "s", Loc: "Items.php:3"}},
						Path:   "$this.db.query", Method: "query", Loc: "Items.php:3",
					}},
				}, Loc: "Items.php:2"},
			}, Loc: "Items.php:1"},
		},
	}}}
	g, err := LowerTyped(prog, true, map[string]string{"PDO": "PDO"})
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	id := findNodeID(t, g, "code.Call", "callee_path", "$this.db.query")
	n, _, _ := g.GetNode(id)
	if got := n.Prop("recv_type"); got != "PDO" {
		t.Fatalf("recv_type = %q, want PDO; props=%+v", got, n.Props)
	}
}

// A field the class declares for itself shadows the base's: the base's write fills a different
// property, so its type says nothing about this one.
func TestLowerWithholdsAFieldTheClassDeclaresButNeverBuilds(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "Base.php",
		Body: []nir.Stmt{
			nir.ClassDef{Name: "Base_Controller", Members: []string{"db"}, Body: []nir.Stmt{
				nir.FuncDef{Name: "__construct", Body: []nir.Stmt{
					phpPropertyWrite("Base.php:4", "db", pdoCtor("Base.php:4")),
				}, Loc: "Base.php:3"},
			}, Loc: "Base.php:2"},
			nir.ClassDef{Name: "Items", Bases: []string{"Base_Controller"}, Members: []string{"db"}, Body: []nir.Stmt{
				nir.FuncDef{Name: "q", Params: []string{"s"}, Body: []nir.Stmt{
					nir.Return{Value: nir.Call{
						Callee: nir.Attr{Base: phpPropertyRead("Items.php:3", "db"), Attr: "query", Path: "$this.db.query", Loc: "Items.php:3"},
						Args:   []nir.Expr{nir.Name{ID: "s", Loc: "Items.php:3"}},
						Path:   "$this.db.query", Method: "query", Loc: "Items.php:3",
					}},
				}, Loc: "Items.php:2"},
			}, Loc: "Items.php:1"},
		},
	}}}
	g, err := LowerTyped(prog, true, map[string]string{"PDO": "PDO"})
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	id := findNodeID(t, g, "code.Call", "callee_path", "$this.db.query")
	n, _, _ := g.GetNode(id)
	if got := n.Prop("recv_type"); got != "" {
		t.Fatalf("recv_type = %q, want empty: this class declares its own db and writes nothing into it", got)
	}
}

// The stamp the property path now carries is the one a plain local already carried, so this
// is the baseline the property case is brought up to.
func TestLowerStillTypesAPlainLocalAssignedFromAKnownConstructor(t *testing.T) {
	prog := nir.Program{Modules: []nir.Module{{
		Key:  "app",
		File: "Repo.php",
		Body: []nir.Stmt{
			nir.FuncDef{Name: "q", Params: []string{"s"}, Body: []nir.Stmt{
				nir.Assign{Targets: []string{"db"}, Value: pdoCtor("Repo.php:2"), Loc: "Repo.php:2"},
				nir.ExprStmt{Value: nir.Call{
					Callee: nir.Attr{Base: nir.Name{ID: "db", Loc: "Repo.php:3"}, Attr: "query", Path: "db.query", Loc: "Repo.php:3"},
					Args:   []nir.Expr{nir.Name{ID: "s", Loc: "Repo.php:3"}},
					Path:   "db.query", Method: "query", Loc: "Repo.php:3",
				}},
			}, Loc: "Repo.php:1"},
		},
	}}}
	g, err := LowerTyped(prog, true, map[string]string{"PDO": "PDO"})
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	id := findNodeID(t, g, "code.Call", "callee_path", "db.query")
	n, _, _ := g.GetNode(id)
	if got := n.Prop("recv_type"); got != "PDO" {
		t.Fatalf("recv_type = %q, want PDO; props=%+v", got, n.Props)
	}
}
