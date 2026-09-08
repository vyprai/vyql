package lowering

import (
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// flashedInputProgram is one view file whose only statement reads a framework's
// flashed previous input for `field` — Laravel's `old($field)`, as a Blade echo tag
// lowers it.
func flashedInputProgram(file, method, field string) nir.Program {
	loc := file + ":7"
	return nir.Program{Modules: []nir.Module{{
		Key:  "",
		File: file,
		Body: []nir.Stmt{
			nir.ExprStmt{Value: nir.Call{
				Callee: nir.Name{ID: method, Loc: loc},
				Args:   []nir.Expr{nir.Const{Value: "'" + field + "'", Loc: loc}},
				Path:   method, Method: method, Loc: loc,
			}},
		},
	}}}
}

// lowerFlashedInput lowers that program and returns the location of every
// account-enumeration smell it synthesizes.
func lowerFlashedInput(t *testing.T, file, method, field string) []string {
	t.Helper()
	g, err := Lower(flashedInputProgram(file, method, field), true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	ids, err := g.NodesOfType("code.Call")
	if err != nil {
		t.Fatalf("nodes: %v", err)
	}
	var smells []string
	for _, id := range ids {
		n, _, _ := g.GetNode(id)
		if n.Prop("callee_path") == "analysis.smell.user_enum" {
			smells = append(smells, n.Loc)
		}
	}
	return smells
}

// A credential-recovery view that repopulates the submitted account identifier from
// the framework's flashed previous input IS the differential response: the framework
// flashes that input only when the lookup failed, so the field comes back filled in
// for an unknown account and empty for a known one. No status code and no message is
// written anywhere, which is why the response-constructor path cannot see it.
func TestFlashedPreviousInputInRecoveryViewIsUserEnumSmell(t *testing.T) {
	const view = "resources/views/auth/passwords/email.blade.php"
	for _, method := range []string{"old", "getOldInput", "oldInput"} {
		got := lowerFlashedInput(t, view, method, "email")
		if len(got) != 1 || got[0] != view+":7" {
			t.Errorf("%s('email'): user_enum smells = %v, want one at %s:7", method, got, view)
		}
	}
	for _, field := range []string{"email", "username", "login", "handle", "phone"} {
		if got := lowerFlashedInput(t, view, "old", field); len(got) != 1 {
			t.Errorf("old(%q): user_enum smells = %v, want one", field, got)
		}
	}
}

// The fix for CVE-2023-0901 drops the `value="{{ old('email') }}"` attribute, so the
// same view holds no flashed read at all and must stay clean.
func TestRecoveryViewWithoutFlashedInputIsClean(t *testing.T) {
	const view = "resources/views/auth/passwords/email.blade.php"
	prog := nir.Program{Modules: []nir.Module{{Key: "", File: view, Body: []nir.Stmt{
		nir.ExprStmt{Value: nir.Call{
			Callee: nir.Name{ID: "__", Loc: view + ":7"},
			Args:   []nir.Expr{nir.Const{Value: "'E-Mail Address'", Loc: view + ":7"}},
			Path:   "__", Method: "__", Loc: view + ":7",
		}},
	}}}}
	g, err := Lower(prog, true)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	ids, _ := g.NodesOfType("code.Call")
	for _, id := range ids {
		n, _, _ := g.GetNode(id)
		if n.Prop("callee_path") == "analysis.smell.user_enum" {
			t.Fatalf("fixed view still reports a user_enum smell at %s", n.Loc)
		}
	}
}

// The shape is not "a form repopulates itself". A login or registration form does the
// same thing and its failure branch is taken for a wrong password or a duplicate
// address too, and a recovery form repopulating a non-identifier field reveals no
// account. Neither is an oracle, so neither may be reported.
func TestFlashedPreviousInputOutsideTheOracleShapeIsClean(t *testing.T) {
	cases := []struct{ file, field string }{
		{"resources/views/auth/login.blade.php", "email"},
		{"resources/views/auth/register.blade.php", "email"},
		{"resources/views/posts/create.blade.php", "email"},
		{"resources/views/auth/passwords/email.blade.php", "subject"},
		{"resources/views/auth/passwords/reset.blade.php", "token"},
	}
	for _, c := range cases {
		if got := lowerFlashedInput(t, c.file, "old", c.field); len(got) != 0 {
			t.Errorf("%s old(%q): user_enum smells = %v, want none", c.file, c.field, got)
		}
	}
}
