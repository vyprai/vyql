package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// ccDefiniteAssignmentObs runs the definite-assignment observation over one
// translation unit and returns the emitted facts as
// "loc|variable=..;init=..;read=..;carried_from=.." text.
func ccDefiniteAssignmentObs(t *testing.T, file, src string) []string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, file)
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	extract := ExtractC
	if strings.HasSuffix(file, ".cpp") {
		extract = ExtractCPP
	}
	prog, err := extract([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	var walk func([]nir.Stmt)
	walk = func(body []nir.Stmt) {
		for _, st := range body {
			switch s := st.(type) {
			case nir.ClassDef:
				walk(s.Body)
			case nir.FuncDef:
				walk(s.Body)
			case nir.ExprStmt:
				call, ok := s.Value.(nir.Call)
				// spelled out rather than referring to the constant, so
				// that the case still builds -- and fails -- without the
				// observation this file is the evidence for.
				if !ok || call.Path != "analysis.definite_assignment.loop_read_not_established_by_init" {
					continue
				}
				var parts []string
				for _, a := range call.Args {
					if konst, ok := a.(nir.Const); ok {
						parts = append(parts, konst.Value)
					}
				}
				out = append(out, call.Loc+"|"+strings.Join(parts, ";"))
			}
		}
	}
	walk(prog.Modules[0].Body)
	return out
}

// expandPrompt is sudo's check.c reduced to the shape CVE-2002-0184 turns on:
// one loop sizes the expansion and a second performs it, and `lastchar` -- the
// flag the substitution branch tests -- is per-run state the second loop's init
// clause does not establish. %s is that init clause.
const expandPrompt = `#include <string.h>
#include <stdlib.h>

char *user_shost;
char *user_name;
void *emalloc(size_t);

static char *
expand_prompt(old_prompt, user, host)
    char *old_prompt;
    char *user;
    char *host;
{
    size_t len;
    int subst;
    char *p, *np, *new_prompt, lastchar;

    subst = 0;
    for (p = old_prompt, len = strlen(old_prompt), lastchar = '\0'; *p; p++) {
	if (lastchar == '%') {
	    if (*p == 'h') {
		len += strlen(user_shost) - 2;
		subst = 1;
	    }
	}
	if (lastchar == '%' && *p == '%') {
	    lastchar = '\0';
	    len--;
	} else
	    lastchar = *p;
    }

    if (subst) {
	new_prompt = (char *) emalloc(len + 1);
	for (%s; *p; p++) {
	    if (lastchar == '%' && (*p == 'h' || *p == '%')) {
		np--;
		strcpy(np, user_shost);
		np += strlen(user_shost);
	    } else
		*np++ = *p;

	    if (lastchar == '%' && *p == '%')
		lastchar = '\0';
	    else
		lastchar = *p;
	}
	*np = '\0';
    } else
	new_prompt = old_prompt;

    return (new_prompt);
}
`

// TestCCDefiniteAssignmentSeparatesTheSudoRevisions is the gap itself: the
// vulnerable copy loop and the fixed one differ by one clause of one
// expression, and every token either revision produces the other produces too
// -- `assign:lastchar='\0'` stands at both, because the sizing loop's init
// clause already spells it. The fact is what tells them apart.
func TestCCDefiniteAssignmentSeparatesTheSudoRevisions(t *testing.T) {
	vulnerable := strings.Replace(expandPrompt, "%s", "p = old_prompt, np = new_prompt", 1)
	got := ccDefiniteAssignmentObs(t, "check.c", vulnerable)
	if len(got) != 1 {
		t.Fatalf("vulnerable revision: want 1 fact, got %d: %v", len(got), got)
	}
	for _, want := range []string{
		"check.c:35|",
		"variable=lastchar",
		"init=p=old_prompt,np=new_prompt",
		"read=lastchar=='%'",
		"carried_from=check.c:30",
	} {
		if !strings.Contains(got[0], want) {
			t.Errorf("vulnerable revision: fact %q missing %q", got[0], want)
		}
	}

	fixed := strings.Replace(expandPrompt, "%s", "p = old_prompt, np = new_prompt, lastchar = '\\0'", 1)
	if got := ccDefiniteAssignmentObs(t, "check.c", fixed); len(got) != 0 {
		t.Errorf("fixed revision: want no fact, got %v", got)
	}
}

// carryBase is the sudo shape reduced to its bones, and it fires: a routine
// that establishes `last` in one loop's init clause, carries it through that
// loop's body, and reads it in a second loop whose init clause forgot it.
const carryBase = `void f(char *s)
{
	char *p, last;

	for (p = s, last = '\0'; *p; p++)
		last = *p;
	for (p = s; *p; p++) {
		if (last == '%')
			sink(p);
		last = *p;
	}
}
`

// TestCCDefiniteAssignmentQuietShapes changes one thing about the firing shape
// per case, so each case is the evidence for one condition rather than a
// snippet that happens to be quiet.
func TestCCDefiniteAssignmentQuietShapes(t *testing.T) {
	if got := ccDefiniteAssignmentObs(t, "base.c", carryBase); len(got) != 1 {
		t.Fatalf("the base shape must fire, or these cases prove nothing: got %v", got)
	}
	cases := []struct {
		name string
		from string
		to   string
	}{
		{
			"the loop's own init clause establishes it",
			"for (p = s; *p; p++) {",
			"for (p = s, last = '\\0'; *p; p++) {",
		},
		{
			"a straight-line assignment above the loop establishes it",
			"	for (p = s; *p; p++) {",
			"	last = '\\0';\n	for (p = s; *p; p++) {",
		},
		{
			"the declaration establishes it",
			"char *p, last;",
			"char *p, last = '\\0';",
		},
		{
			"no init clause established it anywhere",
			"for (p = s, last = '\\0'; *p; p++)",
			"for (p = s; *p; p++)",
		},
		{
			"only an init clause wrote it, so its value is definite",
			"	for (p = s, last = '\\0'; *p; p++)\n		last = *p;",
			"	for (p = s, last = '\\0'; *p; p++)\n		sink(p);",
		},
		{
			"the reading loop has no init clause of its own",
			"	for (p = s; *p; p++) {",
			"	p = s;\n	for (; *p; p++) {",
		},
		{
			"the body writes it before reading it",
			"		if (last == '%')\n			sink(p);\n		last = *p;",
			"		last = *p;\n		if (last == '%')\n			sink(p);",
		},
		{
			"the loop continues it rather than replacing it",
			"		last = *p;\n	}",
			"		last += *p;\n	}",
		},
		{
			"the routine handed the local's address out",
			"	for (p = s, last",
			"	read_last(&last);\n	for (p = s, last",
		},
		{
			"an inner block redeclares the name",
			"	for (p = s; *p; p++) {",
			"	for (p = s; *p; p++) {\n		char last;",
		},
		{
			"the two loops are the arms of one if/else",
			"	for (p = s, last = '\\0'; *p; p++)\n		last = *p;\n	for (p = s; *p; p++) {",
			"	if (*s) {\n	for (p = s, last = '\\0'; *p; p++)\n		last = *p;\n	} else\n	for (p = s; *p; p++) {",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := strings.Replace(carryBase, tc.from, tc.to, 1)
			if src == carryBase {
				t.Fatalf("case did not change the base shape")
			}
			if got := ccDefiniteAssignmentObs(t, "quiet.c", src); len(got) != 0 {
				t.Errorf("want no fact, got %v\nsource:\n%s", got, src)
			}
		})
	}
}

// TestCCDefiniteAssignmentLiftedFunction pins the same fact on a definition the
// frontend does lift, so the observation is not tied to the K&R spelling that
// motivated it.
func TestCCDefiniteAssignmentLiftedFunction(t *testing.T) {
	src := `
void f(char *s)
{
	char *p, last;
	int n;

	for (p = s, n = 0, last = '\0'; *p; p++) {
		last = *p;
		n++;
	}
	for (p = s, n = 0; *p; p++) {
		if (last == '%')
			sink(p);
		last = *p;
	}
}
`
	got := ccDefiniteAssignmentObs(t, "lifted.c", src)
	if len(got) != 1 {
		t.Fatalf("want 1 fact, got %d: %v", len(got), got)
	}
	for _, want := range []string{"lifted.c:11|", "variable=last", "init=p=s,n=0", "read=last=='%'", "carried_from=lifted.c:8"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("fact %q missing %q", got[0], want)
		}
	}
}
