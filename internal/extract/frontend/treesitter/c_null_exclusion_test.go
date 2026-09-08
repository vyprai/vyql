package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// ccNullExclusionFacts runs the null-exclusion observation over one C or C++
// source and returns the emitted facts, one string per fact: the fact's path
// followed by its tokens, semicolon-joined.
func ccNullExclusionFacts(t *testing.T, name, src string) []string {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, name)
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	extract := ExtractC
	if strings.HasSuffix(name, ".cpp") {
		extract = ExtractCPP
	}
	prog, err := extract([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, st := range prog.Modules[0].Body {
		fn, ok := st.(nir.FuncDef)
		if !ok {
			continue
		}
		for _, s := range fn.Body {
			es, ok := s.(nir.ExprStmt)
			if !ok {
				continue
			}
			call, ok := es.Value.(nir.Call)
			if !ok || !strings.HasPrefix(call.Path, "analysis.null_exclusion.") {
				continue
			}
			parts := []string{call.Path}
			for _, a := range call.Args {
				if konst, ok := a.(nir.Const); ok {
					parts = append(parts, konst.Value)
				}
			}
			out = append(out, strings.Join(parts, ";"))
		}
	}
	return out
}

// ccOneNullExclusionFact insists on a single fact and returns it.
func ccOneNullExclusionFact(t *testing.T, what, name, src string) string {
	t.Helper()
	got := ccNullExclusionFacts(t, name, src)
	if len(got) != 1 {
		t.Fatalf("%s: got %q, want exactly one null-exclusion fact", what, got)
	}
	return got[0]
}

// The libsolv namespace arm of CVE-2018-20532, at the parent of the fix and at
// the fix. The two revisions differ in one operator, and that operator is the
// whole vulnerability: `!s ||` false proves s non-null on the else path, `!s &&`
// false proves nothing. Both revisions dereference, both store the result of the
// same call, and every other token of the function is identical, so a fact that
// does not read the connective cannot tell them apart.
const (
	ccNullGuardConjunctive = `
#include <string.h>
void pool_error(void *pool, int e, const char *fmt, ...);
int testcase_read_namespace(void *pool, char **pieces)
{
  int i = strlen(pieces[1]);
  char *s = strchr(pieces[1], '(');
  if (!s && pieces[1][i - 1] != ')')
    pool_error(pool, 0, "testcase_read: bad namespace '%s'", pieces[1]);
  else
    {
      *s = 0;
      pieces[1][i - 1] = 0;
      *s = '(';
    }
  return 0;
}
`
	ccNullGuardDisjunctive = `
#include <string.h>
void pool_error(void *pool, int e, const char *fmt, ...);
int testcase_read_namespace(void *pool, char **pieces)
{
  int i = strlen(pieces[1]);
  char *s = strchr(pieces[1], '(');
  if (!s || pieces[1][i - 1] != ')')
    pool_error(pool, 0, "testcase_read: bad namespace '%s'", pieces[1]);
  else
    {
      *s = 0;
      pieces[1][i - 1] = 0;
      *s = '(';
    }
  return 0;
}
`
)

// TestCNullExclusionReadsTheConnective is the gap itself: the guarded and the
// unguarded revision of one function must not label identically.
func TestCNullExclusionReadsTheConnective(t *testing.T) {
	vulnerable := ccOneNullExclusionFact(t, "conjunctive guard", "testcase.c", ccNullGuardConjunctive)
	fixed := ccOneNullExclusionFact(t, "disjunctive guard", "testcase.c", ccNullGuardDisjunctive)
	if vulnerable == fixed {
		t.Fatalf("the two revisions label identically: %q", vulnerable)
	}
	for _, want := range []string{
		"analysis.null_exclusion.unguarded_deref",
		"source=strchr",
		"use=dereference",
		"exclusion=none",
		"guard=null_test_not_excluding",
		"connective=conjunction",
	} {
		if !strings.Contains(vulnerable, want) {
			t.Errorf("conjunctive guard: fact %q is missing %q", vulnerable, want)
		}
	}
	for _, want := range []string{
		"analysis.null_exclusion.deref",
		"source=strchr",
		"exclusion=guarded",
		"guard=branch_null_test",
		"connective=disjunction",
	} {
		if !strings.Contains(fixed, want) {
			t.Errorf("disjunctive guard: fact %q is missing %q", fixed, want)
		}
	}
}

// TestCNullExclusionCreditsTheGuardOnThePath covers the guards that do make the
// stored pointer non-null where it is used, each named by the fact.
func TestCNullExclusionCreditsTheGuardOnThePath(t *testing.T) {
	guarded := map[string]struct{ src, guard string }{
		"the early-abort guard returns when the pointer is null": {`
int use(void) {
  char *s = get();
  if (!s)
    return 1;
  *s = 0;
  return 0;
}
`, "guard=early_return_null_test"},
		"the early-abort guard goes to the error label": {`
int use(void) {
  char *s = get();
  if (s == NULL) goto err;
  *s = 0;
  return 0;
err:
  return 1;
}
`, "guard=early_return_null_test"},
		"the early-abort guard leaves when either disjunct holds": {`
int use(int x) {
  char *s = get();
  if (!s || x)
    return 1;
  *s = 0;
  return 0;
}
`, "guard=early_return_null_test"},
		"the use sits in the branch the test asserts": {`
int use(void) {
  char *s = get();
  if (s != NULL) { *s = 0; }
  return 0;
}
`, "guard=branch_null_test"},
		"the null test is one conjunct of the branch that uses it": {`
int use(int x) {
  char *s = get();
  if (s && x) { *s = 0; }
  return 0;
}
`, "guard=branch_null_test"},
		"the negated conjunction excludes null on its else": {`
int use(int x) {
  char *s = get();
  if (!(s && x))
    fail();
  else
    *s = 0;
  return 0;
}
`, "guard=branch_null_test"},
		"the short-circuit operand is only evaluated when the test holds": {`
int use(void) {
  struct t *s = get();
  return s && s->x;
}
`, "guard=short_circuit_null_test"},
		"the right operand of a disjunction runs when the null test fails": {`
int use(void) {
  struct t *s = get();
  return !s || s->x;
}
`, "guard=short_circuit_null_test"},
		"the conditional's arm the test selects": {`
int use(void) {
  struct t *s = get();
  return s ? s->x : 0;
}
`, "guard=branch_null_test"},
		"a file-local check macro tests the argument it was handed": {`
#define CHECK(p) do { if (!p) return -1; } while (0)
int use(void) {
  char *s = get();
  CHECK(s);
  *s = 0;
  return 0;
}
`, "guard=macro_null_check"},
		"the guard is an outer if and the use is nested under it": {`
int use(int x) {
  char *s = get();
  if (s != NULL) {
    if (x) {
      while (x--) { *s = 0; }
    }
  }
  return 0;
}
`, "guard=branch_null_test"},
	}
	for name, tc := range guarded {
		fact := ccOneNullExclusionFact(t, name, "guard.c", tc.src)
		if !strings.Contains(fact, "analysis.null_exclusion.deref;") || !strings.Contains(fact, "exclusion=guarded") {
			t.Errorf("%s: fact %q does not record the exclusion", name, fact)
		}
		if !strings.Contains(fact, tc.guard) {
			t.Errorf("%s: fact %q does not name the guard %q", name, fact, tc.guard)
		}
	}
}

// TestCNullExclusionRecordsWhenNothingExcludesNull pins the other direction. A
// guard that does not hold on the path to the use, or that is not about this
// pointer, or that ran before the store it is credited against, leaves the
// dereference reachable with the pointer null.
func TestCNullExclusionRecordsWhenNothingExcludesNull(t *testing.T) {
	unguarded := map[string]struct{ src, guard string }{
		"no test at all stands between the store and the use": {`
int use(void) {
  char *s = get();
  *s = 0;
  return 0;
}
`, "guard=none"},
		"the pointer is null in the branch that uses it": {`
int use(int x) {
  char *s = get();
  if (!s && x)
    *s = 0;
  return 0;
}
`, "guard=null_test_not_excluding"},
		"the test is about something else": {`
int use(int x) {
  char *s = get();
  if (x > 2) { *s = 0; }
  return 0;
}
`, "guard=none"},
		"the null test neither returns nor branches around the use": {`
int use(void) {
  char *s = get();
  if (!s) { note(); }
  *s = 0;
  return 0;
}
`, "guard=null_test_not_excluding"},
		"the use is the arm the test did not select": {`
int use(void) {
  struct t *s = get();
  return s ? 0 : s->x;
}
`, "guard=null_test_not_excluding"},
		"the conjunction reaches the use with the pointer null": {`
int use(void) {
  struct t *s = get();
  return !s && s->x;
}
`, "guard=null_test_not_excluding"},
		"the early-abort guard leaves only when both conjuncts hold": {`
int use(int x) {
  char *s = get();
  if (!s && x)
    return 1;
  *s = 0;
  return 0;
}
`, "guard=null_test_not_excluding"},
		"the guard tested an earlier value of the pointer": {`
int use(void) {
  char *s = get();
  if (!s) return 1;
  s = get_again();
  *s = 0;
  return 0;
}
`, "guard=none"},
		"the test ran before the store it would have to cover": {`
int use(void) {
  char *s = 0;
  if (!s) { note(); }
  s = get();
  *s = 0;
  return 0;
}
`, "guard=none"},
		"the dereference is inside the test's own condition": {`
int use(void) {
  char *s = get();
  if (*s == 'a') return 1;
  return 0;
}
`, "guard=none"},
	}
	for name, tc := range unguarded {
		fact := ccOneNullExclusionFact(t, name, "unguarded.c", tc.src)
		if !strings.Contains(fact, "analysis.null_exclusion.unguarded_deref;") || !strings.Contains(fact, "exclusion=none") {
			t.Errorf("%s: fact %q does not record the missing exclusion", name, fact)
		}
		if !strings.Contains(fact, tc.guard) {
			t.Errorf("%s: fact %q does not name the guard %q", name, fact, tc.guard)
		}
	}
}

// TestCNullExclusionUseKinds covers what counts as a use: the accesses that
// fault when the pointer is null, and nothing else.
func TestCNullExclusionUseKinds(t *testing.T) {
	uses := map[string]string{
		"dereference": `
int use(void) {
  char *s = get();
  return *s;
}
`,
		"member": `
int use(void) {
  struct t *s = get();
  return s->x;
}
`,
		"subscript": `
int use(void) {
  char *s = get();
  return s[2];
}
`,
	}
	for kind, src := range uses {
		fact := ccOneNullExclusionFact(t, kind, "use.c", src)
		if !strings.Contains(fact, "use="+kind) {
			t.Errorf("%s: fact %q does not name the use", kind, fact)
		}
	}

	// A read that does not fault is not a use, and neither is a member read out
	// of a value that no call result was stored into.
	nonUses := map[string]string{
		"the pointer is only passed on": `
int use(void) {
  char *s = get();
  return other(s + 1, s);
}
`,
		"the member read is out of a struct value": `
int use(void) {
  struct t v = make();
  return v.x;
}
`,
		"the local holds no call result": `
int use(char *p) {
  char *s = p;
  return *s;
}
`,
	}
	for name, src := range nonUses {
		if got := ccNullExclusionFacts(t, "nonuse.c", src); len(got) != 0 {
			t.Errorf("%s: got %q, want no fact", name, got)
		}
	}
}

// TestCNullExclusionCPlusPlusSpelling covers the C++ grammar's two differences:
// the condition sits under a condition_clause, and the store is written through
// a named cast that is itself spelled as a call.
func TestCNullExclusionCPlusPlusSpelling(t *testing.T) {
	const guarded = `
struct T { int x; };
int use() {
  T *p = static_cast<T *>(make());
  if (p == nullptr)
    return 1;
  return p->x;
}
`
	fact := ccOneNullExclusionFact(t, "cpp guarded", "use.cpp", guarded)
	for _, want := range []string{"analysis.null_exclusion.deref;", "source=make", "exclusion=guarded", "guard=early_return_null_test"} {
		if !strings.Contains(fact, want) {
			t.Errorf("cpp guarded: fact %q is missing %q", fact, want)
		}
	}

	const unguarded = `
struct T { int x; };
int use(int c) {
  T *p = static_cast<T *>(make());
  if (p == nullptr && c)
    return 1;
  return p->x;
}
`
	fact = ccOneNullExclusionFact(t, "cpp unguarded", "use.cpp", unguarded)
	for _, want := range []string{"analysis.null_exclusion.unguarded_deref;", "exclusion=none", "guard=null_test_not_excluding", "connective=conjunction"} {
		if !strings.Contains(fact, want) {
			t.Errorf("cpp unguarded: fact %q is missing %q", fact, want)
		}
	}
}
