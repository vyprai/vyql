package ontology

import "testing"

func build(t *testing.T) *Ontology {
	t.Helper()
	o := New()
	for _, c := range []Concept{
		{Name: "UntrustedData", Kinds: []Kind{KindSource}, Taint: []string{"UntrustedData"}},
		{Name: "UserControlledData", Kinds: []Kind{KindSource}, Refines: "UntrustedData"},
		{Name: "HttpInput", Kinds: []Kind{KindSource}, Refines: "UserControlledData", Taint: []string{"UntrustedData"}},
		{Name: "QueryParam", Kinds: []Kind{KindSource}, Refines: "HttpInput"},
		{Name: "SqlExecution", Kinds: []Kind{KindSink}, VulnerableTo: []string{"Injection"}, EnabledBy: []string{"UntrustedData"}},
		{Name: "SqlParameterization", Kinds: []Kind{KindControl}, Neutralizes: []string{"Injection"}},
		{Name: "AuthenticationCheck", Kinds: []Kind{KindGuard}, Defends: []string{"Idor"}},
		{Name: "CentralAuthGate", Kinds: []Kind{KindControl, KindGuard}, Neutralizes: []string{"MissingAuthorization"}, Defends: []string{"Idor"}},
	} {
		if err := o.Add(c); err != nil {
			t.Fatalf("Add(%s): %v", c.Name, err)
		}
	}
	return o
}

func TestIsAIsTransitiveAndReflexiveOverRefines(t *testing.T) {
	o := build(t)
	if !o.IsA("QueryParam", "UntrustedData") {
		t.Error("IsA must be transitive through the refines chain")
	}
	if !o.IsA("HttpInput", "HttpInput") {
		t.Error("IsA must be reflexive")
	}
	if o.IsA("UntrustedData", "QueryParam") {
		t.Error("IsA must not be symmetric")
	}
	if o.IsA("SqlExecution", "UntrustedData") {
		t.Error("unrelated concepts must not be related")
	}
}

func TestAddRejectsUnknownParentAndDuplicate(t *testing.T) {
	o := build(t)
	if err := o.Add(Concept{Name: "Orphan", Kinds: []Kind{KindSource}, Refines: "Nope"}); err == nil {
		t.Fatal("a concept naming an unknown refines parent must be rejected")
	}
	if err := o.Add(Concept{Name: "HttpInput", Kinds: []Kind{KindSource}}); err == nil {
		t.Fatal("a duplicate concept must be rejected")
	}
}

func TestAddRejectsBadKinds(t *testing.T) {
	o := build(t)
	// kind outside the closed set
	if err := o.Add(Concept{Name: "Bad1", Kinds: []Kind{Kind("threat")}}); err == nil {
		t.Fatal("a kind outside the closed ten-kind set must be rejected")
	}
	// dual-role is ONLY [control, guard]
	if err := o.Add(Concept{Name: "Bad2", Kinds: []Kind{KindSource, KindSink}}); err == nil {
		t.Fatal("a multi-kind concept other than [control, guard] must be rejected")
	}
	if err := o.Add(Concept{Name: "Bad3", Kinds: []Kind{KindControl, KindControl}}); err == nil {
		t.Fatal("duplicate kinds must be rejected")
	}
}

func TestAddRejectsCycleViaReparent(t *testing.T) {
	o := New()
	_ = o.Add(Concept{Name: "A", Kinds: []Kind{KindSource}})
	_ = o.Add(Concept{Name: "B", Kinds: []Kind{KindSource}, Refines: "A"})
	if err := o.Reparent("A", "B"); err == nil {
		t.Fatal("closing a cycle must be rejected — IsA would not terminate")
	}
}

func TestOfKindProjectsDualRoleIntoBothPools(t *testing.T) {
	o := build(t)
	count := func(k Kind) int {
		n := 0
		for _, c := range o.OfKind(k) {
			n++
			_ = c
		}
		return n
	}
	if got := count(KindSink); got != 1 {
		t.Fatalf("OfKind(sink) = %d, want 1", got)
	}
	if got := count(KindSource); got != 4 {
		t.Fatalf("OfKind(source) = %d, want 4 (UntrustedData, UserControlledData, HttpInput, QueryParam)", got)
	}
	// CentralAuthGate is dual-role: it must appear in BOTH pools.
	inControl, inGuard := false, false
	for _, c := range o.OfKind(KindControl) {
		if c.Name == "CentralAuthGate" {
			inControl = true
		}
	}
	for _, c := range o.OfKind(KindGuard) {
		if c.Name == "CentralAuthGate" {
			inGuard = true
		}
	}
	if !inControl || !inGuard {
		t.Fatalf("dual-role concept must project into both pools: control=%v guard=%v", inControl, inGuard)
	}
}
