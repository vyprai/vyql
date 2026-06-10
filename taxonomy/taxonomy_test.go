package taxonomy

import "testing"

func TestCatalogLoads(t *testing.T) {
	c := Std()
	nCWE, nCAPEC := c.Counts()
	if nCWE < 900 {
		t.Fatalf("expected ~969 CWE entries, got %d", nCWE)
	}
	if nCAPEC < 550 {
		t.Fatalf("expected ~615 CAPEC entries, got %d", nCAPEC)
	}
}

func TestLookup(t *testing.T) {
	c := Std()
	// id with and without prefix
	for _, id := range []string{"CWE-89", "89"} {
		w, ok := c.CWE(id)
		if !ok || w.Name == "" {
			t.Fatalf("CWE %s not found", id)
		}
	}
	w, _ := c.CWE("89")
	if w.Abstraction != "Base" {
		t.Fatalf("CWE-89 abstraction expected Base, got %s", w.Abstraction)
	}
	p, ok := c.CAPEC("CAPEC-66")
	if !ok || p.Name != "SQL Injection" {
		t.Fatalf("CAPEC-66 lookup failed: %+v ok=%v", p, ok)
	}
	if !c.HasCWE("502") || !c.HasCAPEC("66") {
		t.Fatal("HasCWE/HasCAPEC failed for known ids")
	}
	if c.HasCWE("9999999") {
		t.Fatal("HasCWE should be false for unknown id")
	}
}

func TestAncestors(t *testing.T) {
	c := Std()
	anc := map[string]bool{}
	for _, a := range c.CWEAncestors("89") {
		anc[a] = true
	}
	// CWE-89 ChildOf 74 (injection) and 943 (data query logic)
	if !anc["74"] || !anc["943"] {
		t.Fatalf("CWE-89 ancestors should include 74 and 943, got %v", anc)
	}
}

func TestCrossRef(t *testing.T) {
	c := Std()
	w, _ := c.CWE("89")
	// CWE-89 relates to CAPEC-66 (SQL Injection)
	found := false
	for _, p := range w.CAPEC {
		if p == 66 {
			found = true
		}
	}
	if !found {
		t.Fatalf("CWE-89 should cross-reference CAPEC-66, got %v", w.CAPEC)
	}
}
