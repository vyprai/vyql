package ontology

import (
	"testing"

	"github.com/vyprai/vyql/taxonomy"
)

// Every CWE/CAPEC id cited by threat kinds and concepts must resolve in the
// catalog, and sink/control typing must reference known threat kinds
// (docs/16 — bad ids fail CI).
func TestOntologyValidatesAgainstCatalog(t *testing.T) {
	cat := taxonomy.Std()
	problems := Validate(Seed(), cat)
	if len(problems) > 0 {
		t.Fatalf("ontology validation problems:\n  %v", problems)
	}
}

// Threat-kind vocabulary covers the major families and resolves to CWE+CAPEC.
func TestThreatKinds(t *testing.T) {
	cat := taxonomy.Std()
	tks := ThreatKinds()
	if len(tks) < 50 {
		t.Fatalf("expected a comprehensive threat-kind set, got %d", len(tks))
	}
	families := map[string]bool{}
	for _, tk := range tks {
		families[tk.Package] = true
		for _, c := range tk.CWE {
			if !cat.HasCWE(c) {
				t.Fatalf("threat kind %s cites unknown %s", tk.Name, c)
			}
		}
	}
	for _, fam := range []string{"injection", "access_control", "crypto", "memory", "deserialization", "supply_chain"} {
		if !families[fam] {
			t.Fatalf("threat kinds missing family %s", fam)
		}
	}
	// CAPEC is derived from the catalog: injection.SqlInjection -> CAPEC-66
	sqli, _ := ThreatKindByName("injection.SqlInjection")
	found := false
	for _, p := range sqli.CAPEC(cat) {
		if p == "66" {
			found = true
		}
	}
	if !found {
		t.Fatalf("injection.SqlInjection should derive CAPEC-66, got %v", sqli.CAPEC(cat))
	}
}

// The expanded seed covers more families than the original 32.
func TestExpandedSeed(t *testing.T) {
	o := Seed()
	for _, name := range []string{"code.NosqlQuery", "code.XmlParse", "code.FilePathAccess",
		"code.RedirectTarget", "core.EncryptionAtRest", "core.MfaRequirement", "core.SafeDeserialization"} {
		if !o.Exists(name) {
			t.Fatalf("expanded seed missing %s", name)
		}
	}
}
