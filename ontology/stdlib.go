package ontology

import "github.com/vyprai/vyql/datadir"

// The ontology is authored in VyQL (docs/05/06): concepts in
// vyql/ontology/concepts.vyql (`concept X : kind { … }`) and threat kinds in
// threatkinds.vyql (`threat X { … }`), loaded from disk at runtime.

// Seed returns the seed ontology, parsed from vyql/ontology/concepts.vyql.
func Seed() *Ontology {
	o := New()
	cs, err := LoadConceptText(string(datadir.MustRead("ontology/concepts.vyql")))
	if err != nil {
		panic("ontology: invalid ontology/concepts.vyql: " + err.Error())
	}
	for _, c := range cs {
		o.Add(c)
	}
	return o
}
