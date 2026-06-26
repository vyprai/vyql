package ontology

import "github.com/vyprai/vyql/datadir"

// The ontology is authored in VyQL (docs/05/06): concepts in
// vyql/ontology/concepts.vyql (`concept X : kind { … }`) and threat kinds in
// threatkinds.vyql (`threat X { … }`), loaded from disk at runtime.

// Seed returns the seed ontology, parsed from vyql/ontology/concepts.vyql.
func Seed() *Ontology {
	o := New()
	files, err := datadir.ReadVYQL("ontology/concepts.vyql")
	if err != nil {
		panic("ontology: read ontology/concepts.vyql: " + err.Error())
	}
	var cs []Concept
	for _, file := range files {
		fileConcepts, err := LoadConceptText(string(file.Data))
		if err != nil {
			panic("ontology: invalid " + file.Name + ": " + err.Error())
		}
		cs = append(cs, fileConcepts...)
	}
	for _, c := range cs {
		o.Add(c)
	}
	return o
}
