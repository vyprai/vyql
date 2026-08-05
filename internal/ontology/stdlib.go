package ontology

import "github.com/vyprai/vyql/internal/datadir"

// The ontology is authored in VyQL (docs/05/06): concepts in
// vyql/ontology/concepts (`concept X : kind { … }`) and threat kinds in
// ontology/threatkinds (`threat X { … }`), loaded from disk at runtime.

// Seed returns the seed ontology, parsed from vyql/ontology/concepts.
func Seed() *Ontology {
	o := New()
	files, err := datadir.ReadVYQLDir("ontology/concepts")
	if err != nil {
		panic("ontology: read ontology/concepts: " + err.Error())
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
