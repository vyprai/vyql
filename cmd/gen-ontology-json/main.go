// Command gen-ontology-json dumps the ontology content (concepts + threat kinds)
// to JSON, the source-of-truth format the ontology package loads. Run once to
// migrate Go literals -> JSON; thereafter edit the JSON directly.
//
//	go run ./cmd/gen-ontology-json ../vyql/ontology
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vyprai/vyql/internal/ontology"
)

func main() {
	out := "../vyql/ontology"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	write(filepath.Join(out, "concepts.json"), ontology.Seed().AllConcepts())
	write(filepath.Join(out, "threatkinds.json"), ontology.ThreatKinds())
	fmt.Printf("wrote concepts + threatkinds JSON to %s\n", out)
}

func write(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		panic(err)
	}
}
