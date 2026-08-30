package main

import (
	"os"
	"path/filepath"
)

// corpusIsVendored reports whether the definitions under test are the ones this
// repository carries, rather than a bundle fetched at build time.
//
// It separates what this repository can hold itself to from what it cannot. Its
// own specs travel with its engine and are checked here. A CVE spec travels with
// the definitions, is written against the engine of the moment, and arrives from
// a bundle published at a tag chosen elsewhere -- so it is checked where those
// two are kept together.
func corpusIsVendored() bool {
	dir, err := os.Getwd()
	if err != nil {
		return false
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			_, err := os.Stat(filepath.Join(dir, "vyql"))
			return err == nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}
