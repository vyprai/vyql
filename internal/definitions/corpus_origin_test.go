package definitions

import (
	"os"
	"path/filepath"
)

// corpusIsVendored reports whether the definitions under test are the ones this
// repository carries, rather than a bundle fetched at build time.
//
// It decides whether a check that compares the corpus against a checked-in work
// list can mean anything. Such a list is versioned with the corpus it describes;
// once the corpus is fetched, the two move independently -- the bundle is
// published from a tag an operator chooses, with no fixed relationship to this
// repository -- so a comparison reports which side is newer rather than whether
// the corpus is sound. Those checks run where the corpus and the list are kept
// together.
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
