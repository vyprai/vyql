package definitions

import (
	"os"
	"path/filepath"

	"github.com/vyprai/vyql/internal/datadir"
)

// definitionsArePublished reports whether the definitions under test came from a
// publish rather than from a working tree.
//
// A publish stamps VERSION and definitions.meta.json at the root of the bundle; a
// repository's own vyql/ tree carries neither. That is exactly the distinction
// these checks need. A bundle is cut at a tag chosen elsewhere, so its specs were
// written against a different scanner and asserting them reports which side is
// newer. A working tree is the definitions under change, and its specs are the
// thing that has to hold.
//
// Read from the data directory rather than from the checkout's own layout. The
// definitions repository runs these checks against a scanner it fetched, so there
// is no vyql/ beside that scanner -- deciding from its absence would skip the
// gate in the repository that most needs it, and skip it silently.
func definitionsArePublished() bool {
	root, ok := datadir.Lookup()
	if !ok {
		return false
	}
	for _, marker := range []string{"VERSION", "definitions.meta.json"} {
		if _, err := os.Stat(filepath.Join(root, marker)); err == nil {
			return true
		}
	}
	return false
}
