package main

import (
	"testing"

	"github.com/vyprai/vyql/internal/bindings"
	"github.com/vyprai/vyql/internal/extract"
)

// The three shapes below are the rank 1629 pair (CVE-2026-24486,
// python-multipart's uploaded filename), which the first review of the attribute
// store change measured as two new VYQL-PATH-001 findings. They pin, at the rule
// level, which of the two is the store hop the gap names and which is the library
// profile's own threat model reaching the same sink — so the definitions side can
// see exactly what its spec flip owes and nothing beyond it moves silently.
//
// The library profile is the threat model those specs run in: every public-API
// parameter is an entry a caller may forward attacker-controlled data through, so
// BOTH of File.__init__'s parameters are sources without any binding naming them.

// scanAsLibraryProfile scans one fixture the way the spec harness scans a
// `profile library` code spec, and returns the locations VYQL-PATH-001 reported.
func scanAsLibraryProfile(t *testing.T, files map[string]string) []string {
	t.Helper()
	dir := writeFixture(t, files)
	applyProfile([]string{dir}, "library")
	defer bindings.SetActiveSources(nil)
	allRules, err := loadRules("")
	if err != nil {
		t.Fatalf("loadRules: %v", err)
	}
	fs, _, _, err := scanPathsWithProfileDemand([]string{dir}, allRules, "library", true, extract.Options{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return sinkLines(fs, "VYQL-PATH-001")
}

// The verbatim vulnerable revision: the filename crosses the constructor into
// self._file_base and out through _get_disk_file into open(). The spec for this
// pair asserts reject only while the store-to-load hop is missing — its own
// header commits the verbatim form to flip to expect once the hop lands, and
// this is that finding.
func TestPythonAttrStoreCarriesTheUploadFilenameIntoTheDiskFile(t *testing.T) {
	locs := scanAsLibraryProfile(t, map[string]string{
		"python_multipart/multipart.py": "import os\n" +
			"\n" +
			"\n" +
			"class File:\n" +
			"    def __init__(self, file_name, config):\n" +
			"        self._config = config\n" +
			"        base, ext = os.path.splitext(file_name)\n" +
			"        self._file_base = base\n" +
			"        self._ext = ext\n" +
			"\n" +
			"    def _get_disk_file(self):\n" +
			"        file_dir = self._config.get(\"UPLOAD_DIR\")\n" +
			"        keep_extensions = self._config.get(\"UPLOAD_KEEP_EXTENSIONS\", False)\n" +
			"        fname = self._file_base + self._ext if keep_extensions else self._file_base\n" +
			"        path = os.path.join(file_dir, fname)\n" +
			"        return open(path, \"w+b\")\n",
	})
	if !hasLineSuffix(locs, "multipart.py:16") {
		t.Fatalf("the filename stored in the constructor did not reach the disk file through the method that reads it back: %v", locs)
	}
}

// The basename control keeps its grip through the store: the fixed revision with
// the upload directory a constant, so the filename's route is the only one, holds
// at the sink. The store hop carries the stored value into the canonicalized
// flow — it does not leap over the control to re-taint what basename reduced.
func TestPythonAttrStoreHoldsABasenameReducedFilenameAtTheSink(t *testing.T) {
	locs := scanAsLibraryProfile(t, map[string]string{
		"python_multipart/multipart.py": "import os\n" +
			"\n" +
			"\n" +
			"class File:\n" +
			"    def __init__(self, file_name, config):\n" +
			"        basename = os.path.basename(file_name)\n" +
			"        base, ext = os.path.splitext(basename)\n" +
			"        self._file_base = base\n" +
			"        self._ext = ext\n" +
			"\n" +
			"    def _get_disk_file(self):\n" +
			"        fname = self._file_base\n" +
			"        path = os.path.join(\"/var/uploads\", fname)\n" +
			"        return open(path, \"w+b\")\n",
	})
	if len(locs) != 0 {
		t.Fatalf("traversal reported for a filename the constructor reduced to its basename: %v", locs)
	}
}

// The verbatim fixed revision still reports — through the OTHER labelled
// parameter. `config` is as public an entry as `file_name` under the library
// profile, and the upload directory read out of it reaches the same path with no
// canonicalization on that route, so the basename (a sibling-path control) cannot
// dominate. A keyed read of a wholly tainted container staying tainted is the
// container model's own soundness contract (modeledContainerMethod), so the store
// hop cannot carry one labelled parameter and drop the other. This is the finding
// the pair's fixed-revision case draws through the hop, and the expectation flip
// on the definitions side has to account for it.
func TestPythonAttrStoreCarriesTheLabelledSettingsParameterToo(t *testing.T) {
	locs := scanAsLibraryProfile(t, map[string]string{
		"python_multipart/multipart.py": "import os\n" +
			"\n" +
			"\n" +
			"class File:\n" +
			"    def __init__(self, file_name, config):\n" +
			"        self._config = config\n" +
			"        # Extract just the basename to avoid directory traversal\n" +
			"        basename = os.path.basename(file_name)\n" +
			"        base, ext = os.path.splitext(basename)\n" +
			"        self._file_base = base\n" +
			"        self._ext = ext\n" +
			"\n" +
			"    def _get_disk_file(self):\n" +
			"        file_dir = self._config.get(\"UPLOAD_DIR\")\n" +
			"        keep_extensions = self._config.get(\"UPLOAD_KEEP_EXTENSIONS\", False)\n" +
			"        fname = self._file_base + self._ext if keep_extensions else self._file_base\n" +
			"        path = os.path.join(file_dir, fname)\n" +
			"        return open(path, \"w+b\")\n",
	})
	if !hasLineSuffix(locs, "multipart.py:18") {
		t.Fatalf("the labelled settings parameter stored in the constructor did not reach the disk file: %v", locs)
	}
}
