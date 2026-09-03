package extract

import (
	"bytes"
	"io"
	"os"
)

// The minified-bundle gate: a bundled-web file whose lines average a machine
// output's length is declined before any frontend reads it. The caller decides
// which kinds of file are bundled-web code (frontend.BundleKinds); the shape
// test here is only about the lines.
//
// A bundle is not source, and parsing it as source is ruinous in exactly the
// way a memory ceiling catches: every token of a minified megabyte becomes
// graph nodes and retained module text, tens to hundreds of bytes of analysis
// state per byte of bundle, so a committed frontend of a few dozen bundles
// pushes a bounded scan past its ceiling before a single finding is reported.
// The lines are the tell. Written code — hand-written or generated and
// formatted — averages under ~100 bytes per line however densely it is
// written; a minified bundle is one enormous line, often behind a short
// license header.

const (
	// minifiedMinBytes is the size a file must reach before its line shape is
	// measured. Below it a file cannot carry a bundle's per-parse cost, and
	// measuring every small file would read a whole tree to skip almost none
	// of it.
	minifiedMinBytes = 8 << 10
	// minifiedProbeBytes caps how much of a candidate is read: a bundle is one
	// enormous line from its first bytes, and a formatted file shows its
	// newlines just as fast.
	minifiedProbeBytes = 64 << 10
	// minifiedLineAverage is the bytes-per-line average that separates written
	// code from machine output. The densest real source measures ~100 bytes per
	// line and bundles measure in the tens of thousands, so the threshold sits
	// in the gap between them.
	minifiedLineAverage = 256
)

// minifiedBundle reports whether path is machine-generated output, judged only
// by the shape of its lines. A file that cannot be read is never machine
// output: declining it would drop it without evidence.
func minifiedBundle(path string, size int64) bool {
	if size < minifiedMinBytes {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	n := min(int64(minifiedProbeBytes), size)
	buf := make([]byte, n)
	read, _ := io.ReadFull(f, buf)
	if read < minifiedMinBytes {
		return false
	}
	lines := 1 + bytes.Count(buf[:read], []byte{'\n'})
	return read/lines >= minifiedLineAverage
}
