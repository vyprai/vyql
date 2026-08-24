package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// newGraphStoreDir creates the directory the --max-ram graph store lives in.
//
// It is deliberately NOT $TMPDIR. On a systemd distribution /tmp is a tmpfs, so a
// store put there is held in RAM, and the mode whose whole purpose is to keep the
// graph out of RAM would put it straight back, so the scan pays the write and
// codec cost of spilling and gets none of the memory back. The scan cache already
// resolves to the user cache directory for the same reason, so the graph store
// joins it there, under `graph/`, and is removed when the scan ends.
//
// $TMPDIR remains the fallback for a machine with no usable cache directory. A
// store that ends up on a memory filesystem anyway is reported rather than
// silently accepted, because the ceiling the user asked for cannot hold there.
func newGraphStoreDir() (string, error) {
	if base, err := os.UserCacheDir(); err == nil && base != "" {
		parent := filepath.Join(base, "vyql", "graph")
		if err := os.MkdirAll(parent, 0o755); err == nil {
			sweepStaleGraphStores(parent, staleGraphStoreAge)
			if dir, err := os.MkdirTemp(parent, "scan-"); err == nil {
				warnIfRAMBacked(dir)
				return dir, nil
			}
		}
	}
	dir, err := os.MkdirTemp("", "vyql-graph-")
	if err != nil {
		return "", err
	}
	warnIfRAMBacked(dir)
	return dir, nil
}

// warnIfRAMBacked reports a graph store on a memory filesystem, and lets the scan
// go ahead: it still produces the right findings, it just cannot honour the
// ceiling, and telling the user where to point the store is more use than
// refusing to start.
func warnIfRAMBacked(dir string) {
	if ramBacked(dir) {
		fmt.Fprintf(os.Stderr,
			"vyql: the --max-ram graph store is on a memory filesystem (%s), so spilling it frees no RAM;\n"+
				"      point HOME or TMPDIR at a directory on disk\n", dir)
	}
}

// staleGraphStoreAge is how long a graph store may sit in the cache directory
// before a later scan removes it. A store outlives its scan only when the
// process is killed with a signal it cannot catch, and the cache directory is
// not emptied by a reboot the way a temporary one is, so nothing else would ever
// remove it.
const staleGraphStoreAge = 24 * time.Hour

// sweepStaleGraphStores removes graph stores under parent that have not been
// written to for age. It touches only the directories this package creates, by
// name, because it runs inside the user's cache directory. Every failure is
// ignored: the sweep is housekeeping, and a scan must not fail because an old
// directory would not go away.
func sweepStaleGraphStores(parent string, age time.Duration) {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-age)
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "scan-") {
			continue
		}
		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		_ = os.RemoveAll(filepath.Join(parent, e.Name()))
	}
}
