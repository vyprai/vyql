package main

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/vyprai/vyql/extract/parsecache"
	"github.com/vyprai/vyql/graphsync"
)

// syncCollector, when non-nil, makes buildGraphWith assemble a graph-database change-feed during
// the scan (per-module node/edge/label rows for the modules that changed). It is set only when
// graph sync is requested ($VYQL_SYNC), so the normal scan path pays nothing.
var syncCollector *graphsync.Collector

// syncEnabled reports the output path for the change-feed, or "" if graph sync is off. Sync needs
// the cache (it is the incremental engine + the module manifest); without $VYQL_CACHE it is off.
func syncOutputPath() string {
	if parsecache.Shared() == nil {
		return ""
	}
	return os.Getenv("VYQL_SYNC")
}

// manifestKey stores the set of module namespaces present at the last sync, so the next scan can
// tombstone modules that disappeared.
const manifestKey = "sync\x00manifest"

func loadSyncManifest(c *parsecache.Cache) map[string]bool {
	out := map[string]bool{}
	raw, ok := c.GetRaw(manifestKey)
	if !ok {
		return out
	}
	for _, ns := range strings.Split(string(raw), "\n") {
		if ns != "" {
			out[ns] = true
		}
	}
	return out
}

func saveSyncManifest(c *parsecache.Cache, set map[string]bool) {
	nss := make([]string, 0, len(set))
	for ns := range set {
		nss = append(nss, ns)
	}
	c.PutRaw(manifestKey, []byte(strings.Join(nss, "\n")))
}

// writeSyncDelta finalizes the change-feed against the previous manifest, writes it as JSON to
// path, and persists the new manifest. Returns the row counts for the run summary.
func writeSyncDelta(path string) (nodes, edges, labels, deleted int, err error) {
	c := parsecache.Shared()
	delta, newNS := syncCollector.Finalize(loadSyncManifest(c))
	for _, rs := range delta.NodeMods {
		nodes += len(rs)
	}
	for _, rs := range delta.EdgeMods {
		edges += len(rs)
	}
	for _, rs := range delta.LabelMods {
		labels += len(rs)
	}
	deleted = len(delta.Deleted)
	b, err := json.MarshalIndent(delta, "", "  ")
	if err != nil {
		return
	}
	if err = os.WriteFile(path, b, 0o644); err != nil {
		return
	}
	saveSyncManifest(c, newNS)
	return
}
