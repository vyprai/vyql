package usg

import "sync/atomic"

// structEpochCtr is a process-global monotonic counter used to stamp a store's
// "structural epoch": a value that is unique per store and changes whenever the
// store's node/edge structure changes (AddNode/AddEdge), but NOT when only labels
// are added. Frontend binding application keys its shared per-pass node indexes on
// this epoch: within one bindings.Apply pass the store only gains labels (epoch
// stable, so the index is built once and shared by every applicator), while a
// structural mutation between passes yields a fresh epoch (index rebuilt — never
// stale). Being globally monotonic, an epoch is never reused, so a new store that
// happens to reuse a freed store's address can never collide with a cached index.
var structEpochCtr uint64

func nextStructEpoch() uint64 { return atomic.AddUint64(&structEpochCtr, 1) }
