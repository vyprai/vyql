# ADR 0004 — FP triage and path-stable suppression

Status: **Accepted (implemented; see the `triage` command and `-baseline`)**
Date: 2026-09 (relative; see git history)
Relates to: `cmd/vyql/baseline.go`, `internal/resultpolicy/identity.go`,
`internal/graphjson/graphjson.go`, docs/14 (findings output).

## Context

vyql findings are often verified out-of-band — by a human triager, or by an
automated verifier inside a scanning service — and verification is the
expensive step of any pipeline that does it. A triaged false positive must
survive across commits: re-reporting it re-pays verification for a finding
someone already judged.

The baseline (`-baseline` / `-baseline-write`) already records verdicts keyed
on the finding fingerprint — rule id + primary target (sink) location +
concept — deliberately not the whole taint path, and not line-number keyed in
the brittle sense. It survives edits elsewhere in a file. Stale entries
(entries matching nothing) are reported, not silently forgotten.

Two facts shape the rest:

- **vyql cannot judge true from false.** Verdicts come from outside — a
  human on the CLI, an automated verifier in a service. vyql publishes
  identity, applies lists, reports what it did. That split is already correct
  and stays.
- **A scanning service does not own the repositories it scans.** Triage state
  lives in the service's own storage; the scanned checkout stays untouched.

### The gap

A commit can change the *path* under a finding without moving its sink: the
source end is swapped, or mid-path hops change. The fingerprint still matches
(rule + sink + concept unchanged), so a triaged false positive stays
suppressed even though the thing the verdict was about has changed. The
dangerous neighbour case resolves itself for free: adding an engine-visible
neutralizer stops the finding from firing at all, and the entry goes stale.

So the only genuinely open case is: same fingerprint, different path. That is
a policy question — *when has a finding changed enough to re-pay
verification?* — and this ADR answers it.

### Requirements

1. Drift-aware suppression: an FP stays excluded while the path's
   security-relevant structure is unchanged; it re-fires when that changes.
2. The open-source CLI supports the full workflow — record an FP, remove a
   stale one, apply suppressions — with no service behind it.
3. A storage-backed consumer differs only in what only it can do:
   verification, storage, loading and materializing the list, feeding it to
   scans.
4. Memory in vyql when loading the exclude list stays bounded and small; the
   taint paths themselves are never loaded back into vyql.

## Decision

### 1. The path signature lives in vyql, not the consumer

`sig` is a 16-hex sha256 over the ordered sequence of hops along the
finding's witness (source → sink), each hop encoded as `concept@callee_path`
where the hop is a call and `concept` alone otherwise. It is computed from
the live finding at scan time. It is stable across line shifts, formatting, and edits
elsewhere in the file; it changes on a source swap or a structural path
change — exactly the changes that should re-pay verification.

One implementation, in the engine. A consumer does not compute signatures;
it stores them, merges them, and materializes the file. Two reasons this is
not a convenience choice:

- If a consumer owned signatures, CLI users could not have drift detection:
  two suppression semantics, and the open-source CLI silently keeps
  suppressing FPs whose paths changed.
- This repository has scar tissue here. `identity_surfaces_test.go` exists
  because a second fingerprint implementation once silently matched nothing.
  The same guard is extended to `sig`: one implementation, every surface
  calls it.

An entry may carry several sigs. The solver keeps one representative path per
sink, and which one it keeps can change without any code change; after a
benign re-verify, the new sig joins the set rather than replacing it, so the
cost is paid once.

### 2. Baseline format: v2 stays, `sig` is additive

Entries gain an optional `sig` list. No version bump: unknown JSON fields are
ignored by older readers, and an entry without sigs keeps its legacy meaning
(match on `fp` alone). The file remains a single JSON document — the only
interface between vyql and anything that stores triage state.

### 3. Apply semantics

An entry suppresses a finding iff the fingerprint matches **and** (the entry
carries no sigs **or** the finding's sig is among them). Fingerprint match
with sig mismatch: the finding is **reported** and named `drifted`. Gate
semantics are unchanged — a drifted finding is a reported finding, so it
fails the gate where before it was silently absorbed. That behaviour change
is the point, and it goes in the CHANGELOG.

### 4. CLI: `vyql triage add | remove | list`

- `triage add -fp <fp> -baseline <file> -verdict false-positive -reason "..."`
  with optional `-from <scan.graph.json>` captures the sig from that scan's
  witness. Without `-from`, the entry is recorded fp-only (legacy semantics).
- `triage remove -fp <fp> -baseline <file>` drops an entry — the "remove this
  stale FP" action.
- `triage list -baseline <file>` prints entries with verdicts and reasons.
- `scan -baseline <file>` is unchanged as the apply path; "suppress the
  following FPs" is what it already does, now drift-aware.

Hand-editing the JSON stays possible; the subcommands validate and keep the
shape canonical (sorted by fp, stable field order, as `writeBaseline` does).

### 5. graph-json `baseline` section

After application, the graph-json document carries
`{applied, covered: [fp], drifted: [fp], stale: [fp]}`. `drifted` is
load-bearing: reported findings alone cannot distinguish *new* (first
verification) from *drifted* (re-verify; verdict history exists). The
stdout-carries-exactly-one-document invariant is preserved — the section is
part of the document, not a side channel.

### 6. Consumer contract (for anyone storing triage outside the file)

- **Rows are the source of truth.** A triage record keyed `(project, fp)`
  with verdict, reason, sigs, status (`active | stale | archived`),
  verified_by/verified_at, and an optional `expires_at` for FPs whose
  reasoning is invisible to the graph (runtime config, deploy topology — no
  path encoding catches those; expiry is the honest tool). Per-finding
  upserts mean concurrent verifications never lose a write. Storing the
  whole JSON blob as the write target is rejected: parallel verification
  jobs read-modify-write the blob and the last writer silently drops other
  verdicts — a first-week failure, not a scale concern.
- **The file is a derived, disposable artifact.** The materializer is a
  deterministic encoder over rows (~40 lines, mirroring `writeBaseline`'s
  shape), written to the scan job's scratch space. It is never edited as
  state. A cached blob may be kept for audit, never as the write target.
- **vyql never learns a database exists.** No connection strings, no
  service credentials in scan jobs. The baseline file and the graph-json
  document are the entire contract, so a consumer's storage can evolve
  without a vyql release.
- **Scan cycle**: materialize → `vyql scan -format graph-json -baseline
  <scratch>/baseline.json` → ingest findings + baseline section → new and
  drifted findings go to verification → verdicts and merged sigs written →
  covered entries stay alive, stale entries archived.

### 7. Memory

vyql loads fingerprints, sigs, and verdicts — O(entries), bounded by whatever
the consumer materializes, a few MB at tens of thousands of
entries. Path data never enters vyql through the exclude list; the witness
flows one way, out, in the graph-json document.

## Consequences

- A renamed intermediate function changes `callee_path`, so the sig breaks
  and the finding re-fires once — conservative by design; the merged-sig set
  means the cost is paid once per structural change, not per scan.
- Baseline users' gates get stricter: drifted FPs now fail builds that were
  previously silently green. Intentional; CHANGELOG entry required.
- Benchmarks do not exercise baselines, so detection scores must not move; a
  CI run confirms, and any movement is quoted rather than assumed.
- README gains `triage` documentation; vyql-action is untouched (no flag
  changes); the claude-plugins skill names CLI flags and is synced by that
  repository's CI — noted in the pull request, not fixable here.
- Testing: a signature stability matrix (line shift, formatting, in-place
  rename, source swap, hop insertion/removal), apply-semantics tests (legacy
  entry, sig match, sig mismatch → drifted and reported), triage roundtrip,
  an identity-surfaces-style guard extended to `sig`, and the graph-json
  section's presence and exit-code behaviour.
