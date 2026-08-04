# 11 — Domain: Supply Chain and Runtime

Status: `DRAFT` (supply chain: Tier 2; runtime: Tier 3)

## Part A — Supply chain (SCA)

### Sub-graph

`sbom.*` nodes: `Repository`, `Dependency` (declared edge with version
constraint), `Package`, `PackageVersion` (id = purl), `ContainerImage`,
`Layer`, `Artifact`, `Advisory`, `License`, `Maintainer`. Ingested from
lockfiles/manifests, SBOM documents (CycloneDX/SPDX accepted natively),
registry metadata, and image scanning.

`threat.*` enrichment: advisories (OSV/NVD/GHSA) project to `Advisory` nodes
with affected-version ranges; VEX statements project as suppression facts
with provenance ([16](16-standards-alignment.md)).

### Rules

```vyql
rule vypr.sca.vulnerable_dependency {
  meta { id: "VYQL-SCA-001", severity: from_advisory }
  match sbom.PackageVersion as p
  where p affected_by Advisory as adv
  unless vex_states(adv, p.deployment, not_affected)
}

rule vypr.sca.reachable_vulnerable_function {
  meta { id: "VYQL-SCA-002", severity: from_advisory, confidence_floor: medium }
  match sbom.PackageVersion as p
  where p affected_by Advisory as adv
    and adv has_vulnerable_symbols
    and flow(code.CallSite calling adv.vulnerable_symbols, ANY)   // call-graph reachability
}

rule vypr.sca.typosquat_candidate {
  meta { id: "VYQL-SCA-005", severity: high, confidence_floor: low }
  match sbom.Dependency as d
  where edit_distance(d.name, POPULAR_PACKAGE) <= 1
    and d.package.downloads < typosquat_threshold
}

rule vypr.sca.dependency_confusion {
  meta { id: "VYQL-SCA-006", severity: high }
  match sbom.Dependency as d
  where d.name in INTERNAL_NAMESPACE
    and d.resolved_registry == PUBLIC_REGISTRY
}
```

Notes:

- **Reachability-gated SCA** (VYQL-SCA-002) is the headline: vulnerable
  *and called* beats vulnerable-in-lockfile. It reuses the code call graph
  from [10](10-domain-sast.md) — a cross-domain join no standalone SCA tool
  gets for free. Symbol-level advisory data is sparse; the rule degrades to
  package-level when symbols are unknown, recorded in confidence.
- `severity: from_advisory` defers to CVSS/advisory data; the risk model
  ([17](17-risk-model.md)) then modifies by exposure (is the deploying
  service internet-reachable?) and asset proximity.
- Heuristic rules (typosquatting) carry `confidence_floor: low` and route to
  review queues, not blocking gates ([14](14-findings-explainability-output.md)).

### Vulnerable-library entrypoints: present → reachable → exploitable

The biggest SCA noise problem is that most "you depend on a vulnerable version"
alerts are not exploitable in the consuming application. When an advisory carries
**entrypoint information** (which library symbol is the vulnerable sink) and
**vulnerability-class information** (what kind of flaw — deserialization, SQLi,
XXE, SSRF, path traversal, RCE — and which argument is dangerous), VyQL can
incorporate that directly into taint analysis and answer the exploitability
question, not just the presence question.

**The advisory becomes a graph fact.** An enriched advisory is modeled as a
`VulnerableEntrypoint`:

```
VulnerableEntrypoint {
  advisory:       "CVE-2017-18342" | "GHSA-…" | "OSV-…"
  package:        { name, ecosystem, affected_version_range }
  symbol:         "yaml.load"            // the entrypoint the app calls
  role:           sink | source | bypassed_control
  vuln_class:     DESERIALIZATION        // → a sink concept + threat kind
  cwe:            [CWE-502]
  tainted_param:  arg0 | receiver | named("data") | any   // sink-argument precision
  taint_required: [UNTRUSTED_DATA]       // what must reach it to be exploitable
  precondition:   optional config/flag guard (e.g. resolve_entities=true)
}
```

**Projection (an advisory adapter, [07](07-adapters-and-patterns.md)).** When the
SBOM shows the affected version is present, an adapter resolves the advisory's
`symbol` to the application's actual **call sites** — using the same import +
type resolution the SAST frontend already provides
([20](20-extraction-frontends.md) §"Call resolution") — and **labels the
`tainted_param` node of each such call with the sink concept implied by
`vuln_class`** (carrying the advisory id and version range as provenance, and the
argument position as sink precision). A CVE thereby becomes a first-class,
typed sink in the graph, contributed by threat intelligence rather than a
hand-written sink list. (Roles other than `sink`: a `source` labels the
library's return value as tainted; a `bypassed_control` downgrades a control the
app relied on so it no longer neutralizes — see [06](06-ontology.md).)

**The existing taint rules then do the work.** No new engine machinery: the
standard rule `taint USER_CONTROLLED_DATA -> DESERIALIZATION` now fires when
attacker-controlled data reaches the CVE's entrypoint with the required taint
kind, past any `precondition` guard. The result is an **exploitability-grade**
finding — "CVE-2017-18342 is reachable from HTTP input at orders.py:42 →
yaml.load" — with a full taint witness, not a lockfile match.

This yields a **three-tier funnel**, each tier strictly narrower and more
actionable than the last:

| Tier | Rule | Question | Gate |
|---|---|---|---|
| Present | `VYQL-SCA-001` | do we ship the vulnerable version? | manifest |
| Reachable | `VYQL-SCA-002` | is the vulnerable symbol called at all? | call graph |
| **Exploitable** | `VYQL-SCA-003` | does attacker-controlled data taint-reach the entrypoint? | taint solver |

```vyql
rule vypr.sca.exploitable_vulnerable_dependency {
  meta { id: "VYQL-SCA-003", severity: from_advisory }
  // the entrypoint sink was contributed by an advisory adapter from CVE data
  taint USER_CONTROLLED_DATA -> VULNERABLE_ENTRYPOINT_SINK
  unless guarded_by ADVISORY_PRECONDITION_UNMET
}
```

Most "exploitable" findings disappear at the taint tier (the call exists but no
attacker data reaches it, or a safe wrapper is used) — which is exactly the SCA
noise reduction reachability alone cannot deliver, and the headline value of
having SCA and SAST in one graph.

**Two fidelities of entrypoint data:**

1. **Public-entrypoint sink (default).** The advisory names the public function
   the application calls; the adapter labels that call site. Simple, and what
   most function-level advisory data supports today.
2. **Library taint summaries.** When the dangerous sink is deep inside the
   library and the app calls a wrapper, a per-library taint summary
   (param → internal vulnerable sink, with the library's own sanitizers) is
   precomputed **once** with the same summary-based solver
   ([08](08-dataflow-and-taint.md)) and reused across every consuming app. This
   turns "is this library function exploitable here" into a cached cross-boundary
   taint join. Summaries are keyed to the advisory + version range and are a
   natural artifact for external assistants to draft and humans to review
   (18).

**Where the data comes from** ([16](16-standards-alignment.md)): OSV's
increasingly function-level affected data, GitHub Security Advisories' affected
functions, VEX (exploitability status that can short-circuit the funnel), and
research/commercial vulnerable-symbol datasets. The advisory adapter is the
single ingestion point; `tainted_param`, `vuln_class`, and `precondition` are the
fields that make a CVE *actionable* rather than merely *known*, and advisories
lacking them degrade gracefully to the Reachable or Present tier with confidence
recorded.

### Supply chain × identity composition

The genuinely novel joins live across namespaces:

```vyql
rule vypr.sca.compromised_package_to_prod {
  meta { id: "VYQL-SCA-010", severity: critical }
  // a package flagged malicious whose consuming pipeline's identity can write prod
  match sbom.PackageVersion as p
  where p labeled MALICIOUS_PACKAGE
    and p consumed_by Pipeline as ci
    and assume(ci.principal, privilege(WRITE) on PRODUCTION_SCOPE)
}
```

CI/CD pipelines are first-class: pipeline definitions extract to nodes whose
principals join the identity graph ([09](09-domain-cloud-identity.md)) —
"who can poison what build, and what can that build touch" is an `assume`
question.

## Part B — Runtime security (Tier 3)

### Ingestion model: aggregate, don't graph raw events

Raw runtime telemetry (eBPF sensors, audit logs, OCSF streams) is far too
voluminous to store as graph nodes. The runtime extractor maintains:

- **Behavioral aggregates** as nodes: `runtime.Process` (per executable
  identity per workload, not per PID), `runtime.Connection` (per
  src/dst/port flow identity), `runtime.EventWindow` summaries.
- **OBSERVED edges** with first/last-seen, counts: `SPAWNED`,
  `CONNECTED_TO`, `SERVED`, `ACCESSED_FILE`.
- Raw events stay in the telemetry store; graph facts carry pointers
  (`evidence_ref`) so proof trees can cite raw events without storing them.

OCSF is the ingestion schema ([16](16-standards-alignment.md)); sensors that
speak OCSF need no custom extractor.

### Rules

```vyql
rule vypr.runtime.webshell {
  meta { id: "VYQL-RTM-001", severity: critical, attack: ["T1505.003"] }
  flow HTTP_REQUEST -> SHELL_EXECUTION
  where same_process_lineage
}

rule vypr.runtime.workload_drift {
  meta { id: "VYQL-RTM-003", severity: high }
  match runtime.Process as p
  where p.image not in p.workload.declared_images   // joins cloud graph
}

rule vypr.runtime.crypto_mining_egress {
  meta { id: "VYQL-RTM-004", severity: high, attack: ["T1496"] }
  match runtime.Connection as c
  where c.dst labeled MINING_POOL      // threat-intel projection
}
```

`flow` in the runtime namespace is served by a **runtime flow solver** over
observed lineage (process ancestry, fd/socket inheritance) — same contract
as all solvers (witness = the observed event chain via `evidence_ref`s),
different fixpoint. Evaluation is **streaming**: runtime rules compile to
standing queries over the aggregate delta stream, with the Datalog core
incrementally maintained — this is the main engine work item for Tier 3.

### Runtime × static composition: detection becomes confirmation

The strategic value of runtime in VyQL is *confirming* static findings:

- A `taint` finding on a route + observed exploit-shaped requests to that
  route = incident-grade escalation.
- `reach(INTERNET, db)` predicted statically; `runtime.Connection` from an
  external IP observed = exposure confirmed, risk likelihood → 1.0
  ([17](17-risk-model.md)).
- Conversely, a vulnerable dependency whose symbols are *never observed
  executing* over 90 days lowers exploitation likelihood (never to zero).

These are ordinary VyQL rules joining `runtime.*` facts with static
findings — no special machinery beyond the streaming evaluator.

## Open questions

- Runtime aggregate cardinality control (high-churn workloads, per-request
  process spawning) — needs sensor-side pre-aggregation contracts.
- Retention tiers and their interaction with finding lifecycle (a runtime
  fact ages out; does the composite finding downgrade?). Proposal: composite
  findings record the observation window and decay to the static-only
  severity, never silently disappear.
- eBPF sensor build/buy decision — out of scope for the language design;
  the OCSF boundary isolates it.
