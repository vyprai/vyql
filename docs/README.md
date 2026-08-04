# VyQL documentation

## Guides

Task-shaped, start here.

- [Install and first scan](guides/first-scan.md)
- [Output formats and CI](guides/output-formats.md)
- [Why did this fire, or not?](guides/debugging-findings.md)
- [Writing a binding](guides/writing-a-binding.md)

## Reference

The design series. Read the relevant one before changing the engine or the
language — these describe why things are the shape they are, not just what they
do.

| To understand | Read |
|---|---|
| How the whole thing fits together | [03 Architecture overview](03-architecture-overview.md) |
| The graph everything is expressed on | [04 Universal security graph](04-universal-security-graph.md) |
| The VyQL language itself | [05 Language specification](05-language-specification.md) |
| Concepts and threat kinds — the vocabulary | [06 Ontology](06-ontology.md) |
| How code shapes become concepts | [07 Adapters and patterns](07-adapters-and-patterns.md) |
| Taint semantics, and why sanitization is a transfer function | [08 Dataflow and taint](08-dataflow-and-taint.md) |
| SAST detection | [10 SAST](10-domain-sast.md) |
| Dependencies, SBOM, runtime | [11 Supply chain and runtime](11-domain-supply-chain-runtime.md) |
| Findings, proof trees, output | [14 Findings and explainability](14-findings-explainability-output.md) |
| Rule lifecycle and governance | [15 Rule lifecycle](15-rule-lifecycle-governance.md) |
| CWE, CAPEC, SARIF alignment | [16 Standards alignment](16-standards-alignment.md) |
| Severity and risk scoring | [17 Risk model](17-risk-model.md) |
| How a language becomes a graph | [20 Extraction frontends](20-extraction-frontends.md) |

The numbering has gaps. Documents 01, 02, 18, 19, 21 and 22 are strategic,
forward-looking, or describe an internal product boundary, and are not published.
Nothing here cites them.

[05 Language specification](05-language-specification.md) is marked
**superseded**: it documents v1 syntax and is kept for history. The current
binding language is [07](07-adapters-and-patterns.md).

## Designed, not implemented

These describe intent. Nothing in them ships today, and a scan will not produce
what they describe -- no binding emits the concepts they are built on, so their
rules cannot fire. They are published because the reasoning is useful, not
because the capability exists.

| Document | Why it does not run |
|---|---|
| [09 Cloud and identity](09-domain-cloud-identity.md) | no binding emits a `cloud.` or `identity.` concept |
| [12 Business logic](12-domain-business-logic.md) | no binding emits a `business.` concept |
| [13 Attack-path analysis](13-attack-path-analysis.md) | the `attackpath` package is not reachable from the CLI |

[11 Supply chain and runtime](11-domain-supply-chain-runtime.md) is partly real:
dependency and SBOM analysis runs, and the runtime concepts have bindings, but
the document describes more than ships.

## Decisions

Architecture decisions with their reasoning and their alternatives:

- [0001 Storage engine](adr/0001-storage-engine.md) — why the graph is stored the way it is
- [0002 Go and BadgerDB](adr/0002-go-badgerdb.md) — why Go, and what the Python prototype was for
- [0003 Tree-sitter frontends](adr/0003-treesitter-frontends.md) — why parsing is pluggable

## Measurements

[benchmarks/RESULTS.md](../benchmarks/RESULTS.md) is the measured record: which
score, on which corpus, at which commit, and the corpus defects that make some
numbers misleading. Read the corpus column before comparing anything — scores
from the synthetic language ports are not comparable to the public OWASP suites,
and conflating them has been the single largest source of confusion in this
project.
