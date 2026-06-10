# 16 — Standards Alignment

Status: `STABLE` (policy); per-standard mapping tables `DRAFT`

Policy: **VyQL maps onto existing standards; it does not invent parallel
taxonomies.** Every concept, rule, and output format declares its relationship
to the relevant standard, or the ontology review records why no mapping
exists. This is both credibility (security teams live in CWE/ATT&CK terms)
and interoperability (findings must flow into ecosystems we don't control).

## Mapping summary

| Standard | Role in VyQL | Direction |
|---|---|---|
| **CWE** | **full catalog embedded** (969 weaknesses, `go/taxonomy/`) + weakness ids on sink concepts/threat kinds/rules; hierarchy (ChildOf) for roll-up; `ontology.Validate` fails on unknown ids | VyQL ↔ CWE (catalog + annotation) |
| **CAPEC** | **full catalog embedded** (615 attack patterns) + CWE↔CAPEC cross-refs; CAPEC for a threat kind is *derived* from its CWEs' cross-references | VyQL ↔ CAPEC (catalog + annotation) |
| **OWASP Top 10 / ASVS** | rule metadata (`owasp:`); ASVS control ids on control concepts | annotation |
| **MITRE ATT&CK** | technique/tactic ids on runtime rules, identity rules, attack-path steps; matrix projection of paths ([13](13-attack-path-analysis.md)) | annotation + projection |
| **MITRE D3FEND** | defensive-technique ids on control concepts | annotation |
| **SARIF 2.1** | normative output for code-shaped findings ([14](14-findings-explainability-output.md)) | VyQL → SARIF |
| **OCSF** | normative *input* schema for runtime telemetry ([11](11-domain-supply-chain-runtime.md)); candidate output for detection findings | OCSF → VyQL (→ OCSF) |
| **STIX 2.1** | threat-intel input: bundles project to `threat.*` nodes via the STIX adapter | STIX → VyQL |
| **CycloneDX / SPDX** | SBOM input formats for the sbom extractor | → VyQL |
| **OSV / NVD / GHSA / CVSS** | advisory data on `sbom.Advisory`; CVSS as severity input (`severity: from_advisory`); **function-level / affected-symbol data** (OSV ecosystem-specific, GHSA affected functions) feeds the advisory adapter's `VulnerableEntrypoint` (symbol, tainted-param, vuln-class) for exploitability analysis ([11](11-domain-supply-chain-runtime.md)) | → VyQL |
| **CSAF / VEX** | VEX statements become provenance-carrying suppressions ([14](14-findings-explainability-output.md)); VEX `exploitability` status can short-circuit the SCA present→reachable→exploitable funnel ([11](11-domain-supply-chain-runtime.md)) | → VyQL |
| **EPSS / KEV** | exploitation-likelihood inputs to the risk model ([17](17-risk-model.md)) | → VyQL |
| **purl / CPE** | package identity (purl primary; CPE via advisory matching) | identity scheme |
| **OSCAL** | compliance-control mapping for rule packs (which rules evidence which controls) — enables compliance reporting without a second rule corpus | VyQL → OSCAL |
| **OpenAPI / AsyncAPI** | API-shape input strengthening route extraction and cross-service flow composition ([08](08-dataflow-and-taint.md)) | → VyQL |

## Mapping mechanics

- Mappings are **fields in versioned artifacts** (ontology concepts, rule
  metadata), validated at build: unknown CWE ids, retired ATT&CK technique
  ids, malformed purls fail pack CI. External taxonomy versions are pinned
  per ontology release and upgraded deliberately.
- Mappings are **many-to-many and lossy by nature**; where a concept is
  broader or narrower than its CWE counterpart, the mapping carries a
  qualifier (`cwe: [CWE-89]` vs `cwe_related: [CWE-20]`). Review enforces
  the distinction — sloppy mappings are worse than none.
- **Inbound standards get adapters like any technology**: the STIX adapter,
  the OCSF adapter, the CycloneDX extractor are ordinary
  pattern/adapter-layer citizens with fixtures and versions
  ([07](07-adapters-and-patterns.md)). Standards churn is then absorbed in
  the same place all technology churn is absorbed.

## Compliance reporting (OSCAL path)

Rule packs can carry control mappings:

```toml
[compliance]
"VYQL-CLD-007" = { nist_800_53 = ["SC-28"], cis_aws = ["2.1.1"], pci_dss = ["3.4"] }
```

A compliance report is then a *query over findings* grouped by control —
no separate compliance rule corpus, no drift between "security" and
"compliance" results. OSCAL export packages this for GRC tooling. (VyQL
remains not-a-GRC-platform, [01](01-vision-and-scope.md) non-goals; we emit
evidence, we don't manage programs.)

## Where we deliberately deviate

- **Concept granularity ≠ CWE granularity.** CWE's 900+ entries are a
  reporting taxonomy, not an analysis vocabulary; the ontology stays small
  and analysis-shaped, with mappings carrying the burden of translation.
- **Severity is not raw CVSS.** Advisory CVSS is an input; VyQL severity
  composes it with graph context (exposure, asset sensitivity, privilege)
  per [17](17-risk-model.md). Outputs carry both (the context-adjusted score
  and its inputs) so consumers can audit the adjustment.
- **No OVAL/SCAP rule authoring.** Legacy configuration-check formats are
  ingestion candidates at most.

## Standards engagement

Where VyQL produces shapes no standard covers (attack-path sets,
choke-point reports, proof trees), v1 ships them under the documented Nexus
API. If/when OASIS or OCSF working groups open relevant tracks,
participation is warranted — the proof-tree and path formats are natural
contributions and early-mover standardization is a moat-deepener. Owner:
research team; revisit each roadmap checkpoint.
