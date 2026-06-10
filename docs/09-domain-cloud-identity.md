# 09 — Domain: Cloud and Identity Security

Status: `STABLE` (flagship vertical — this ships first)

Cloud + identity + attack paths are VyQL's Tier 1 flagship: the domain where
"everything is a graph traversal" is literally true, the adapter surface is
small (a handful of providers, not hundreds of frameworks), and the
universality demo is crisp — one `PUBLIC_STORAGE` rule across AWS, Azure,
GCP. Strong precedent (Wiz graph, BloodHound, PMapper, Cartography) de-risks
the model.

## Cloud sub-graph

### Ingestion

Extractors per provider (AWS, Azure, GCP in v1; K8s as a fourth "provider")
pull inventory via cloud APIs into `cloud.*` and `identity.*` nodes with
Class A edges. IaC (Terraform/CloudFormation/Bicep) is extracted by the same
schema into a **planned** scope — the same rules evaluate deployed state and
PR-time plans, which is the IaC-security story for free.

### Adapter examples — the universality demo

```vyql
adapter aws.s3 {
  requires pattern doc(aws.s3_bucket_acl)
  map bucket where acl in ["public-read","public-read-write"]      to PUBLIC_STORAGE
  map bucket where policy grants_to principal("*") action("s3:GetObject") to PUBLIC_STORAGE
  map bucket where not sse_configured                              to lacks ENCRYPTION_AT_REST
}

adapter azure.blob {
  map container where public_access in ["blob","container"]        to PUBLIC_STORAGE
}

adapter gcp.storage {
  map bucket where iam_binding(member: "allUsers" | "allAuthenticatedUsers") to PUBLIC_STORAGE
}
```

One rule covers all three:

```vyql
rule vypr.cloud.public_storage_with_sensitive_data {
  meta { id: "VYQL-CLD-001", severity: critical, cwe: [CWE-284] }
  match PUBLIC_STORAGE as s
  where s holds_asset_kind [CUSTOMER_DATA, PII, CREDENTIALS]
}
```

## The `reach` solver (network reachability)

`reach A -> B` answers: is there a permitted network path from A to B?

**Inputs:** Class A topology facts — VPCs/VNets, subnets, route tables,
security groups / NSGs / firewall rules, load balancers, gateways (IGW, NAT,
peering, transit), public IPs, DNS, K8s services/ingress/network policies.

**Semantics:** fixpoint over (location, protocol, port-range, direction)
states. A hop is permitted iff routing allows it AND all traversed filters
(SG/NSG/NACL/NetworkPolicy) allow the protocol/port. `INTERNET` is the
per-tenant pseudo-node attached to public IPs/listeners.

**Witness:** the hop chain with, per hop, the specific permitting rule
(security group rule ID, route entry) — this is what makes reachability
findings *actionable*: the fix is the named rule.

**Precision notes:**

- Port/protocol carried through the fixpoint; `reach INTERNET -> DATABASE`
  means a database *protocol* port unless the rule says otherwise
  (`where protocol in [tcp:5432, tcp:3306, ...]` derived from the DATABASE
  concept's defaults).
- L7 constructs (ALB rules, API gateways, service meshes) are hops with
  path/host conditions carried as witness annotations at
  `confidence: medium` in v1 (full L7 modeling is an explicit non-goal for
  v1).
- Identity-based network controls (e.g. SG-references-SG) handled natively;
  IP allowlists evaluated against known org CIDRs.

## The `assume` solver (privilege closure)

`assume P -> Q` answers: can principal P obtain privileges of/act as Q?

**Inputs:** identity facts normalized per provider into a common policy
algebra: principals, policy statements (effect, action, resource, condition),
trust relationships, group memberships, permission boundaries, SCPs, K8s
RBAC bindings.

**Edge generators (the BloodHound/PMapper lesson — escalation is multi-step
closure over a small set of primitive abilities):**

- direct: `sts:AssumeRole` + trust policy match; `iam:PassRole` + service
  execution; Azure RBAC role assignment writes; GCP `iam.serviceAccounts.
  actAs` / `getAccessToken`; K8s `create pods` with SA mounting, etc.
- indirect: ability to modify a policy/trust document that would grant the
  above; ability to write to a deployment pipeline that executes as a
  higher principal (composes with sbom/CI graph).

**Semantics:** `CAN_ASSUME` is the transitive closure of these primitive
edges, computed per tenant with condition evaluation (resource constraints,
MFA conditions honored; unevaluatable conditions degrade the edge to
`confidence: medium`, never silently dropped or silently kept).

**`CAN_ACCESS(p, r, action)`** is effective-permission evaluation: the policy
algebra evaluated for principal × resource × action, *after* closure (P can
access what anyone P can assume can access — flagged distinctly in the
witness as "via assumed role X").

### Canonical identity rules

```vyql
rule vypr.identity.external_to_admin {
  meta { id: "VYQL-IDN-002", severity: critical, attack: ["TA0004"] }
  assume EXTERNAL_PRINCIPAL -> ADMIN_PRIVILEGE
}

rule vypr.identity.ci_can_touch_prod_data {
  meta { id: "VYQL-IDN-007", severity: high }
  match CI_PRINCIPAL as p
  where can_access(p, DATABASE holds_asset_kind [CUSTOMER_DATA], WRITE)
}

rule vypr.identity.toxic_combination_lateral {
  meta { id: "VYQL-IDN-011", severity: critical }
  // workload reachable from internet whose identity can escalate
  match WORKLOAD_IDENTITY as w
  where reach(INTERNET, w.workload)
    and assume(w, ADMIN_PRIVILEGE)
}
```

The third rule is the Wiz-style "toxic combination" — note it composes two
solvers in one rule body through the Datalog core. This composition is the
flagship demo of the whole architecture.

## Kubernetes

K8s is modeled as cloud (workloads, services, ingress, network policies) +
identity (RBAC) + a containment bridge to the hosting cloud account (node IAM
roles, workload identity federation, IRSA). The famous K8s escalation paths
(create-pod → mount SA token → cloud role) fall out of the `assume` edge
generators plus the bridge edges — no special-case rules.

## What Tier 1 deliberately defers

- Exotic providers (OCI, Alibaba) — adapter additions later, no engine work.
- Full L7 / WAF semantics in `reach`.
- Real-time config drift (sub-minute) — v1 target is ingest latency of
  minutes via event-driven deltas (CloudTrail/EventGrid/Audit Log triggers),
  not seconds.

## Success criteria for the flagship

1. The same ≤30-rule core pack runs unmodified across AWS+Azure+GCP test
   orgs and reproduces the top-20 CSPM checks plus 5 toxic-combination
   findings no single-domain CSPM expresses.
2. Reachability witnesses name the exact permitting SG rule/route in ≥95% of
   findings on the benchmark org.
3. PR-time IaC evaluation: the same pack flags a Terraform plan that would
   introduce `reach INTERNET -> DATABASE` before apply.
4. Privilege-closure parity: reproduce PMapper/BloodHound escalation findings
   on their own test datasets.
