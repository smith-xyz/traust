---
name: rbac-tenancy-rollup
description: Use when the user asks for a portfolio view of RBAC or multi-tenancy findings — "what are our RBAC issues", "top RBAC misconfigurations", "multi-tenancy findings rollup", "which repos have over-permissive RBAC", "tenant-isolation findings summary", "ATT&CK view of our RBAC findings" — or asks to (re)build the RBAC/tenancy dashboard. Deterministically aggregates authorization and tenant-isolation findings from the corpus-resolved report population (disposition-aware, FP-excluded, branch re-audits excluded) into an executive rollup with MITRE ATT&CK candidate-technique heat, a detailed top-misconfigurations report, and a self-contained HTML dashboard under progress-tracker/metrics/dashboards/rbac-tenancy/.
metadata:
  harness.tier: "secondary"
---

# RBAC & Multi-Tenancy Rollup

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Aggregates the campaign's RBAC (authorization) and multi-tenancy
(tenant-isolation) findings into leadership-facing rollups. All analysis
is traust-core-side and deterministic; the model's job is to run the builder,
sanity-check the outputs, and narrate.

## Input

`$ARGUMENTS` may be empty (default: every product) or name products
(`--product <slug>`), repositories (`--repo-url`) or an alternate output directory.

## Procedure

### Step 1 — run the deterministic builder

```bash
python3 -m traust.cli dashboard view findings-rollup \
    [--product <slug>…] --out progress-tracker/metrics/dashboards/rbac-tenancy
python3 -m traust.cli findings summary --repo-url <url> --group-by category
```

traust-core's `FindingsRollupView` counts the findings (never a hand-rolled
walker) and writes `findings-rollup.{md,html,json}` to
`progress-tracker/metrics/dashboards/rbac-tenancy/`: headline counts, per-repository
and per-product tables, top findings. `findings summary` counts one repository's
findings per `category` (the RBAC/tenancy rows are the ones named below).
*Retired:* the RBAC/tenancy selection, the top-patterns and per-pattern
detailed reports and the ATT&CK heat. Those await the weakness classification
(Q5) and the label taxonomy in traust-contracts; the rollup is portfolio-wide until then.
NEED(classifiers: Q5/G11 — category values free-text, no RBAC/tenancy axis scope)
NEED(contracts: label-taxonomy — authz CWE set, ATT&CK labels)

### Step 2 — interpret honestly

- **Counting semantics** (mirror the census taxonomy): the view is
  disposition-aware (false positives excluded, `resolved` counted
  separately, `hardening` bucketed as posture debt, execution-proven
  counted apart from unverified). No raw-audit fallback and no branch
  re-audit filter: it reads recorded findings only.
- *Retired:* the next three bullets (selection tiers, pattern buckets, ATT&CK
  semantics) described the old builder; the view no longer selects, buckets or
  maps techniques. They stay as the contract for the axis-scoped view that
  comes back with Q5 and the label taxonomy.
- **Selection tiers are confidence labels, not equals**: T1 = structured
  fields (`category` ∈ {authorization, tenant-isolation},
  `peach_references`, `isolation_dimensions`/`isolation_boundary`);
  T2 = framework signals (authz CWE set 862/863/269/284/266/250/648/283/639/668,
  OWASP-K8s K02/K08 or `KHS-R*` citations); T3 = lexical keyword matches
  (heuristic). Never quote an individual T3 row to leadership without
  opening the underlying finding; T3 aggregates are directional only.
- **Pattern buckets** are first-match regex clusters (confused-deputy via
  controller SA, cross-tenant access, cluster-admin bindings, wildcard
  verbs/resources, cluster-wide secrets read, escalate/bind/impersonate,
  RBAC self-escalation, cross-namespace / AllNamespaces, missing tenant
  scoping, SA-token automount, missing network segmentation,
  webhook/aggregated-API exposure, GitHub-Actions workflow privilege,
  unauthenticated endpoints, app-level role over-grants,
  injection-to-privilege, untrusted build/auto-merge input, TLS
  verification gaps, client-supplied identity trust, hardcoded/leaked
  credentials, privileged workload config, cloud IAM overbreadth, shared
  identities). A finding lands in exactly one bucket; `other` collects
  the remainder — if `other` dominates, the buckets need extending (file
  it, don't hand-wave).
- **ATT&CK semantics**: the technique heat table lists **weakness-derived
  CANDIDATE techniques** (what an adversary would use to exploit that
  weakness class), inferred from three sources in confidence order —
  `cited` (finding text names the technique), `pattern` (bucket-derived
  map), `category` (attack-coverage's shared `category_map`). All IDs are
  validated against the pinned vendored ATT&CK table
  (`harnessing/attack-coverage/tables/`); deprecated/revoked/unknown IDs
  are dropped and reported. NEVER present candidates as observed
  adversary behavior — for validated chains use `/attack-coverage`, which
  joins live-validation evidence. Keep the MITRE attribution line in any
  derived artifact.

### Step 3 — placement discipline

Outputs are dashboards/rollups → they belong in
`progress-tracker/metrics/dashboards/` and ONLY there. Never copy the
underlying findings reports into progress-tracker; the rollups reference
`analysis-results` paths (owner directive, 2026-07-21).

## Failure modes

| Symptom | Likely cause | Fix |
|---|---|---|
| Counts disagree with census headline | census counts ALL findings; this rollup is portfolio-wide until the axis scope returns, and applies the same disposition rules | expected — cite the population block |
| Zero tenancy findings on a multi-tenant tree | reports predate PEACH tagging | note the coverage gap; re-audit or isolation-review refreshes tags |
