# Tooling and structure files

The schemas, packaged CLIs and key scripts that make up the harness's deterministic tooling.

The schemas below (from the installed `traust-contracts` package) are the complete set; the scripts listed are the key entry points — packaged CLIs live under `src/traust/`, and skill-specific tooling lives alongside each skill in its own `scripts/` — under a stage directory for workflow skills (`harnessing/3-audit/vuln-scan/scripts/`), at the `harnessing/` root for the rest.

| Component | Purpose |
|---|---|
| python3 -m traust.cli util safe-exec + `$TRAUST_CONFIG_HOME/safe-exec-profiles.yaml` | Enforced sandbox for target-derived commands (argv allowlists, env scrub, shell-free pipelines) — gate rule S10; [docs/safe-exec.md](safe-exec.md) |
| python3 -m traust.cli dashboard refresh | Rebuilds the remaining registered dashboard stages; retired corpus projections and dashboard builders are not part of this job — see [continuous-operations.md](continuous-operations.md#standing-jobs--the-complete-inventory) |
| `traust_engine.escaping` | Shared untrusted-text helpers every emitter uses (HTML, inline-script JSON, md cells, CSV, slugs) — library import, not a CLI |
| `schemas/v1/report.schema.json` | JSON Schema (draft 2020-12) for security-audit reports |
| `schemas/v1/triage.schema.json` | JSON Schema for TRIAGE.json validation |
| `schemas/v1/vuln-findings.schema.json` | JSON Schema for vuln-scan candidate reports (`<repo>-vuln-findings.json`) |
| `schemas/v1/adapter-result.schema.json` | JSON Schema for traust-engine scanner adapter `scan()` return values (distinct from skill-level vuln-findings output) |
| `traust-contracts/artifacts_schema/v1/code-facts.schema.json` | Recorded symbols and measured language statistics on a `tool_scan` assessment; read through core's artifact and code-facts services |
| `schemas/v1/validation.schema.json` | JSON Schema for live-validation reports |
| `schemas/v1/remediation.schema.json` | JSON Schema for remediation patches |
| `schemas/v1/verification.schema.json` | JSON Schema for remediation-verification reports |
| `schemas/v1/impact-analysis.schema.json` | JSON Schema for CVE impact-analysis artifacts |
| `schemas/v1/layer.schema.json` | JSON Schema for findings-disposition layers (track-findings ledger) |
| `schemas/v1/refuted-register.schema.json` | JSON Schema for the refuted-finding register: triage or validation refutations kept, integrity-bound, for later execution evidence and countersign |
| `schemas/v1/threat-model.schema.json` | JSON Schema for one subject's threat model contract (`<repo>-threat-model.json`), alongside the authored Markdown (`<repo>-threat-model.md`); the former JSON emitter is retired and the core assessment/artifact skill port is unfinished, with no executable fallback |
| `schemas/v1/corpus-registry.schema.json` | JSON Schema for the corpus ownership registry — the subject→owner/business-unit mapping that every denominator divides by |
| `schemas/v1/operator-priv-profile.schema.json` | JSON Schema for per-operator least-privilege profiles (`*-priv-profile.json`), parsed from shipped manifests — declared state, never a live cluster read |
| `traust_core.v1.services.findings.identity.IdentityPolicy` | Core-owned finding fingerprint recipe and version attribution, moved from traust-ledger. Reuse core identity handling; never invent a second recipe or substitute a fingerprint for the finding UUID required by the severity writer. |
| `schemas/v1/isolation-review.schema.json` | JSON Schema for tenant-isolation review reports |
| `schemas/v1/cloud-config-audit.schema.json` | JSON Schema for declared-layer IaC audit reports |
| `schemas/v1/cloud-config-findings-current.schema.json` | JSON Schema for cloud-config cumulative status reports (`*-findings-current.json` from track-findings) |
| `schemas/v1/compliance-assessment.schema.json` | JSON Schema for compliance-check assessment reports |
| `schemas/v1/compliance-mapping.schema.json` | JSON Schema for the control↔check policy mapping |
| `schemas/v1/doc-variance.schema.json` | JSON Schema for documentation-variance registers (`<repo>-doc-variance.json`) — official docs.redhat.com claims contradicted by code evidence, per doc version; source URL schema-restricted to docs.redhat.com (informal inputs never mint variance records) |
| `schemas/v1/compliance-scope.schema.json` | JSON Schema for the compliance scope registry (declared boundaries; repo membership resolved via the repo-graph product mapping by `python3 -m traust.cli compliance scope`) |
| `schemas/v1/pqc-facts.schema.json` | JSON Schema for the deterministic Layer 1 crypto census (`*-pqc-facts.json`) — the contract `/patch`'s pqc ingest and the Layer 2 prepass consume |
| `schemas/v1/pqc-readiness.schema.json` | JSON Schema for PQC readiness reports |
| `schemas/v1/pqc-blockers.schema.json` | JSON Schema for the findings-shaped projection of readiness remediations (`*-pqc-blockers.json`, emitted by `build_pqc_blockers.py`) — mirrors the security-audit findings vocabulary without claiming `report.schema.json` conformance |
| `schemas/v1/pqc-decision-tree.schema.json` | JSON Schema for the PQC provenance decision tree |
| `schemas/v1/fleet-fix.schema.json` | JSON Schema for fleet-fix transform specs |
| `schemas/v1/sla-policy.schema.json` | JSON Schema for SLA policy files (sla-view) — adopters configuring their own service levels start at [sla-policy.md](sla-policy.md) |
| `schemas/v1/model-registry.schema.json` | JSON Schema for the model registry (config/model-registry.yaml — role routing, tier floors, spend policy) |
| `schemas/v1/benchmark-target.schema.json` | JSON Schema for recall-benchmark target definitions |
| `schemas/v1/attack-mapping.schema.json` | JSON Schema for the finding-category→ATT&CK mapping table |
| `schemas/v1/adr-registry.schema.json` | JSON Schema for the architecture-decision-record registry |
| `schemas/v1/org-parameters.schema.json` | JSON Schema for org-wide parameter files |
| `schemas/v1/risk-rating-methodology.schema.json` | JSON Schema for the risk-rating methodology config |
| `schemas/v1/repo-state.schema.json` | JSON Schema for a repository's forge observation: observed default-branch head compared with its latest audit, stored as a repo-state assessment artifact; unavailable/deferred run outcomes are not observation documents |
| python3 -m traust.cli reporting validate | Validates report JSON against schema; supports `--strict` and batch validation |
| python3 -m traust.cli reporting lint | Deterministic threat-model gate — sections/columns/enums, coverage invariant, ID stability, provenance, evidence hygiene |
| python3 -m traust.cli reporting render | Renders validated JSON reports to Markdown |
| python3 -m traust.cli reporting sarif | Exports any report (incl. disposition-aware findings-current and cloud-config audits) to SARIF 2.1.0 for any SARIF consumer — a derived projection, dispositions become suppressions; `--results-root` batch sweep |
| python3 -m traust.cli check citations | Citation verification gate for findings |
| python3 -m traust.cli build symbol-index | Builds symbol index for triage acceleration |
| python3 -m traust.cli admin query-index | Queries the symbol index |
| Retired baseline-claim workflow | Formerly pinned legacy baseline claim hashes; core finding intake/baseline services own the unfinished skill port, with no executable fallback |
| python3 -m traust.cli triage record | Records validated triage decisions through core; human review items feed the countersign queue |
| python3 -m traust.cli admin countersign | Paged core review cards with evidence, review requests, direct validity/severity/resolution judgements, and typed single/bulk review apply (verified human via stdin token) |
| python3 -m traust.cli check docs-consistency | Doc-drift detection for harness docs |
| python3 -m traust.cli impact cluster-state-diff | P5 discovery sweep 1 — before/after security-state snapshots (RBAC, SCCs, webhooks, NetworkPolicies, Services/Routes) diffed into validation-discovery candidates for /triage |
| python3 -m traust.cli sweep benchmark | P7 validation-lane benchmark — vulnerable/safe-twin fixtures, confirm-recall + refute-precision + severity-accuracy floors, hybrid release-cut/monthly cadence (check-trigger + drift-watch) |
| python3 -m traust.cli admin attest-target | P2 pre-flight target attestation for validation lanes — fail-closed environment gate (cluster fingerprint, CSV/pod readiness, version-in-range, URL reachability) emitting target-attestation.json |
| python3 -m traust.cli registry models | Model-registry loader/resolver — role→model resolution with floor enforcement, routing stamps, spend recording (docs/model-routing.md) |
| python3 -m traust.cli admin checkpoint | Agent checkpoint support |
| python3 -m traust.cli check fix-propagation | Deterministic cross-repo fix-propagation check — has the original repo consumed the fixed module version (go.mod/vendor, lockfiles, shipped-image SBOMs)? Feeds verify-remediation's two-legged rule |
| python3 -m traust.cli impact analyze | CVE impact analysis across the portfolio graph — blast radius, L4 refinement, language-specific deep scan (GoAnalyzer: govulncheck + ELF, the strongest reachability tier; other ecosystems get manifest-level analyzers); `--ecosystem` seeds a non-Go blast radius, `--skip-scan` for graph-only, `--jobs N` for parallel workers |
| Retired regression router | Formerly converted remediation regressions into event-carried findings; core finding intake owns the replacement, but the skill port is unfinished and there is no executable fallback |
| Retired FP-precedent corpus CLI | Formerly built a tiered refutation-precedent index for triage and the Precision Gate; core finding precedents own the replacement, but the skill port is unfinished and there is no executable fallback |
| python3 -m traust.cli sweep | Class-generalization sweep loop: confirmed finding → candidate rule → corpus-wide sweep → triage-ready candidates |
| python3 -m traust.cli sweep mine | The /mine-ledger miner — confirmed-TP corpus, cluster coverage vs the opengrep pack, per-rule campaign precision |
| harnessing/mine-ledger/scripts/emit_rule_drafts.py | Regression-rule draft staging from resolved-at-fix-commit findings (pre/post calibration pairs) |
| python3 -m traust.cli sweep rule-lane | The weekly rule-mining lane runner — miner → sweep collect/draft → bounded draft staging → `lane-delta.{json,md}` vs the previous mine; exit 1 when the delta needs authoring attention |
| harnessing/census/scripts/check_repo_liveness.py | Census-owned repo-liveness sweep (active/archived/moved/missing, status_since ratcheting) |
| python3 -m traust.cli check skill-alignment | Pre-commit cross-skill contract gate (A-series rules) |
| python3 -m traust.cli check skill-security | Pre-commit security-posture gate (S-series rules incl. S9 repo-config isolation) |
| python3 -m traust.cli adapters crypto-audit | Unopinionated crypto data collector — source/image/cluster tiers emit `crypto-audit/v1` JSON |
| python3 -m traust.cli adapters crypto-probe | Source-level crypto provider census (imported by crypto_audit.py) |
| python3 -m traust.cli util elf | General-purpose ELF binary analyzer (linked libraries, byte scanning) |
