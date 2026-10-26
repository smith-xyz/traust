---
name: attack-coverage
description: Use when the user asks for MITRE ATT&CK coverage of the portfolio — "which ATT&CK techniques/tactics do our threats or validated chains cover", "build the ATT&CK Navigator layer", "ATT&CK heat map", or after updating threat models/validations to refresh the coverage roll-up. Deterministically joins threat-model attack_refs and finding-category-derived candidates (validated attack chains once traust-core records them) against the pinned vendored ATT&CK table and emits a Navigator layer JSON plus a tactic/technique coverage one-pager.
user-invocable: true
metadata:
  harness.tier: "secondary"
---

# ATT&CK Coverage Roll-up

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Fleet-wide MITRE ATT&CK coverage from artifacts the pipeline already
produces. **Fully deterministic** — every number is a table lookup or a
count; no agent authors, adds, or reinterprets a technique reference.

## The three evidence classes (never blended)

| Class | Source | Meaning |
|---|---|---|
| **observed** (score 3) | confirmed validation chains' `mitre_attack_refs`: not yet recorded in traust-core (NEED: ValidationService), so the view reports this class as not recorded | adversary behavior demonstrated against a live target |
| **modeled** (score 2) | each repository's latest recorded threat model: its threats' ATT&CK techniques (`AssessmentService.threats`) | behavior an owner/bootstrap pass named as a threat |
| **derived** (score 1) | recorded findings' categories (`FindingService.summary`) → [`tables/attack-mapping.json`](tables/attack-mapping.json) `category_map` | candidate techniques implied by a weakness class — potential, not behavior |

## Shared assets (used by other skills)

- [`tables/attack-techniques.json`](tables/attack-techniques.json) — distilled technique/mitigation table
  from ONE sha256-pinned ATT&CK release (`build_attack_table.py`; pin in
  [`tables/attack-bundle.sha256`](tables/attack-bundle.sha256)). The single source every harness
  component validates technique IDs against.
- [`tables/attack-mapping.json`](tables/attack-mapping.json) — harness vocabulary → candidate technique
  IDs (`capability_map` feeds `validate-findings/chain.py`; `category_map`
  feeds this roll-up). Schema: `contracts/schemas/attack-mapping.schema.json`.
- `attack_refs.py` — loader + validator, through traust-core's catalog. CLI:
  `traust attack validate <ids…>` (used by threat-model authors);
  referential integrity is checked by traust-core on every catalog load.

## Run

(traust-core's `AttackCoverageView` joins the classes.)

```bash
traust dashboard view attack-coverage \
    --out progress-tracker/metrics/dashboards/attack-coverage
```

Outputs to `progress-tracker/metrics/dashboards/attack-coverage/`:

| File | Contents |
|---|---|
| `attack-coverage.json` `navigator_layer` | ATT&CK Navigator layer (format 4.5) — load at <https://mitre-attack.github.io/attack-navigator/>; score 1/2/3 = derived/modeled/observed |
| `attack-coverage.md` (and `.html`) | per-tactic and per-technique coverage tables, population block, dropped-reference report |

*(Retired: the metrics append to the shared ledger; trends come from `--as-of`.)*

## Hard rules

- Technique IDs are **selected, never authored**: anything not present and
  live in the pinned table is dropped *and listed* in the "Dropped
  references" section — no silent loss.
- `derived` counts never masquerade as observed behavior; the three
  classes stay separate in every output.
- Upgrading the ATT&CK release is a deliberate act: bump `ATTACK_VERSION`
  in `build_attack_table.py`, run with `--refresh-pin`, review the diff
  (revocations!), fix any mapping fallout flagged by
  traust-core's catalog load (`traust attack validate` refuses), commit.
- ATT&CK® is © The MITRE Corporation, used with attribution under the
  [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/);
  the attribution statement travels in the vendored table and every
  emitted layer.
