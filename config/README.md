# `config/` — one config file: copy, fill in, run `traust admin doctor`

```bash
scripts/install_traust            # copies traust.example.yaml to $TRAUST_CONFIG_HOME/traust.yaml
                                  # (plus the shipped model-registry.yaml)
$EDITOR "$TRAUST_CONFIG_HOME/traust.yaml"   # uncomment and fill in what you use
traust admin doctor               # every effective value and its source: file, env or default
```

An adopter sets **one file, `traust.yaml`**, in the directory named by
`TRAUST_CONFIG_HOME` (default `~/.traust/config`): the database, identity, the ledger
key, budgets, forge hosts, locations, and four small adopter fields (`feeds.osv_access`,
`execution.sandbox`, `remediation`, `campaign`). Secrets come from the environment: the
`*_env` keys name the variable. No `traust.yaml` at all is the zero-config local install
(SQLite and artifacts under `~/.traust`). The schema is traust-contracts' `traust`
(`config/v1/traust.schema.json`); unknown keys are refused. A deployment such as SCI sets
the same file as Helm values and its secrets from a secrets manager.

## What ships here

| File | What it is |
|---|---|
| `traust.example.yaml` | the template for `traust.yaml`: every section, documented, commented out except the defaults. As copied it is the zero-config install |
| `model-registry.yaml` | model tier classes, routing roles and prices; read from the config home, where `install_traust` copies it ([procedure](../docs/model-classes.md#configuring-your-own-models)) |
| `rule-pack-allowlist.example.yaml` | the calibrated supplemental rule allowlist; enable it with `overrides.rule_pack_allowlist` (shipped default: no supplements) |
| `org-parameters.example.yaml`, `adr-registry.example.yaml`, `benchmark-targets.example.yaml` | adopter facts: keep yours in your own repository and record them (`traust compliance policy org-parameters <file>`, `traust compliance policy adr-registry <file>`, `traust sweep benchmark-targets <file>`) |
| `product-definitions-map.example.yaml` | the package/repo → product map `traust registry products` reads from the config home |
| `sla-policy.example.yaml` | the SLA view's policy, read from the config home |
| `export.example.yaml`, `internal-vocabulary.example.yaml` | inputs to the one-shot public export and `traust admin scan-internal-refs`, not runtime config |

## What ships with traust-core instead (not configurable)

Tool pins (`external-tools.yaml`), the base safe-exec profiles (`safe-exec-profiles.yaml`)
and the feeds registry (`feeds.yaml`) are the project's opinions: they ship as traust-core
package data (`traust_core.v1.context.config.SHIPPED_*`) and `traust.context.load()`
registers them. The only override is `overrides.rule_pack_allowlist`. Build scripts that
need the pins (`scripts/containerfile-build-args.py`, `scripts/install-toolchain.sh`) read
the installed package's copy.

## From an old config home

Before `traust.yaml` a config home held up to 25 files. `traust config migrate <old home>`
writes one `traust.yaml` from `core.yaml`, `locations.yaml` (inline as `locations:`),
`ledger.yaml` and `ledger-signing-key.pub` (`ledger:`), `budget-policy.yaml` (`budgets`),
`execution-boundaries.yaml` (`execution.sandbox`), `remediation.yaml`, `campaign.yaml`,
`rule-pack-allowlist.yaml` (`overrides.rule_pack_allowlist`) and an old `feeds.yaml`'s osv
`access: air-gapped` (`feeds.osv_access`). It reports every file: carried, dropped (an old
`external-tools.yaml`, `safe-exec-profiles.yaml` or `feeds.yaml` is never carried, and it
says when one differs from the shipped copy), an adopter fact with the command to record
it, kept, or moved elsewhere. `corpus-config.yaml`, `storage.yaml` and
`hardening-risk-weights.json` are retired (no readers).

## Hygiene gate

`python3 -m traust.cli check docs-consistency` fails when this directory contains anything
other than `model-registry.yaml`, the `*.example.*` templates and this README, or when any
file here carries estate-specific markers.
