# CLI Command Reference

<!-- The group/operation table below is verified against the live GROUPS
     registry by the "CLI reference drift" check in check_docs_consistency.py.
     Add a group or operation in code and this table fails the docs gate
     until it matches — do not hand-wave it. -->

The harness CLI is grouped: **`traust <group> <operation>`**, or
`python3 -m traust.cli <group> <operation>` from the harness venv. Both are the
same entry point (`[project.scripts] traust = "traust.cli.__main__:main"`).

```bash
traust check skill-alignment
python3 -m traust.cli check skill-alignment      # equivalent
```

## Command groups

15 groups (plus the deprecated `tools` group below).

| Group | Description | Operations |
|---|---|---|
| `adapters` | Scanner adapters (deterministic pre-scans) | `checkov`, `crypto-audit`, `crypto-probe`, `gitleaks`, `govulncheck`, `joern`, `opengrep`, `osv`, `yara` |
| `admin` | Operator tooling | `attest-target`, `checkpoint`, `countersign`, `query-index`, `scan-internal-refs`, `toolchain` |
| `build` | Deterministic builders | `rescan-worklist`, `skills-reference`, `symbol-index` |
| `check` | Deterministic gates | `citations`, `content-licenses`, `docs-consistency`, `estate-data`, `drift`, `fix-propagation`, `location-paths`, `reference-integrity`, `skill-alignment`, `skill-security` |
| `compliance` | Compliance reporting | `dashboard`, `scope` |
| `dashboard` | Dashboard rebuilds | `refresh` |
| `feeds` | Feed management | `fetch` |
| `impact` | Impact analysis | `analyze`, `calibrate-rule-pack`, `cluster-state-diff`, `resolve-advisory-symbols`, `sweep` |
| `ledger` | Documentation-variance tooling | `doc-variance` |
| `metrics` | Metrics & spend | `attribute-spend`, `collect-spend`, `history`, `sla`, `spend` |
| `portfolio` | Portfolio graph | `artifacts`, `build`, `deps-multi`, `freshness`, `interfaces`, `parsers`, `query`, `stats`, `symbols` |
| `registry` | Model/product registry | `models`, `products` |
| `reporting` | Report validation & rendering | `lint`, `rate-threats`, `render`, `sarif`, `validate` |
| `sweep` | Class-generalization sweep | `benchmark`, `collect`, `draft`, `emit`, `mine`, `rule-lane`, `sweep` |
| `util` | Utility commands | `elf`, `redact`, `safe-exec` |

### Retired workflow entry points

The core-hub cutover removed the following entry points; they are **not**
deprecated aliases. Their former purposes and replacement owners are listed
here so an old runbook cannot be mistaken for an executable fallback:

| Former entry point | Former purpose | Current owner / port status |
|---|---|---|
| `build cumulative` | Replay legacy layers into findings-current reports | Core finding queries and insight services; report skill port unfinished |
| `check report-digests` | Verify report/artifact digest bindings | Core artifact publishing/index services; gate skill port unfinished |
| `feeds reconcile-cve-provenance` | Reconcile advisory provenance on findings | Core exposure service; skill port unfinished |
| Ledger triage / validation / verification emitters | Convert report verdicts into legacy layer events | Core finding decisions, validation and remediation services respectively; skill ports unfinished |
| `ledger pull` | Ingest external source determinations into the legacy ledger | Core finding intake/decisions; source-ingestion skill port unfinished |
| `corpus` group | Report discovery, identity, projections, summaries and precedents | Core assessment and finding services; corpus skill ports unfinished |
| `route` group | Admit impact findings and remediation regressions without changing baselines | Core finding intake; routing skill ports unfinished |

There is no executable fallback for these workflows. Do not hand-write a
layer, invoke a removed module, or use the severity-only writer below for
finding intake, triage, validation, validity or resolution writes.


## Deprecated forms

Two older spellings still work and must not be used in docs, skills, or
command wrappers:

| Form | Example | Use instead |
|---|---|---|
| Pre-grouping module invocation | `python3 -m traust.cli.check_skill_alignment` | `python3 -m traust.cli check skill-alignment` |
| `tools` group alias | `python3 -m traust.cli tools check-skill-alignment` | `python3 -m traust.cli check skill-alignment` |

The dot-separated form keeps working because each `src/traust/cli/<module>.py`
carries an `__main__` delegate that forwards to the grouped parser — which is
exactly why a stale example drifts silently. `src/traust/cli/groups/tools.py`
self-describes as "deprecated aliases for migrated command groups".

Both are enforced: the **CLI invocation syntax** check in
[`check_docs_consistency.py`](../src/traust/cli/check_docs_consistency.py) fails
the docs gate on any dot-separated invocation in `README.md`, `AGENTS.md`,
`PROCESS.md`, `docs/*.md`, `config/*`, `harnessing/*/SKILL.md`, or
`.claude/commands/*.md`.

> Not every `traust.cli.*` module is a CLI. `traust.cli.budget_shadow`, for
> instance, has no argparse or `__main__` — refer to it as a module path, never
> as `python3 -m`.

See [tooling-and-structure-files.md](tooling-and-structure-files.md) for what
each packaged CLI does, and [skills.md](skills.md) for the skills that call them.

## Direct human severity recording

Only `admin countersign record --decision severity` is ported to core services.
Other countersign operations (including queue/apply and validity overrides) remain
unported and are rejected; the command does not read legacy layers or rebuild
cumulative reports.

```bash
traust admin countersign record \
    --finding 31dcc9b8-b569-4340-9032-3b335d53a9ef \
    --decision severity --severity high \
    --rationale 'Reviewed the reachable call path and impact with the operator.' \
    --token-stdin --config-home /path/to/private-config \
    < /path/to/private-identity-token
```

Use an **existing core finding UUID** and the exact canonical spelling shown by
`traust admin countersign record --help`. `--evidence-grade` is optional; omission
remains ungraded rather than inferring strength from a human or interactive source.
Core refuses weaker/ungraded conflicting overrides of stronger proof.

`--config-home` (or `TRAUST_CONFIG_HOME`) selects `core.yaml`; configure its
`identity:` trusted issuers and directory policy through core. The token is read
only from stdin and authenticated by core, which must return a verified human.
No REST service, legacy ledger login/cache, local identity flag or caller actor
argument is required or accepted. Never embed a token in argv or log it. Dynamic
arguments, especially rationale, must use an argv-list API or shell-safe quoting,
not text interpolated into shell syntax.

For a PostgreSQL record store, install the core-owned driver with
`uv sync --extra postgres`. SQLite needs no extra.
The connection belongs in `core.yaml`'s `database.url`; the command never opens it directly.

Success prints a JSON receipt containing the saved decision UUID and stable
metadata, but neither token nor rationale. The same judged statement is
idempotent; reload through `services.findings.history(finding_id)`. Authentication,
authorization and decision-admission refusals exit 2 without a success receipt.
