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

16 groups (plus the deprecated `tools` group below).

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
| `triage` | Core-backed triage | `check`, `intake`, `prepare`, `record`, `render` |
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

There is no executable fallback for these retired workflows. Do not hand-write a
layer or invoke a removed module. The human countersign workbench below records
judgements on existing core findings; it does not replace machine-report intake.


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

The countersign workbench now includes direct validity/severity/resolution
judgements, pending review cards, review requests and single/bulk reviewed apply.
All commands use core domain services; no legacy layer/corpus/db reads or
cumulative-file rebuilds are performed.

```bash
traust admin countersign record \
    --finding 31dcc9b8-b569-4340-9032-3b335d53a9ef \
    --decision severity --severity high \
    --rationale 'Reviewed the reachable call path and impact with the operator.' \
    --token-stdin --config-home /path/to/private-config \
    < /path/to/private-identity-token
```

Use an **existing core finding UUID** and exact canonical spelling from
`record --help`. `--decision validity --validity <canonical>` and
`--decision resolution --resolution <canonical>` record the corresponding
human judgement. Supply only the field selected by `--decision`.
`--evidence-grade` is optional: omission stays null, never inferred from identity.
Core owns evidence precedence, actor, clock, admission, persistence and replay.

### Review queue and requests

```bash
traust admin countersign queue --limit 25 --config-home /path/to/private-config
traust admin countersign queue --finding 31dcc9b8-b569-4340-9032-3b335d53a9ef
traust admin countersign request \
    --finding 31dcc9b8-b569-4340-9032-3b335d53a9ef \
    --reason ambiguous_statement --token-stdin \
    < /path/to/private-identity-token
```

Queue returns JSON `{"items":[...],"next":null-or-cursor}`. Cards contain
`review_item`, `finding`, `history` and `evidence` (integrity-checked artifact
documents, including raw probe observations). `--finding`, `--reason` and
`--status` filter the read; status defaults to pending, limit to 100. Resume with
`--cursor <returned-next>` and unchanged filters/limit until next is null.
Invalid cursors or nonpositive limits fail, not an empty queue. Canonical reason
and status choices come from `queue --help`.

Request optionally takes `--decision <UUID>` for the proposal being reviewed.
The same pending request is idempotent; a cross-finding proposal is refused.
After a settled item, another independent reviewer can request a new pending
item for the same finding/proposal.

### Single and bulk apply

`traust admin countersign apply /path/to/reviewed-answers.json --token-stdin`
reads **one answer object or a nonempty array**, with this shape:

```json
{
  "review_item_id": "6ef12c66-4e7d-4fac-9b05-cfd6777658ea",
  "decision": "reject",
  "answer": {
    "finding_id": "31dcc9b8-b569-4340-9032-3b335d53a9ef",
    "validity": "confirmed",
    "rationale": "The reviewed unauthenticated path still reaches the proven operation.",
    "evidence_grade": "E0"
  }
}
```

`decision` is confirm or reject; **both** require a genuine explicit answer and
the reviewer's own rationale. Reject never infers an opposite classifier.
The nested answer allows only `finding_id`, `rationale`, optional `validity`,
`severity`, `resolution`, `evidence_grade`; core requires at least one judged
field. Actor/source/time/restatement/auto-accept fields are forbidden.
Omit deferred items instead of creating a fake answer.

Each answer atomically records the human decision and settles that review item.
Exact replay returns the saved item; a changed answer/outcome conflicts without
an orphan decision. Core requires a distinct later E0 second reviewer to dismiss
execution proof: first concurrence leaves it open, replay/same signer is not a
second. Ledger-integrity refusal changes neither decision nor review.
Direct record does not close queue items; selected-review apply does.

Bulk apply is per item, not a batch transaction. It returns
`{"results":[{"ok":true,"review_item":...},{"ok":false,"review_item_id":...,"error":...}]}`.
Successful results include the resolving decision UUID. Exit is 0 when all
succeeded, 2 if any failed. Report partial successes accurately; earlier committed
answers remain saved when a later item fails.
Every successful write receipt includes `finding` with core-derived
`disposition`, `is_open` and effective severity. Review acceptance does not imply
finding closure. If the first E0 dismissal leaves it open, another independent
human must review a new pending item. Re-read accepted cards using
`queue --status accepted --finding <UUID>`.

### Identity and receipts

`--config-home` (or `TRAUST_CONFIG_HOME`) selects `core.yaml`; its `identity:`
configuration owns trust and optional directory policy. Every write requires a
stdin-only token authenticated by core as a verified human; a machine admin does
not qualify. No second login store, local identity flag or caller actor argument
is accepted. Use an argv-list API or shell-safe quoting for dynamic arguments;
never interpolate rationale into shell syntax or put tokens in argv/logs.

For PostgreSQL install the core-owned driver with `uv sync --extra postgres`.
SQLite needs no extra. `database.url` belongs in `core.yaml`; the app never opens
the connection directly.

Write receipts/errors omit submitted rationale and tokens. Queue history and
evidence deliberately expose prior judgements for review: they are sensitive
review material, not publication receipts. Reload through
`services.findings.history/get` and `services.attestation.pending/for_finding`.
The [skill](../harnessing/4-triage/countersign/SKILL.md#legacy-parity-and-retirement)
accounts for retired Markdown parsing, scan-ID mapping and file-based state.
