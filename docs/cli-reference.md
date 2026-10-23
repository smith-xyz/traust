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

18 groups (plus the deprecated `tools` group below).

| Group | Description | Operations |
|---|---|---|
| `adapters` | Scanner adapters (deterministic pre-scans) | `checkov`, `crypto-audit`, `crypto-probe`, `gitleaks`, `govulncheck`, `joern`, `opengrep`, `osv`, `yara` |
| `admin` | Operator tooling | `attest-target`, `checkpoint`, `countersign`, `query-index`, `scan-internal-refs`, `toolchain` |
| `auth` | Who you act as, over traust-core's identity provider | `local`, `login`, `logout`, `refresh`, `service-account`, `status`, `token` |
| `build` | Deterministic builders | `rescan-worklist`, `skills-reference`, `symbol-index` |
| `check` | Deterministic gates | `citations`, `content-licenses`, `docs-consistency`, `estate-data`, `drift`, `fix-propagation`, `location-paths`, `reference-integrity`, `skill-alignment`, `skill-security` |
| `compliance` | Compliance reporting | `dashboard`, `scope` |
| `dashboard` | Dashboard rebuilds | `refresh` |
| `feeds` | Feed management | `fetch` |
| `findings` | track-findings' doors on traust-core | `baseline`, `confirm`, `decide`, `find`, `history`, `import`, `queue`, `refuted`, `reject`, `sarif`, `status`, `surfaces`, `tickets` |
| `impact` | Impact analysis | `analyze`, `calibrate-rule-pack`, `cluster-state-diff`, `resolve-advisory-symbols`, `sweep` |
| `ledger` | Doc-variance register | `doc-variance` |
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
| Ledger triage / validation / verification emitters | Convert report verdicts into legacy layer events | `traust triage record` uses core findings; validation/remediation skill ports remain unfinished |
| `ledger pull` | Ingest external source determinations into the legacy ledger | `traust findings import` uses core attestation and the shared authenticated caller |
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

## Authentication and finding statements

`traust auth login` stores a deployment login obtained by device code.
`traust auth login --token-file /private/token` imports a token without putting
it on argv. A solo installation may instead use:

```bash
traust auth local --identity reviewer@example.com --config-home /path/to/private-config
traust auth status --config-home /path/to/private-config
```

Local tokens are trusted only when `core.yaml` explicitly sets
`identity: {trust_local: true}`. `auth service-account` and `auth local --machine`
are machine sessions, not human approval. `auth refresh` renews a stored login;
`auth logout` removes it. `auth token` deliberately prints the secret: do not
run it in an agent-visible capture or log.

The `findings` group reads core state (`baseline`, `find`, `status`, `history`),
imports forge/Jira statements (`import`), reads queued statements (`queue`),
and supplies refuted findings, review surfaces, SARIF and ticket links.
`findings decide FINDING --validity <canonical> --rationale '<own judgement>'`
records a statement under the stored, verified caller.

Both `findings confirm ITEM FINDING …` and `findings reject ITEM FINDING …`
require at least one actual `--validity`, `--severity` or `--resolution` and
the human's own `--rationale`. They atomically append that judgement and settle
only that review item. Reject never infers an inverse or means "close without
a decision". No judgement means defer, leaving the item pending.
`--evidence-grade` is optional and never inferred. Exact replay is idempotent;
cross-finding answers or altered replay are refused without an orphan decision.
For full evidence cards, requests and typed single/bulk apply, use countersign.

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
traust admin countersign queue --limit 25 \
    --output /path/to/private-review/countersign-queue.md
traust admin countersign request \
    --finding 31dcc9b8-b569-4340-9032-3b335d53a9ef \
    --reason ambiguous_statement --token-stdin \
    < /path/to/private-identity-token
```

Without `--output`, queue returns JSON `{"items":[...],"next":null-or-cursor}`.
Core `ReviewCase` provides `review_item`, rich `finding` and attributed `history`;
the client adds `evidence` (integrity-checked artifact
documents, including raw probe observations). `--finding`, `--reason` and
`--status` filter the read; status defaults to pending, limit to 100. Resume with
`--cursor <returned-next>` and unchanged filters/limit until next is null.
Invalid cursors or nonpositive limits fail, not an empty queue. Canonical reason
and status choices come from `queue --help`.

`--output` explicitly creates a new Markdown workbench with permissions 0600;
existing files and symlinks are refused, never overwritten. It includes the same
decision cards/evidence, page filters and next cursor. Stdout is a receipt
`{"written":"path","items":count,"next":null-or-cursor}` without evidence or
submitted rationale. Use a new file per page. The file is intentionally
sensitive, untrusted review material, not authoritative state.

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

For the async round trip, the human edits **only** the generated Markdown file's
single marked typed JSON block, adding the above answer objects to `answers`:

````markdown
<!-- traust:countersign-answers:v1:begin -->
```json
{
  "type": "traust.countersign.answers.v1",
  "answers": []
}
```
<!-- traust:countersign-answers:v1:end -->
````

Then run `traust admin countersign apply /path/to/private-review/countersign-queue.md`
(optionally `--token-stdin`). The exact markers, JSON fence and type are required;
the payload is limited to one MiB. Missing, duplicate or malformed controls,
duplicate JSON fields and invalid rows fail rather than being silently ignored.
Cards escape HTML/comment markers and use safe fences; evidence cannot forge
the answer block. Checkboxes, prose, copied report JSON and `DECISION:` lines are
never interpreted as approval. Do not populate answers from machine text.

An unchanged Markdown `answers: []` is an explicit **defer**: verified-human
authentication is still required, but no decision or review is changed. Exit 0
returns `{"results":[],"deferred":true}`. Omitted items remain pending. A plain
JSON empty array still fails; existing JSON object/nonempty-array behavior is
unchanged. All answers use the same strict core service calls regardless of file
format.

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
verified human; a machine admin does not qualify. Without `--token-stdin`, the
workbench uses the same stored login verified by `load_caller(core)` as the
`findings` group. An explicit `--token-stdin` reads only stdin and never falls
back to a stored login if missing, invalid or unauthorized. Omit that flag and
the token redirection from the examples to use the stored login.
No second credential store, local bypass flag or caller actor argument is
accepted. Use an argv-list API or shell-safe quoting for dynamic arguments;
never interpolate rationale into shell syntax or put tokens in argv/logs.

For PostgreSQL install the core-owned driver with `uv sync --extra postgres`.
SQLite needs no extra. `database.url` belongs in `core.yaml`; the app never opens
the connection directly.

Write receipts/errors omit submitted rationale and tokens. Queue history and
evidence deliberately expose prior judgements for review: they are sensitive
review material, not publication receipts. Reload through
`services.findings.history/get`, core `ReviewCase` queues and
`services.attestation.for_finding`.
The [skill](../harnessing/4-triage/countersign/SKILL.md#legacy-parity-and-retirement)
accounts for retired checkbox/prose approval parsing, scan-ID mapping and
file-based state; the typed async workbench does not restore those paths.
