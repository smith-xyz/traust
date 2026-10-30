---
name: insecure-patterns
description: Use when the user asks which insecure coding patterns recur across the portfolio, wants findings grouped/ranked by CWE or OWASP ASVS category, asks "what are our top vulnerabilities by pattern", "which repos share CWE-X", or asks to (re)build the insecure-patterns dashboard. Reads the findings recorded in traust-core (owned and upstream reported as separate ownership cuts), buckets by primary CWE, and writes insecure-patterns.{md,html,json}.
argument-hint: "[summary] [open]"
metadata:
  harness.tier: "secondary"
allowed-tools:
  - Bash(python3 -m traust.cli dashboard view insecure-patterns:*)
  - Bash(ls:*)
  - Bash(open *.html:*)
  - Read
  # scoped 2026-07-31 (P1-W4): A11 grandfather retired —
  # per-script anchored grants replace Bash(python3:*)
---

# Insecure Coding Patterns — ASVS 5.0 roll-up

> **Paths.** `analysis-results/…` and `progress-tracker/…` in this skill are the
> default workspace layout. They resolve through `locations:` in `traust.yaml` in
> `$TRAUST_CONFIG_HOME` (`docs/setup.md`, Storage locations); substitute your
> configured roots.


Aggregate every source-code security finding across the campaign into a ranked
table of recurring insecure coding patterns, categorised against the OWASP
ASVS 5.0 taxonomy, with example `repo · file · function` tuples and a
one/two-line root-cause fix per pattern.

## Input

`$ARGUMENTS` is optional and may be any combination of:

| Token | Meaning |
|---|---|
| *(none)* | Default run — every ownership class in traust-core, write the outputs. |
| `summary` | Also print the top-25 table to the conversation. |
| `open` | Open the resulting dashboard in the default browser when done. |
| `<path>` | *Retired:* the view reads traust-core, not an analysis-results tree. |

---

## Procedure

### Step 1 — Locate the analysis-results root

*Retired:* traust-core holds the findings; there is no root to locate.

### Step 2 — Run the view

```bash
python3 -m traust.cli dashboard view insecure-patterns \
    [--product <slug>…] [--as-of <ISO time>] \
    --out progress-tracker/metrics/dashboards/insecure-patterns
```

What the view does:

1. *Retired:* the report-file glob and tree tagging. It reads the current
   findings recorded in traust-core, so the false-positive drop honours human
   triage and machine validation dispositions. The owned and upstream cuts are
   the corpus registry's ownership classes, aggregated separately — the owned
   cut drives the ranking and the upstream cut is never folded into it.
2. *Retired:* the code-vs-config decision. NEED(classifiers: Q5 — code-vs-config):
   findings are counted unfiltered until it lands.
3. Drops findings with `validation_status: false_positive`.
4. **Pattern key = primary CWE** (`cwes[0]`, required by the report schema).
5. De-duplicates occurrences by `(repo, cwe, path)` — applied within each
   ownership class independently — so per-branch report copies count once.
6. *Retired:* the in-harness `CWE_META` table. NEED(contracts: label-taxonomy —
   CWE names + root-cause fix text): the table shows the CWE id and its ASVS
   label only.
7. *Retired:* the evidence-text function-name regexes. An example is
   `repo · file:lines · symbol`, with the symbol only where traust-core recorded one.
8. Ranks patterns by **distinct repository count**, then occurrence count.
   Every ownership class gets its own ranking by the
   same key, rendered as its own section in `insecure-patterns.md` and
   `insecure-patterns.html`, and as its own cut in `insecure-patterns.json`.
9. Writes the artefacts under `progress-tracker/metrics/dashboards/insecure-patterns/`.

### Step 3 — Report back

Always tell the user:

- The output paths.
- Corpus stats: occurrences counted per ownership class (one per repository·path),
  occurrences without a
  CWE, distinct patterns.
- The top-25 table (CWE · ASVS § · repos · occurrences) for each ownership
  class; mention the upstream cut headline (top pattern) when it is present.

If `open` was requested, open the dashboard:
`open progress-tracker/metrics/dashboards/insecure-patterns/insecure-patterns.html`

---

## Outputs

| File | Purpose |
|---|---|
| `insecure-patterns/insecure-patterns.md` | Ranked top-25 table per ownership class (owned first), CWE · ASVS · repos · occurrences · severity mix · examples. |
| `insecure-patterns/insecure-patterns.html` | The same report as a self-contained HTML page. |
| `insecure-patterns/insecure-patterns.json` | Machine-readable roll-up: the full ranked pattern list per ownership class with severity mix and examples. |

*Retired:* the standard population block (`python3 -m traust.cli corpus`) is not embedded; the ownership classes are the registry's.

---

## Tuning

*Retired:* the tuning constants (`CODE_EXT`, `CONFIG_EXT`, `CWE_META`, `FUNC_PATTERNS`) went with the script; their NEEDs above say where each lands.

---

## Failure modes

| Symptom | Likely cause | Fix |
|---|---|---|
| Pattern shows a bare CWE id and no ASVS label | No label-taxonomy yet | NEED(contracts: label-taxonomy). |
| Examples mostly `file:lines` | traust-core recorded no symbol for the location | Expected — the fallback is intentional. |
| A config-only finding is in the ranking | The code-vs-config filter is not ported | NEED(classifiers: Q5 — code-vs-config). |

## Trends

*Retired:* the run no longer appends `code_findings` / `distinct_cwes` (source
`insecure-patterns`) to the central metrics ledger or injects a trend-vs-previous banner into
`insecure-patterns-top25.md` and the dashboard HTML (the metrics history is retired; see
[`traust-metrics`](../traust-metrics/SKILL.md)).
