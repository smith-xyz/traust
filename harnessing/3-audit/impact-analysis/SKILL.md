---
name: impact-analysis
description: Use when determining which portfolio commits are affected by
  an advisory (CVE, GHSA, MAL-/malicious-package, or another OSV-native id).
  Fetches the advisory from its source, walks the blast radius over the
  commits' SBOMs (through base images and internal libraries), classifies
  every commit it reaches (govulncheck symbol reachability for Go, the
  strongest tier; the SBOM pin plus source scans for npm, PyPI, Maven, Cargo,
  RubyGems, NuGet and C libraries; manifest-level for Actions/Docker/Helm)
  and records an `impact` assessment per commit in traust-core, with a
  dependency finding for each `affected` commit.
argument-hint: "<advisory-id> [--repo-url <url> --sha <commit>] [--scan]"
user-invocable: true
metadata:
  harness.tier: "primary"
allowed-tools:
  - Read
  - Glob
  - Grep
  - Write
  - Task
  - Bash(jq:*)
  - Bash(python3 *-m traust.cli impact find:*)
  - Bash(python3 *-m traust.cli impact sbom:*)
  - Bash(python3 *-m traust.cli impact symbols:*)
  - Bash(python3 *-m traust.cli impact analyze:*)
---

# Impact Analysis

Which commits does an advisory reach, and how strongly? Every deterministic
step runs in traust-core (`ExposureService`); this skill drives the doors
and does the judgement the tools can't: reading the results, deciding what
deserves a manual trace, and saying when the evidence is too thin.

| Door | What it does |
|---|---|
| `traust impact find <advisory>` | The advisory **as its source states it now** (the feeds registry's `osv` source): identity, aliases, affected packages with their spans and fixed versions, references. Unknown to the source: not assessed |
| `traust impact sbom <file> --repo-url --sha` | Records a commit's manifest SBOM (CycloneDX / SPDX JSON from syft or osv-scanner). The blast radius reads only recorded SBOMs |
| `traust impact symbols <advisory>` | The functions the fix touched: published by the source (Go), else mined from the fix commits on the advisory and its aliases, each with source and confidence |
| `traust impact analyze <advisory> [--scan]` | Every commit the advisory reaches (or the one named with `--repo-url --sha`): evidence, classification, an `impact` assessment, and a dependency finding for each `affected` commit. `--scan` clones each commit the SBOMs leave undecided, at its own sha, and runs the analysis tiers on it |

## Procedure

### Step 1: The advisory, from its source

```bash
python3 -m traust.cli impact find <ADVISORY-ID>
```

**Ranges and fixed versions come from the fetched advisory, never from
memory.** If `find` fails or the source doesn't know the id, stop and report
the advisory as not assessed. If its `unmodeled_ecosystems` is not empty,
say which ecosystems the analysis can't cover.

### Step 2: SBOMs for commits that have none

The blast radius walks recorded SBOMs only: a commit without one is never
reached, so an empty result can mean "no SBOMs", not "not affected". Record
one with `traust impact sbom` (syft: `syft dir:<checkout> -o cyclonedx-json`).

### Step 3: Analyze

```bash
python3 -m traust.cli impact analyze <ADVISORY-ID> --scan
```

Without `--scan` it is the fast pass: SBOM evidence only, no clones.
`--repo-url <url> --sha <commit>` assesses one commit.

### Step 4: Review

Read the summary: how many commits per classification, and which are
`affected` (each now has a dependency finding, owned and on the SLA clock).
Do the numbers make sense for what the advisory is about?

- `inconclusive` with `needs_manual_trace`: unsafe/reflect/cgo usage may hide
  reachability from govulncheck. A human traces these.
- A note `<tier> skipped: …` means that tier could not run (e.g. govulncheck
  not installed). The commit was **not** checked by it: never read it as clean.
- A note "reached through a base image or an internal library" means the
  commit's own SBOM doesn't list the package. Trace the path before trusting
  any classification above `inconclusive`.
- `symbols` with status `no_symbols_in_diff` or `degraded` means the source
  scan had no symbols to look for: say so, and that `likely_affected` is the
  ceiling.

## Classification rubric

Owned by `ImpactEvidence.classification()` in traust-core; reproduced here so
the review reads the same rules.

| Classification | Meaning | Evidence |
|---|---|---|
| `affected` | Vulnerable symbol reachable | govulncheck `symbol_reachable` |
| `likely_affected` | Present, not shown reachable | SBOM pin in range (manifest ecosystems), imports found, symbols used in source, package path in binaries |
| `not_observed` | The tools we ran didn't observe it | govulncheck `*_not_observed`; not in manifests and no imports |
| `version_not_in_range` | At a safe version | SBOM version outside every affected span |
| `not_imported` | No SBOM of the commit reaches the package | blast-radius miss |
| `inconclusive` | Not enough evidence | in range, no deep scan yet; or a tier could not run |

Manifest, import and symbol-usage evidence never rises above
`likely_affected`; SBOM evidence of shipped images alone decides nothing.
`not_observed` means "not observed by the tools we ran", evidence for a
human decision, never a verdict. **`not_observed` never auto-closes a
tracker.** Every classification carries its evidence in the recorded
artifact.

**Assurance beyond static:** `affected` is machine-static evidence. To reach
execution evidence, feed the affected commits to `/create-fuzzing`; live
validation (`/validate-findings`) is the end-to-end gold standard. Triage's
attacker-influence judgment ranks which `affected` verdicts deserve that
first.

## Downstream consumption

Each commit's result is an `impact` assessment in traust-core with its
`impact-analysis` document, and each `affected` commit has a dependency
finding (`origin: impact-analysis`, `category: supply-chain`, the advisory
on `finding.advisory_id`), filed through traust-core's intake and never
written to the baseline (gate A15). Consumers that read
impact-analysis JSON files under the results tree (triage Phase 2f,
verify-remediation `--impact-filter`, fleet-fix worklists, validate-findings,
create-fuzzing, secure-code/container/rpm audit, drift-watch,
refresh-dashboards) move to `ExposureService` reads in their own ports;
until then no such file is produced. Fix propagation for cross-repo
remediations is `traust check fix-propagation` (also on traust-core).

## Hard rules

- The advisory comes from its source on every run; never from memory.
- The SBOMs are the backbone: keep commits' SBOMs current, or the blast
  radius lies.
- `not_observed` never auto-closes a tracker.
- Every classification carries its evidence.
- The doors own the analysis; the skill invokes them and doesn't
  reimplement them.
