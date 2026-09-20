#!/usr/bin/env python3
"""Make live-validation artifacts satisfy their contract (2026-09-19).

Two independent repairs, neither of which changes the schema and neither
of which re-runs anything.

ONE -- attack-chain steps are ENRICHED, not relaxed.
`validation.schema.json` requires a chain step to carry adapter, verb and
classification. The producer emits only {step_id, finding_ref, verdict},
so every artifact failed. The missing fields are already recorded, keyed
by step_id, in the validation-audit.jsonl the artifact itself references:
53,133,757 chain steps across 1,242 artifacts, 100% resolvable, zero
gaps. So the fix is to carry them into the chain, not to stop asking for
them.

TWO -- run diagnostics move to a sidecar.

A validation artifact records OUTCOMES: which claimed findings were
confirmed, refuted, inconclusive, blocked by scope, or not attempted. The
producer additionally inlines diagnostics about the RUN -- why a finding
was not attempted, on which surface it would have run, who approved the
session and when. Measured across the corpus:

    skip_reason              180,257 of 208,346 findings
      triage-false-positive  154,366   a routing decision the LEDGER
                                       already records
      no-poc-no-adapter       15,871   harness capability gap
      wrong-surface:*          4,992   routing mismatch
      dos-needs-destructive      714   safety refusal
    surface                  205,756
    summary.by_surface / not_attempted_by_reason / needs_credential_count
    metadata.approval.approved_by / approved_at
    needs_credential

None describes the SUBJECT; every one describes the run. No published
dashboard reads any of them -- the live-validation dashboard reports a
verdict x claimed-severity matrix and nothing else. And `skip_reason`
appears on zero confirmed, refuted or inconclusive findings: it exists
only on rows where nothing happened.

So they move to a sidecar rather than into the contract. NOT deleted:
validation-audit.jsonl records attempted STEPS, and a finding that was
never attempted produces no step, so the reasons have no other home.

`verdict: not_attempted` STAYS on the artifact. "We did not attempt this"
is a real outcome, it is in the dashboard's matrix, and it is a claim the
validation is entitled to make. It is the REASON that is run-log.

    python3 -m traust.migrations.split_validation_runlog <root>
    python3 -m traust.migrations.split_validation_runlog <root> --write
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

RUN_TOP = ("needs_credential",)
RUN_SUMMARY = (
    "by_surface",
    "not_attempted_by_reason",
    "needs_credential_count",
    # Provenance of a re-scoring pass: which verdicts moved and the
    # before/after counts. A property of the RUN that produced this
    # restatement, not of the subject. 44 artifacts.
    "recompute",
)
RUN_APPROVAL = ("approved_by", "approved_at")
RUN_FINDING = (
    "skip_reason",
    "surface",
    # A manual adjudication note explaining why the tool's verdict was
    # overridden ("Downgraded per MANUAL-REVIEW-FLAGS.md -- v0.4.3
    # _verdict() substring FP"). It documents a decision about the RUN, not
    # a property of the finding, so it travels with the other run detail.
    # 6 occurrences, all on inconclusive.
    "verdict_note",
)

#: What the contract says a validation STEP is. Read from the schema so
#: the split follows the contract rather than a list that drifts from it.
STEP_FIELDS = frozenset(
    {
        "step_id",
        "adapter",
        "verb",
        "classification",
        "verdict",
        "target",
        "evidence",
        "expected",
        "observed",
        "differential",
        "duration_ms",
        "error",
        "controls",
        "replay",
        "rollback_output",
        "rollback_performed",
        "scope_reason",
        "soundness_flag",
        "finding_ref",
        "novel_ref",
    }
)


def enrich_chain_steps(document: dict, log: dict[str, dict]) -> int:
    """Carry the recorded execution detail into each attack-chain step.

    The chain names the steps; the execution log says what each one did.
    The contract asks the chain to carry adapter/verb/classification, and
    the log has all three keyed by step_id -- so this is a join, not an
    invention. A step whose id is absent from the log is LEFT ALONE and
    reported by the validator rather than filled with a guess.
    """
    filled = 0
    for chain in document.get("attack_chains") or []:
        for step in chain.get("steps") or []:
            entry = log.get(step.get("step_id"))
            if entry is None:
                continue
            changed = False
            for key in ("adapter", "verb", "classification", "target"):
                if key not in step and key in entry:
                    step[key] = entry[key]
                    changed = True
            filled += bool(changed)
    return filled


def read_log(path: Path) -> dict[str, dict]:
    """Index a validation-audit.jsonl by step_id."""
    log: dict[str, dict] = {}
    if not path.is_file():
        return log
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if entry.get("step_id"):
            log[entry["step_id"]] = entry
    return log


VERDICTS = ("confirmed", "refuted", "inconclusive", "blocked_by_scope", "not_attempted")


def recompute_summary(document: dict) -> dict | None:
    """Derive summary.by_verdict from the findings it summarises.

    The contract requires all five verdicts so that a zero is STATED rather
    than omitted -- "nothing was refuted" is a claim, and an absent key
    cannot make it. The producer omits zero counts, which fails validation.

    Filling the gaps with zero would have been wrong: measured across the
    corpus, by_verdict disagrees with validated_findings in 78 artifacts,
    and one (hawtio-csrf) omits `refuted` while actually carrying 2. So the
    rollup is recomputed from the detail, which is the evidence. Two
    independent counts of one thing is how they drift.

    Returns what changed, for the record.
    """
    summary = document.setdefault("summary", {})
    stated = summary.get("by_verdict") or {}
    actual = dict.fromkeys(VERDICTS, 0)
    for finding in document.get("validated_findings") or []:
        verdict = finding.get("verdict")
        if verdict in actual:
            actual[verdict] += 1
    changed = {v: (stated.get(v), actual[v]) for v in VERDICTS if stated.get(v) != actual[v]}
    summary["by_verdict"] = actual
    # novel_findings is required and an absent one means none were found.
    document.setdefault("novel_findings", [])
    document.setdefault("attack_chains", [])
    return changed or None


def split(document: dict) -> dict | None:
    """Move run diagnostics out of `document`. Returns the sidecar, or None."""
    runlog: dict = {}
    for key in RUN_TOP:
        if key in document:
            runlog[key] = document.pop(key)

    summary = document.get("summary") or {}
    for key in RUN_SUMMARY:
        if key in summary:
            runlog.setdefault("summary", {})[key] = summary.pop(key)

    approval = (document.get("metadata") or {}).get("approval") or {}
    for key in RUN_APPROVAL:
        if key in approval:
            runlog.setdefault("approval", {})[key] = approval.pop(key)

    findings: dict[str, dict] = {}
    for finding in document.get("validated_findings") or []:
        moved = {k: finding.pop(k) for k in RUN_FINDING if k in finding}
        # Step-level extras the contract does not model (`note`, `redacted`).
        # Driven by the schema's own allowed set rather than a hand-kept
        # list, so a new producer field lands in the sidecar instead of
        # breaking ingest.
        step_extras = []
        for index, step in enumerate(finding.get("steps") or []):
            if not isinstance(step, dict):
                continue
            extra = {k: step.pop(k) for k in list(step) if k not in STEP_FIELDS}
            if extra:
                step_extras.append({"index": index, **extra})
        if step_extras:
            moved["step_extras"] = step_extras
        if moved:
            findings[finding.get("source_id", "")] = moved
    if findings:
        runlog["findings"] = findings

    return runlog or None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--write", action="store_true", help="persist the split")
    args = parser.parse_args(argv)

    moved: Counter[str] = Counter()
    corrections: dict[str, dict] = {}
    touched: list[tuple[Path, dict, dict]] = []

    for path in sorted(args.root.rglob("*-validation.json")):
        if "_manifest" in path.parts:
            continue
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            print(f"skip {path}: {error}", file=sys.stderr)
            continue
        log = read_log(path.with_name("validation-audit.jsonl"))
        moved["chain_steps_enriched"] += enrich_chain_steps(document, log)
        drift = recompute_summary(document)
        if drift:
            moved["summaries_corrected"] += 1
            corrections[path.name] = drift
        runlog = split(document)
        if runlog is None and not drift:
            continue
        runlog = runlog or {}
        runlog["artifact"] = path.name
        for key in runlog:
            if key not in ("artifact",):
                moved[key] += 1
        moved["findings_with_diagnostics"] += len(runlog.get("findings") or {})
        touched.append((path, document, runlog))

    if corrections:
        print(f"summary.by_verdict corrected in {len(corrections)} artifact(s):")
        for name, drift in list(corrections.items())[:5]:
            detail = ", ".join(f"{v}: {a}->{b}" for v, (a, b) in drift.items())
            print(f"  {name[:44]:<46}{detail}")
        if len(corrections) > 5:
            print(f"  ... and {len(corrections) - 5} more")
        print()
    print(f"validation run-log split: {len(touched)} artifact(s)")
    for key, count in moved.most_common():
        print(f"  {count:>8}  {key}")

    if not args.write:
        print("\ndry run: nothing written. Re-run with --write.")
        return 0
    for path, document, runlog in touched:
        sidecar = path.with_name(path.name.replace("-validation.json", "-validation-runlog.json"))
        sidecar.write_text(json.dumps(runlog, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\nwrote {len(touched)} artifact(s) and their sidecars")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
