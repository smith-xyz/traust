#!/usr/bin/env python3
"""Emit the structured threat-model artifact beside each Markdown model
(2026-09-20).

Threat models were the only artifact family with no JSON form. Their
structure was always a contract -- section headings, table columns and
enums, stated in the skill's schema.md and enforced by regex in
lint_threat_model.py -- but nothing machine-readable existed, so every
consumer re-parsed the prose with its own copy of the column list. That
is how `attack_refs` came to sit on 786 of 84,623 threats while being
default since harness 0.82.0.

contracts v0.24.0 added threat-model.schema.json. This writes the JSON
the schema describes, from the Markdown that already exists:

    <repo>-threat-model.md    authored, human-edited, stays canonical prose
    <repo>-threat-model.json  the contract artifact, projected into storage

The parse is the one already shipped in traust_engine.reporting.lint and
used by the register builder -- not a second implementation.

THE SCHEMA IS THE AUTHORITY. A model whose prose does not satisfy
threat-model.schema.json does not get an artifact written: an invalid
artifact would be rejected at ingest anyway, and writing one would put a
file on disk that claims to be a contract artifact and is not. Those
models are reported by reason so they can be fixed at the source, which
is the Markdown.

Nothing here is invented. Provenance is read from section 7, never
defaulted -- a fabricated `mode` or `date` is a false fact written into
a contract field whose whole purpose is to record how the model came to
exist. Models with no parseable provenance are reported, not guessed at.

`subject_id` is deliberately NOT written. Identity belongs to the
binding (`artifact_binding.subject_id`, minted from the corpus repo_key
at ingest); a second answer carried inside the document can only agree
or disagree, and disagreeing is worse than being absent. The projector
already prefers the binding value.

Going forward the /threat-model skill should emit both, the way an audit
emits .json and .md. This backfills the models that predate that.

    python3 -m traust.migrations.emit_threat_model_json <root>
    python3 -m traust.migrations.emit_threat_model_json <root> --write
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

from traust.lib.threat_model_artifact import MODEL_SUFFIX, emit


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--write", action="store_true", help="persist the artifacts")
    parser.add_argument(
        "--report",
        type=Path,
        help="write the non-conformant models and their reasons here (JSON)",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()

    tally: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    rejected: list[dict] = []
    seen: set[str] = set()
    pending: list[Path] = []

    for path in sorted(root.rglob(f"*{MODEL_SUFFIX}")):
        real = os.path.realpath(path)
        if real in seen:
            continue  # the same model reached through a symlinked tree
        seen.add(real)
        tally["models"] += 1
        model = Path(real)
        # Dry run still derives and validates -- the point of the run is
        # to learn which models cannot produce an artifact.
        target, why = emit(model, root, write=args.write)
        if why:
            tally["rejected"] += 1
            reasons[why[0].split(":")[0] if len(why) > 1 else why[0]] += 1
            rejected.append(
                {"model": str(model.relative_to(root)), "reasons": why[:10]}
            )
            continue
        tally["conformant"] += 1
        pending.append(target)

    print(
        f"threat models: {tally['models']} found, {tally['conformant']} conformant"
    )
    if tally["rejected"]:
        print(
            f"  NOT WRITTEN           {tally['rejected']} — fix the Markdown",
            file=sys.stderr,
        )
        for reason, count in reasons.most_common(15):
            print(f"    {count:6}  {reason}", file=sys.stderr)

    if args.report:
        args.report.write_text(
            json.dumps({"rejected": rejected}, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(f"  reasons written to    {args.report}")

    if not args.write:
        print("\ndry run: nothing written. Re-run with --write.")
        return 0
    print(f"\nwrote {len(pending)} artifact(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
