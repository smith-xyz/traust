#!/usr/bin/env python3
"""Emit the structured threat-model artifact beside each Markdown model
(2026-09-20).

Threat models were the only artifact family with no JSON form. Their
structure was always a contract -- section headings, table columns and
enums, stated in the skill's schema.md and enforced by regex in
lint_threat_model.py -- but nothing machine-readable existed, so every
consumer re-parsed the prose with its own copy of the column list. That
is how `attack_refs` came to sit on 781 of 82,075 threats while being
default since harness 0.82.0.

contracts v0.24.0 added threat-model.schema.json. This writes the JSON
the schema describes, from the Markdown that already exists:

    <repo>-threat-model.md    authored, human-edited, stays canonical prose
    <repo>-threat-model.json  the contract artifact, projected into storage

The parse is the one already shipped in traust_engine.reporting.lint and
used by the register builder -- not a second implementation.

Going forward the /threat-model skill should emit both, the way an audit
emits .json and .md. This backfills the 7,476 models that predate that.

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

from traust_engine.corpus.threat_model import parse_threats

#: Fields the contract keeps on a threat, in schema order.
THREAT_FIELDS = (
    "id",
    "threat",
    "surface",
    "asset",
    "impact",
    "likelihood",
    "status",
    "controls",
    "evidence",
    "attack_refs",
    "isolation_dimensions",
)


def build(path: Path, root: Path) -> dict | None:
    """Shape one parsed model into the contract artifact, or None."""
    parsed = parse_threats(path, root)
    if not parsed:
        return None
    subject = str(path.relative_to(root).parent)
    threats = []
    for threat in parsed["threats"]:
        row = {field: threat[field] for field in THREAT_FIELDS if field in threat}
        row["actor"] = threat["actors"]
        threats.append(row)
    return {
        "system": path.parent.name,
        "subject_id": subject,
        "provenance": {
            "mode": "bootstrap",
            "date": "2026-01-01",
            "target": parsed["meta"]["root"],
        },
        "threats": threats,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--write", action="store_true", help="persist the artifacts")
    args = parser.parse_args(argv)
    root = args.root.resolve()

    tally: Counter[str] = Counter()
    written: list[tuple[Path, dict]] = []
    seen: set[str] = set()

    for path in sorted(root.rglob("*-threat-model.md")):
        real = os.path.realpath(path)
        if real in seen:
            continue  # the same model reached through a symlinked tree
        seen.add(real)
        document = build(Path(real), root)
        if document is None:
            tally["unparseable"] += 1
            continue
        tally["models"] += 1
        tally["threats"] += len(document["threats"])
        tally["with_attack_refs"] += sum(
            1 for t in document["threats"] if t.get("attack_refs")
        )
        written.append((Path(real).with_name(Path(real).name[: -len(".md")] + ".json"), document))

    print(f"threat-model artifacts: {tally['models']} model(s), {tally['threats']} threats")
    print(f"  with attack_refs      {tally['with_attack_refs']}")
    if tally["unparseable"]:
        print(f"  UNPARSEABLE           {tally['unparseable']}", file=sys.stderr)

    if not args.write:
        print("\ndry run: nothing written. Re-run with --write.")
        return 0
    for target, document in written:
        target.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\nwrote {len(written)} artifact(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
