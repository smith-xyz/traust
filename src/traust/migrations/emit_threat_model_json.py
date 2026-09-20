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

import jsonschema
from traust_contracts.paths import schema_path

from traust_engine.corpus.threat_model import parse_threats
from traust_engine.reporting.lint import parse_provenance, parse_sections

#: Fields the contract keeps on a threat, in schema order. `key`, `model`,
#: `product`, `linddun` and `score` are parser bookkeeping or derived
#: values, not contract fields -- `$defs/threat` sets
#: `additionalProperties: false`, so carrying them would invalidate every
#: artifact. The projection derives the ones it needs.
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

#: Provenance bullets the contract declares. `owner: unset` is how a
#: bootstrap model spells "nobody reviewed this", and the schema says the
#: field must be ABSENT in that case -- "a model nobody reviewed must not
#: look reviewed" -- so the literal string is dropped rather than carried.
PROVENANCE_FIELDS = ("mode", "date", "target", "inputs", "owner", "harness_version")
PROVENANCE_REQUIRED = ("mode", "date", "target")
UNSET = {"unset", "none", "n/a", "-", ""}


def _validator() -> jsonschema.Draft7Validator:
    schema = json.loads(schema_path("threat-model").read_text(encoding="utf-8"))
    return jsonschema.Draft7Validator(schema)


def provenance(path: Path) -> dict[str, str] | None:
    """Section 7 as the contract's provenance block, or None.

    None means the section carries none of the three required bullets.
    That is a model defect, reported rather than papered over: the
    alternative is writing a `date` nobody recorded.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    sections = dict(parse_sections(text))
    body = next(
        (lines for head, lines in sections.items() if "provenance" in head.lower()),
        None,
    )
    if body is None:
        return None
    parsed = parse_provenance(body)
    block = {}
    for field in PROVENANCE_FIELDS:
        value = (parsed.get(field) or "").strip()
        if not value or value.lower() in UNSET:
            continue
        block[field] = value
    if any(field not in block for field in PROVENANCE_REQUIRED):
        return None
    return block


def build(path: Path, root: Path) -> dict | None:
    """Shape one parsed model into the contract artifact, or None."""
    parsed = parse_threats(path, root)
    if not parsed:
        return None
    block = provenance(path)
    if block is None:
        return None
    threats = []
    for threat in parsed["threats"]:
        row = {field: threat[field] for field in THREAT_FIELDS if field in threat}
        row["actor"] = threat["actors"]
        threats.append(row)
    # The register's `product` -- the directory that groups a subject's
    # models -- so the projection's `product` column means the same thing
    # it has always meant in the threat dashboards.
    return {
        "system": parsed["threats"][0]["product"],
        "provenance": block,
        "threats": threats,
    }


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
    validator = _validator()

    tally: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    rejected: list[dict] = []
    written: list[tuple[Path, dict]] = []
    seen: set[str] = set()

    for path in sorted(root.rglob("*-threat-model.md")):
        real = os.path.realpath(path)
        if real in seen:
            continue  # the same model reached through a symlinked tree
        seen.add(real)
        tally["models"] += 1
        relative = str(Path(real).relative_to(root))
        document = build(Path(real), root)
        if document is None:
            tally["unusable"] += 1
            # Distinguish the two ways build() gives up: they are
            # different defects with different fixes.
            why = (
                "no parseable threats table"
                if parse_threats(Path(real), root) is None
                else "section 7 provenance missing mode/date/target"
            )
            reasons[why] += 1
            rejected.append({"model": relative, "reason": why})
            continue
        errors = sorted(validator.iter_errors(document), key=lambda e: e.json_path)
        if errors:
            tally["invalid"] += 1
            for error in errors:
                where = "/".join(str(part) for part in error.absolute_schema_path)
                reasons[where] += 1
            rejected.append(
                {
                    "model": relative,
                    "reason": "schema",
                    "errors": [
                        {"path": e.json_path, "message": e.message[:300]}
                        for e in errors[:10]
                    ],
                }
            )
            continue
        tally["valid"] += 1
        tally["threats"] += len(document["threats"])
        tally["with_attack_refs"] += sum(
            1 for t in document["threats"] if t.get("attack_refs")
        )
        written.append(
            (Path(real).with_name(Path(real).name[: -len(".md")] + ".json"), document)
        )

    print(
        f"threat models: {tally['models']} found, {tally['valid']} conformant "
        f"({tally['threats']} threats)"
    )
    print(f"  with attack_refs      {tally['with_attack_refs']}")
    if tally["unusable"] or tally["invalid"]:
        print(
            f"  NOT WRITTEN           {tally['unusable'] + tally['invalid']} "
            f"({tally['unusable']} unusable, {tally['invalid']} schema-invalid)",
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
    for target, document in written:
        target.write_text(
            json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    print(f"\nwrote {len(written)} artifact(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
