#!/usr/bin/env python3
"""ONE-SHOT, COMPLETED 2026-09-20: Markdown threat models -> JSON artifacts.

7,660 threat models were authored as prose before
`threat-model.schema.json` existed. This read what was on disk and wrote
the contract artifact beside each one: 7,482 written, 82,126 threats.

THIS DIRECTION IS WRONG AND EXISTS ONLY BECAUSE OF THAT HISTORY. Going
forward `/threat-model` authors `<repo>-threat-model.json` against the
schema and renders the Markdown from it with `reporting validate` +
`reporting render`, exactly as every other artifact works. Nothing new
derives an artifact from prose -- which is why this code lives HERE,
self-contained in a dated one-shot, and not in a library where it would
read as a supported path.

The 178 models it could not convert are NOT a correction queue. The
Markdown is an output format now, so editing it by hand is overwritten
by the next emission, and reading intent into `status: open` or
`likelihood: medium` is re-modelling rather than editing. They get an
artifact when /threat-model next authors one; the re-model cadence
already schedules that.

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


#: Fields the contract keeps on a threat, in schema order. `key`,
#: `model`, `product`, `linddun` and `score` are parser bookkeeping or
#: derived values, not contract fields -- `$defs/threat` sets
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

ARTIFACT_SUFFIX = "-threat-model.json"
MODEL_SUFFIX = "-threat-model.md"


def validator() -> jsonschema.Draft7Validator:
    """The contract, loaded from the installed package -- never a copy."""
    schema = json.loads(schema_path("threat-model").read_text(encoding="utf-8"))
    return jsonschema.Draft7Validator(schema)


def artifact_path(model: Path) -> Path:
    """Where the JSON form of this model belongs: beside it."""
    return model.with_name(model.name[: -len(".md")] + ".json")


def provenance(model: Path) -> dict[str, str] | None:
    """Section 7 as the contract's provenance block, or None.

    None means the section does not carry all three required bullets.
    That is a model defect, reported rather than papered over: the
    alternative is writing a `date` nobody recorded into the field whose
    entire purpose is recording how the model came to exist.
    """
    try:
        text = model.read_text(encoding="utf-8")
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


# ---------------------------------------------------------------------------
# LEGACY: Markdown -> JSON. Backfill only. See the module docstring.
# ---------------------------------------------------------------------------


def build(model: Path, root: Path) -> dict | None:
    """The contract artifact for one model, or None if it cannot be made.

    `subject_id` is deliberately NOT written. Identity belongs to the
    binding (`artifact_binding.subject_id`, minted from the corpus
    repo_key at ingest); a second answer carried inside the document can
    only agree or disagree, and disagreeing is worse than being absent.
    """
    parsed = parse_threats(model, root)
    if not parsed:
        return None
    block = provenance(model)
    if block is None:
        return None
    threats = []
    for threat in parsed["threats"]:
        row = {field: threat[field] for field in THREAT_FIELDS if field in threat}
        row["actor"] = threat["actors"]
        threats.append(row)
    # The register's `product` -- the directory grouping a subject's
    # models -- so the projection's `product` column keeps the meaning it
    # has always had in the threat dashboards.
    return {
        "system": parsed["threats"][0]["product"],
        "provenance": block,
        "threats": threats,
    }


def emit(
    model: Path, root: Path, *, write: bool = True
) -> tuple[Path | None, list[str]]:
    """Derive and write the artifact. Returns (path_written, reasons).

    `reasons` is empty on success. A non-empty `reasons` with a None
    path means this model cannot be back-derived: its prose predates the
    schema and does not carry what the contract needs. Not an edit to
    make -- the Markdown is an output format, so a hand correction is
    overwritten by the next emission, and reading intent into
    `status: open` is re-modelling. Such a model has no artifact until
    /threat-model next authors one.
    """
    document = build(model, root)
    if document is None:
        if parse_threats(model, root) is None:
            return None, ["no parseable threats table (section 4)"]
        return None, ["section 7 provenance missing mode/date/target"]
    errors = sorted(validator().iter_errors(document), key=lambda e: e.json_path)
    if errors:
        return None, [f"{e.json_path}: {e.message}" for e in errors]
    target = artifact_path(model)
    if write:
        target.write_text(
            json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    return target, []


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
            f"  NO ARTIFACT           {tally['rejected']} — these models"
            " predate the schema. RE-MODEL them; do not edit the prose,"
            " which is an output format now.",
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


if __name__ == "__main__":
    raise SystemExit(main())
