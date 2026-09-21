"""The contract artifact for one threat model, derived from its Markdown.

A threat model is authored as prose, because people write and edit it.
Its structure has always been a contract -- sections, table columns and
enums -- and `threat-model.schema.json` is that contract made
machine-readable. So the model has two forms and they are not
alternatives:

    <repo>-threat-model.md      authored, human-edited, canonical prose
    <repo>-threat-model.json    the contract artifact, projected into
                                storage and read by every consumer

This module owns the derivation, and is the ONLY implementation of it.
`/threat-model` calls it on every emission through
`traust reporting threat-model-json`; the one-shot backfill in
`traust.migrations.emit_threat_model_json` calls the same functions over
a whole tree. A second copy of the column list is exactly what having a
schema was meant to end.

THE SCHEMA IS THE AUTHORITY. A model whose prose does not satisfy it
gets no artifact: an invalid file on disk claims to be a contract
artifact and is not, and the ingest would refuse it anyway. Nothing here
is defaulted or inferred -- provenance is read from section 7, and a
model that does not state it is reported rather than given a date nobody
recorded.
"""

from __future__ import annotations

import json
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

    `reasons` is empty on success. A non-empty `reasons` with a None path
    is a model that must be fixed in the Markdown -- never worked around
    here, and never written in a degraded form.
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
