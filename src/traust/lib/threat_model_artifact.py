"""The threat-model contract artifact, and the prose rendered from it.

`threat-model.schema.json` defines the model. The JSON is the artifact:
it is authored against the schema, validated against it, and projected
into storage. The Markdown is a RENDERING of that validated document, produced by
`traust reporting render` -- the same command, and the same
relationship, as every other artifact family.

    <repo>-threat-model.json    the artifact. Authored, validated, the
                                source of truth.
    <repo>-threat-model.md      rendered from it. Never the source.

Deriving the JSON from prose would make an unvalidated Markdown table
the thing everything downstream depends on, and every consumer would be
reading a re-parse of a re-parse. Rendering the other way means the
enums, the required fields and the column set are checked once, at the
point of authorship, and the prose cannot disagree with the artifact
because it is generated from it.

Everything in THIS module goes the wrong way, md -> json. It exists
for ONE reason: 7,660 models were authored as prose before the schema
existed, and a backfill can only read what is on disk. They are used by
`traust.migrations.emit_threat_model_json` and by nothing else. Do not
reach for them in new code.

THE SCHEMA IS THE AUTHORITY. A document that does not satisfy it yields
no files at all -- there is no degraded form to fall back to, and an
invalid artifact is one the ingest refuses anyway.
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
