"""The threat-model backfill must never invent a fact.

The first cut of this migration defaulted `provenance` to
`{mode: bootstrap, date: 2026-01-01}` on all 7,660 models and wrote a
`subject_id` that was a directory path rather than the corpus repo_key
the binding carries. Both are false facts in contract fields, and both
would have been written into 7,482 artifacts.
"""

from __future__ import annotations

import json
from pathlib import Path

from traust.lib.threat_model_artifact import build, emit, provenance
from traust.migrations.emit_threat_model_json import main

MODEL = """# Threat model

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|----|--------|-------|---------|-------|--------|------------|--------|----------|----------|
| T1 | Token theft via log leak | remote_auth | api | tokens | high | likely | unmitigated | none | FIND-001 |

## 7. Provenance

- mode: interview
- date: 2026-03-04
- target: https://github.com/org/repo @ deadbee
- owner: a service owner
"""


def _model(root: Path, text: str = MODEL) -> Path:
    d = root / "findings" / "prodA" / "repo"
    d.mkdir(parents=True)
    path = d / "repo-threat-model.md"
    path.write_text(text, encoding="utf-8")
    return path


def test_provenance_is_read_not_defaulted(tmp_path):
    path = _model(tmp_path)
    assert provenance(path) == {
        "mode": "interview",
        "date": "2026-03-04",
        "target": "https://github.com/org/repo @ deadbee",
        "owner": "a service owner",
    }


def test_owner_unset_is_dropped_not_carried(tmp_path):
    """The schema says an unreviewed model must not look reviewed."""
    path = _model(tmp_path, MODEL.replace("- owner: a service owner", "- owner: unset"))
    assert "owner" not in provenance(path)


def test_model_without_required_provenance_yields_nothing(tmp_path):
    """117 live models are in this state. None may get a guessed date."""
    path = _model(tmp_path, MODEL.split("## 7. Provenance")[0] + "## 7. Provenance\n\n- owner: x\n")
    assert provenance(path) is None
    assert build(path, tmp_path) is None


def test_document_carries_no_subject_id(tmp_path):
    """Identity is the binding's. A second answer can only disagree."""
    path = _model(tmp_path)
    document = build(path, tmp_path)
    assert "subject_id" not in document
    assert document["provenance"]["mode"] == "interview"
    assert [t["id"] for t in document["threats"]] == ["T1"]
    assert document["threats"][0]["actor"] == ["remote_auth"]


def test_threats_carry_only_contract_fields(tmp_path):
    """`$defs/threat` is additionalProperties:false -- parser bookkeeping
    (`key`, `model`, `product`, `linddun`, `score`) would invalidate every
    artifact. The projection derives what it needs."""
    document = build(_model(tmp_path), tmp_path)
    assert not {"key", "model", "product", "linddun", "score"} & set(document["threats"][0])


def test_off_contract_model_is_reported_and_not_written(tmp_path, capsys):
    """61 live models fail the enums. An invalid artifact on disk claims to
    be a contract artifact and is not."""
    _model(tmp_path, MODEL.replace("| unmitigated |", "| open |"))
    report = tmp_path / "rejects.json"
    assert main([str(tmp_path), "--write", "--report", str(report)]) == 0
    assert not list(tmp_path.rglob("*-threat-model.json"))
    rejected = json.loads(report.read_text())["rejected"]
    assert len(rejected) == 1
    assert any("status" in r for r in rejected[0]["reasons"])


def test_conformant_model_is_written(tmp_path):
    _model(tmp_path)
    assert main([str(tmp_path), "--write"]) == 0
    out = tmp_path / "findings" / "prodA" / "repo" / "repo-threat-model.json"
    assert json.loads(out.read_text())["provenance"]["date"] == "2026-03-04"


# ---------------------------------------------------------------------------
# the skill's per-model path and the backfill share ONE implementation
# ---------------------------------------------------------------------------


def test_emit_writes_the_artifact_beside_the_model(tmp_path):
    model = _model(tmp_path)
    target, reasons = emit(model, tmp_path)
    assert reasons == []
    assert target == model.with_name("repo-threat-model.json")
    assert json.loads(target.read_text())["threats"][0]["id"] == "T1"


def test_emit_refuses_and_explains_rather_than_degrading(tmp_path):
    """No artifact is better than one the ingest would refuse."""
    model = _model(tmp_path, MODEL.replace("| unmitigated |", "| open |"))
    target, reasons = emit(model, tmp_path)
    assert target is None
    assert not model.with_suffix(".json").exists()
    assert any("status" in r for r in reasons)


def test_check_mode_writes_nothing(tmp_path):
    model = _model(tmp_path)
    target, reasons = emit(model, tmp_path, write=False)
    assert reasons == [] and target is not None
    assert not target.exists()


def test_the_forward_direction_lives_in_the_engine_not_here(tmp_path):
    """This module is the LEGACY md -> json backfill and nothing else.

    New models are authored as JSON and rendered by
    `reporting validate` + `reporting render`. A renderer here would be a
    second implementation of the direction that matters.
    """
    from traust.lib import threat_model_artifact as lib

    assert not hasattr(lib, "render"), "rendering belongs to traust_engine.reporting.render"
    assert not hasattr(lib, "write")
    from traust_engine.reporting import render

    assert hasattr(render, "render_threat_model")
