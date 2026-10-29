"""`traust reporting validate|lint|render|sarif`: the CLI layer over core's `ctx.reporting`."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from tests.test_render_section_guard import FULL
from tests.test_validate_report import _valid_report
from tests.test_validate_triage import _valid_triage
from traust.cli.__main__ import main as cli

CLOUD = Path(__file__).parent / "fixtures" / "cloud_config" / "myrepo-cloud-config-audit.json"


def _write(path: Path, document: object) -> Path:
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_validate_reads_the_schema_from_the_file_name(tmp_path, capsys):
    _write(tmp_path / "widget-security-audit.json", _valid_report())
    _write(tmp_path / "widget-threat-model.json", {"system": "no provenance"})
    assert cli(["reporting", "validate", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "Validating 2 report(s)" in out
    assert "  PASS  widget-security-audit.json" in out
    assert "  FAIL  widget-threat-model.json" in out
    assert "Result: 1 FAILED" in out


@pytest.mark.parametrize("schema", ["triage.schema.json", "contracts/triage.schema.json", "triage"])
def test_validate_maps_a_schema_file_name_to_its_contract_schema(tmp_path, capsys, schema):
    report = _write(tmp_path / "widget-security-audit.json", _valid_report())
    assert cli(["reporting", "validate", str(report), "--schema", schema]) == 1
    assert "  FAIL  widget-security-audit.json" in capsys.readouterr().out


def test_validate_refuses_a_schema_the_contracts_do_not_have(tmp_path, capsys):
    report = _write(tmp_path / "widget-security-audit.json", _valid_report())
    assert cli(["reporting", "validate", str(report), "--schema", "nope.schema.json"]) == 2
    assert "nope" in capsys.readouterr().err


def test_validate_with_nothing_to_validate(tmp_path, capsys):
    assert cli(["reporting", "validate", str(tmp_path)]) == 1
    assert f"No .json files found in {tmp_path}" in capsys.readouterr().out
    assert cli(["reporting", "validate", str(tmp_path / "missing.json")]) == 1
    assert "Path not found" in capsys.readouterr().out


def test_canonical_write_requires_an_explicit_contract(tmp_path):
    path = _write(tmp_path / "repo-triage.json", _valid_triage())
    assert cli(["reporting", "validate", str(path), "--canonical-write"]) == 2


def test_canonical_write_fails_closed_without_a_shared_gate(tmp_path):
    path = _write(tmp_path / "repo-triage.json", _valid_triage())
    assert (
        cli(["reporting", "validate", str(path), "--schema", "triage-missing", "--canonical-write"])
        == 2
    )


def _canonical_triage():
    report = _valid_triage()
    report["findings"][0]["kind"] = "vulnerability"
    report["findings"][1].update(verdict="true_positive", kind="weakness", verify_verdict=None)
    return report


def test_final_canonical_gate_accepts_disjoint_weakness_and_vulnerability_totals(tmp_path):
    path = _write(tmp_path / "repo-triage.json", _canonical_triage())
    assert cli(["reporting", "validate", str(path), "--schema", "triage", "--canonical-write"]) == 0


def test_historical_triage_remains_readable_without_new_output_gate(tmp_path):
    report = _valid_triage()
    path = _write(tmp_path / "repo-triage.json", report)
    assert cli(["reporting", "validate", str(path)]) == 0
    assert cli(["reporting", "validate", str(path), "--schema", "triage", "--canonical-write"]) == 1
    assert json.loads(path.read_text()) == report


@pytest.mark.parametrize(
    "change",
    [
        {"severity": "high"},
        {"kind": "vulnerability"},
        {"exclusion_rule": None},
        {"claimed_severity": "MEDIUM"},
    ],
)
def test_final_canonical_gate_rejects_contradictory_serialized_weakness(tmp_path, change):
    report = _canonical_triage()
    report["findings"][1].update(change)
    path = _write(tmp_path / "repo-triage.json", report)
    assert cli(["reporting", "validate", str(path), "--schema", "triage", "--canonical-write"]) == 1


def test_canonical_weakness_is_not_counted_again_as_a_vulnerability(tmp_path):
    report = _canonical_triage()
    report["summary"]["true_positives"] += 1
    path = _write(tmp_path / "repo-triage.json", report)
    assert cli(["reporting", "validate", str(path), "--schema", "triage", "--canonical-write"]) == 1


def test_lint_reports_each_threat_model(tmp_path, capsys):
    md = tmp_path / "repo-threat-model.md"
    assert cli(["reporting", "render", str(_write(tmp_path / "repo-threat-model.json", FULL))]) == 0
    md.write_text(capsys.readouterr().out, encoding="utf-8")
    (tmp_path / "THREAT_MODEL.md").write_text("# not a threat model\n", encoding="utf-8")
    assert cli(["reporting", "lint", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert f"{tmp_path / 'THREAT_MODEL.md'}:\n  ERROR: " in out
    assert "2 file(s)" in out and "Result: 1 FAILED" in out


def test_lint_with_no_threat_models(tmp_path, capsys):
    assert cli(["reporting", "lint", str(tmp_path)]) == 1
    assert "no THREAT_MODEL.md files found" in capsys.readouterr().err


def test_render_refuses_a_schema_invalid_document(tmp_path, capsys):
    src = _write(tmp_path / "repo-threat-model.json", {"system": "no provenance"})
    out = tmp_path / "repo-threat-model.md"
    assert cli(["reporting", "render", str(src), "-o", str(out)]) == 2
    assert "threat-model" in capsys.readouterr().err
    assert not out.exists()


def test_render_writes_a_security_report(tmp_path, capsys):
    src = _write(tmp_path / "widget-security-audit.json", _valid_report())
    out = tmp_path / "widget.md"
    assert cli(["reporting", "render", str(src), "-o", str(out)]) == 0
    assert out.read_text(encoding="utf-8").startswith("# Security Assessment — Test Widget")


def test_sarif_exports_reports_and_cloud_config_audits(tmp_path, capsys):
    report = _write(tmp_path / "widget-security-audit.json", _valid_report())
    cloud = shutil.copy(CLOUD, tmp_path / CLOUD.name)
    assert cli(["reporting", "sarif", str(report), str(cloud)]) == 0
    code = json.loads((tmp_path / "widget-security-audit.sarif").read_text())
    declared = json.loads((tmp_path / "myrepo-cloud-config-audit.sarif").read_text())
    assert code["runs"][0]["properties"]["traust/report_title"] == _valid_report()["title"]
    assert "declared" in json.dumps(declared["runs"][0]["properties"]).lower()


def test_sarif_refuses_a_schema_invalid_report(tmp_path, capsys):
    report = _write(tmp_path / "widget-security-audit.json", {"findings": []})
    assert cli(["reporting", "sarif", str(report)]) == 1
    assert f"ERROR: {report}:" in capsys.readouterr().err
    assert not (tmp_path / "widget-security-audit.sarif").exists()


def test_sarif_sweeps_a_results_root(tmp_path, capsys):
    results = tmp_path / "results" / "widget"
    results.mkdir(parents=True)
    _write(results / "widget-security-audit.json", _valid_report())
    out_dir = tmp_path / "sarif"
    assert (
        cli(
            [
                "reporting",
                "sarif",
                "--results-root",
                str(tmp_path / "results"),
                "--out-dir",
                str(out_dir),
            ]
        )
        == 0
    )
    assert (out_dir / "widget" / "widget-security-audit.sarif").is_file()
