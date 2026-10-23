"""`traust triage intake|prepare|record|render` end to end on traust-core, in-process on SQLite."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from traust.cli import triage
from traust.paths import skill_dir

CANARY = skill_dir("triage") / "fixtures" / "canary-target"
SHA = "a" * 40
SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "CodeQL",
                    "version": "2.20.0",
                    "rules": [
                        {
                            "id": "c/overflow",
                            "shortDescription": {"text": "Unbounded copy into a heap buffer"},
                            "properties": {"security-severity": "8.1"},
                        },
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "c/overflow",
                    "ruleIndex": 0,
                    "message": {"text": "memcpy of claimed bytes"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "entry.c"},
                                "region": {"startLine": 25},
                            }
                        }
                    ],
                },
            ],
        }
    ],
}


@pytest.fixture
def home(tmp_path: Path) -> Path:
    """A config home whose core.yaml keeps the store in the test's directory."""
    config = tmp_path / "config"
    config.mkdir()
    (config / "core.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def run(door: Any, home: Path, *argv: str) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = door(["--config-home", str(home), *argv])
    return rc, out.getvalue()


def intake(home: Path, tmp_path: Path) -> str:
    scan = tmp_path / "scan.sarif"
    scan.write_text(json.dumps(SARIF))
    rc, out = run(
        triage.intake,
        home,
        str(scan),
        "--format",
        "sarif",
        "--repo-url",
        "https://github.com/example/canary",
        "--sha",
        SHA,
        "--origin",
        "vuln-scan",
    )
    assert rc == 0, out
    got = json.loads(out)
    assert (got["findings"], got["new"]) == (1, 1)
    return got["assessment_id"]


def test_scanner_output_triaged_and_recorded(home: Path, tmp_path: Path) -> None:
    assessment = intake(home, tmp_path)

    rc, out = run(triage.prepare, home, assessment)
    assert rc == 0, out
    prepared = json.loads(out)
    assert prepared["subject"]["sha"] == SHA
    [item] = prepared["items"]
    assert item["occurrence"]["severity"] == "high"
    assert item["locations"][0]["path"] == "entry.c"

    finding = item["finding"]
    report = {
        "triage_completed": "2026-10-23",
        "triage_context": {
            "mode": "auto",
            "environment": "Multi-tenant platform",
            "votes_per_finding": 3,
            "repo": str(CANARY),
            "harness_version": "0.34.2-abc1234",
        },
        "summary": {
            "input_count": 1,
            "true_positives": 1,
            "hardening": 0,
            "false_positives": 0,
            "undetermined": 0,
            "duplicates": 0,
            "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "informational": 0},
        },
        "findings": [
            {
                "id": "f001",
                "title": finding["title"],
                "verdict": "true_positive",
                "severity": "high",
                "file": "entry.c",
                "line": 25,
                "rationale": "reachable from main at entry.c:53",
                "fingerprint": finding["fingerprint"],
                "fingerprint_algo": finding["fingerprint_algo"],
            }
        ],
    }
    path = tmp_path / "canary-triage.json"
    path.write_text(json.dumps(report))

    rc, out = run(triage.record, home, assessment, str(path), "--repo", str(CANARY))
    assert rc == 0, out
    assert json.loads(out) == {"decisions": 1, "awaiting_countersign": 0, "auto_accepted": 0}

    rc, out = run(triage.render, home, str(path))
    assert rc == 0 and "## Act on these" in out and "(f001)" in out
    assert not (Path.cwd() / "artifacts").exists(), "artifacts belong under the core home"


def test_a_triage_not_matching_the_assessment_is_refused(
    home: Path, tmp_path: Path, capsys: Any
) -> None:
    assessment = intake(home, tmp_path)
    report = json.loads((skill_dir("triage") / "fixtures" / "canary-findings.json").read_text())
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(report))
    rc, _ = run(triage.record, home, assessment, str(path), "--repo", str(CANARY))
    assert rc == 2
    assert "ERROR" in capsys.readouterr().err


def test_an_unknown_assessment_is_an_error(home: Path) -> None:
    rc, _ = run(triage.prepare, home, "00000000-0000-0000-0000-000000000000")
    assert rc == 2
