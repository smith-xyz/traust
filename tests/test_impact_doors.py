"""`traust impact find|sbom|symbols|analyze` end to end on traust-core, in-process on SQLite."""

from __future__ import annotations

import contextlib
import io
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from traust_core.v1.models.dependencies import (
    AdvisoryIdentifier,
    AdvisoryRecord,
    AffectedPackage,
    AffectedSpan,
    Version,
)
from traust_core.v1.models.vocabulary import Ecosystem
from traust_core.v1.providers.base import Acquisition, Result

from traust.cli import check_fix_propagation, impact
from traust.context import load_core

SHA = "a" * 40
REPO = "https://github.com/org/app"
LODASH = AdvisoryRecord(
    identifier=AdvisoryIdentifier("GHSA-35jh-r3h4-6jhm"),
    affected=(
        AffectedPackage(
            ecosystem=Ecosystem.NPM,
            name="lodash",
            spans=(AffectedSpan(introduced=Version("0"), fixed=Version("4.17.21")),),
        ),
    ),
    declared_severity="HIGH",
    source="https://api.osv.dev/v1/vulns/GHSA-35jh-r3h4-6jhm",
)


class Lookup:
    name = "osv"

    def record(self, identifier: AdvisoryIdentifier) -> Result[AdvisoryRecord | None]:
        found = LODASH if identifier == LODASH.identifier else None
        return Result(found, Acquisition(provider="osv", acquired_at=datetime.now(UTC)))


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "core.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))

    def core(config_home: Path | None) -> Any:
        made = load_core(config_home)
        made.advisories = Lookup()
        return made

    monkeypatch.setattr(impact, "_core", core)
    return config


def run(door: Any, home: Path, *argv: str) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = door(["--config-home", str(home), *argv])
    return rc, out.getvalue()


def sbom(tmp_path: Path, version: str) -> Path:
    path = tmp_path / f"sbom-{version}.json"
    components = [{"purl": f"pkg:npm/lodash@{version}"}]
    path.write_text(json.dumps({"bomFormat": "CycloneDX", "components": components}))
    return path


def test_find_prints_the_advisory_from_its_source(home: Path) -> None:
    rc, out = run(impact.find, home, LODASH.identifier)
    assert rc == 0
    found = json.loads(out)
    assert (found["identifier"], found["affected"][0]["name"]) == (LODASH.identifier, "lodash")
    assert found["advisory_id"]


def test_an_advisory_its_source_doesnt_know_is_not_assessed(
    home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(impact.analyze, home, "CVE-2099-0001")[0] == 2
    assert "not assessed" in capsys.readouterr().err
    assert run(impact.find, home, "../etc")[0] == 2


def test_analyze_records_every_commit_the_sboms_reach(home: Path, tmp_path: Path) -> None:
    rc, out = run(
        impact.sbom, home, str(sbom(tmp_path, "4.17.20")), "--repo-url", REPO, "--sha", SHA
    )
    assert rc == 0 and json.loads(out)["sbom_id"]
    other = "https://github.com/org/web"
    run(impact.sbom, home, str(sbom(tmp_path, "4.17.21")), "--repo-url", other, "--sha", "b" * 40)
    rc, out = run(impact.analyze, home, LODASH.identifier)
    assert rc == 0
    summary = json.loads(out)
    assert summary["commits"] == 2
    assert summary["classifications"] == {"likely_affected": 1, "version_not_in_range": 1}
    assert summary["affected"] == []
    assert json.loads(run(impact.analyze, home, LODASH.identifier)[1]) == summary


def test_scan_clones_an_undecided_commit_at_its_sha(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run(impact.sbom, home, str(sbom(tmp_path, "4.17.20")), "--repo-url", REPO, "--sha", SHA)
    cloned: list[tuple[str, str]] = []

    def clone(url: str, sha: str, dest: Path) -> Path:
        cloned.append((url, sha))
        dest.mkdir(parents=True)
        (dest / "a.js").write_text("const _ = require('lodash')\n")
        return dest

    monkeypatch.setattr(impact, "clone", clone)
    rc, out = run(impact.analyze, home, LODASH.identifier, "--scan")
    assert rc == 0 and cloned == [(REPO, SHA)]
    assert json.loads(out)["classifications"] == {"likely_affected": 1}


def test_one_commit_by_url_and_sha(home: Path, tmp_path: Path) -> None:
    rc, out = run(impact.analyze, home, LODASH.identifier, "--repo-url", REPO, "--sha", SHA)
    assert rc == 0 and json.loads(out)["classifications"] == {"not_imported": 1}
    with pytest.raises(SystemExit):
        run(impact.analyze, home, LODASH.identifier, "--repo-url", REPO)


def test_symbols_says_why_when_unresolved(home: Path) -> None:
    rc, out = run(impact.symbols, home, LODASH.identifier)
    assert rc == 0 and json.loads(out)["status"] == "no_fix_commit"


def test_fix_propagation_reads_the_commits_sbom(home: Path, tmp_path: Path) -> None:
    args = ["--repo-url", REPO, "--sha", SHA, "--ecosystem", "npm", "--module", "lodash"]
    rc, out = run(check_fix_propagation.main, home, *args, "--fixed-version", "4.17.21")
    assert rc == 0 and json.loads(out)["propagation"] == "not_observed"
    rc, out = run(
        check_fix_propagation.main,
        home,
        *args,
        "--fixed-version",
        "4.17.21",
        "--sbom",
        str(sbom(tmp_path, "4.17.20")),
    )
    assert json.loads(out)["propagation"] == "pending"
    assert json.loads(out)["checked"] == [
        {"source": "manifest", "version": "4.17.20", "consumed": False}
    ]
