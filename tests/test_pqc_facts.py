"""pqc-readiness's `pqc_facts.py` on traust-core's crypto census, SQLite and Postgres; the pinned
pqc-scan binary is a fake, so only the census and its mapping run."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.test_products_doors import _postgres
from traust.paths import skill_dir

FIXTURES = Path(__file__).parent / "fixtures" / "crypto"
SBOM = FIXTURES / "manifest-sbom.cdx.json"
REPO = "https://github.com/org/app"
SHA = "a" * 40

_SPEC = importlib.util.spec_from_file_location(
    "pqc_facts", skill_dir("pqc-readiness") / "scripts" / "pqc_facts.py"
)
pqc_facts = importlib.util.module_from_spec(_SPEC)
sys.modules["pqc_facts"] = pqc_facts
_SPEC.loader.exec_module(pqc_facts)


@pytest.fixture(params=["sqlite", "postgres"])
def home(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Path]:
    config = tmp_path / "config"
    config.mkdir()
    core: dict[str, Any] = {"home": str(tmp_path / "store")}
    with contextlib.ExitStack() as stack:
        if request.param == "postgres":
            core["database"] = {"url": stack.enter_context(_postgres())}
        (config / "traust.yaml").write_text(yaml.safe_dump(core))
        yield config


@pytest.fixture
def scanner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    binary = tmp_path / "pqc-scan"
    binary.write_bytes(b"fake")
    report = {"summary": {"scanned_files": 19, "skipped_files": 0}, "findings": []}
    monkeypatch.setattr(pqc_facts, "run_scanner", lambda *_: report)
    return binary


def facts(monkeypatch: pytest.MonkeyPatch, home: Path, out: Path, *argv: str) -> dict:
    args = ["--config-home", str(home), "--repo-url", REPO, "--sha", SHA, "--out", str(out)]
    monkeypatch.setattr(sys, "argv", ["pqc_facts.py", *args, *argv])
    with contextlib.redirect_stdout(io.StringIO()):
        pqc_facts.main()
    return json.loads(out.read_text())


def test_source_mode_maps_the_checkout_and_its_sbom_packages(
    home: Path, scanner: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    doc = facts(
        monkeypatch,
        home,
        tmp_path / "facts.json",
        *("--repo-dir", str(FIXTURES / "repo"), "--sbom", str(SBOM), "--scanner", str(scanner)),
    )
    by_rule = {f["rule_id"]: f for f in doc["facts"]}
    assert doc["coverage"]["assessment_basis"] == "source"
    assert by_rule["HP_CHAIN_GO_TOOLCHAIN"]["file"] == "go.mod"
    assert by_rule["HP_CHAIN_GO_TOOLCHAIN"]["pqc_capable"] is True
    assert {"HP_CHAIN_PYTHON_CRYPTO_DEP", "HP_CHAIN_RUST_TLS_BACKEND"} <= by_rule.keys()
    assert "HP_SBOM_CRYPTO_COMPONENT" not in by_rule
    assert all(f["fips_mode"] for f in doc["facts"] if f["rule_id"].startswith("HP_CHAIN_"))


def test_source_mode_without_a_recorded_sbom_says_how_to_record_one(
    home: Path, scanner: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "facts.json"
    with pytest.raises(SystemExit, match=f"commit {SHA} has no manifest SBOM recorded"):
        facts(monkeypatch, home, out, "--repo-dir", str(FIXTURES / "repo"))
    assert not out.exists()


def test_sbom_mode_is_every_crypto_package_as_an_sbom_component(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    doc = facts(monkeypatch, home, tmp_path / "facts.json", "--from-sbom", str(SBOM))
    assert doc["coverage"]["assessment_basis"] == "sbom-only"
    assert doc["coverage"]["scanned_files"] is None
    assert {f["rule_id"] for f in doc["facts"]} == {"HP_SBOM_CRYPTO_COMPONENT"}
    details = {f["detail"] for f in doc["facts"]}
    assert {"cryptography==43.0.1", "golang.org/x/crypto v0.36.0"} <= details
    assert not any("flask" in d or "rails" in d for d in details)


def test_a_commit_is_required(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    argv = ["pqc_facts.py", "--from-sbom", str(SBOM), "--repo-url", REPO, "--out", "x.json"]
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit) as exit_, contextlib.redirect_stderr(io.StringIO()):
        pqc_facts.main()
    assert exit_.value.code == 2
