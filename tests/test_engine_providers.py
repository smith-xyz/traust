"""`load_engine_core`: traust-core gets traust-engine's providers for its protocols, so the doors
behind them run instead of raising their NEED(engine) ConfigError."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml
from traust_core.v1.errors import ConfigError

from traust.context import load_core, load_engine_core

FIXTURE_CONFIG = Path(__file__).parent / "fixtures" / "config"


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    config = tmp_path / "config"
    shutil.copytree(FIXTURE_CONFIG, config)
    (config / "core.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    return config


def test_every_engine_provider_is_wired(home: Path) -> None:
    core = load_engine_core(home)
    assert core.adr_source is not None and core.doc_source is not None
    assert core.rule_packs is not None and core.canaries is not None
    assert core.fleet_fix_applier is not None and core.fleet_fix_goldens is not None


def test_services_read_the_rule_packs_through_the_engine(home: Path) -> None:
    packs = load_engine_core(home).services().detection_quality.rule_packs()
    assert packs and packs[0].rules


def test_canary_sources_are_the_named_recall_benchmark_dir(home: Path) -> None:
    core = load_engine_core(home, canaries="seeded")
    assert not core.canaries.check().ready
    assert str(home / "recall-benchmark" / "seeded") in core.canaries.check().detail


def test_plain_core_still_raises_the_need(home: Path) -> None:
    with pytest.raises(ConfigError, match="NEED"):
        load_core(home).services().detection_quality.rule_packs()


def test_the_scanner_tools_and_their_inspector_are_wired(home: Path) -> None:
    core = load_engine_core(home)
    assert set(core.tools.names()) >= {
        "checkov",
        "gitleaks",
        "gitleaks-history",
        "govulncheck",
        "grype",
        "opengrep",
        "osv",
        "yara",
    }
    assert core.tool_inspector is not None
    assert core.tool_floors.get("gitleaks")  # external-tools.yaml pins are the floors


def test_the_catalog_answers_readiness_for_every_registered_tool(home: Path) -> None:
    catalog = load_engine_core(home).services().catalog
    names = {b.capability.name for b in catalog.readiness(None)}
    assert {"gitleaks", "grype", "opengrep", "checkov"} <= names


def test_run_tools_reaches_an_engine_adapter_through_core(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from traust_contracts.models import AdapterResult
    from traust_core.v1.models.assessment import ToolName
    from traust_core.v1.providers.base import Readiness
    from traust_engine.adapters import grype
    from traust_engine.adapters._contract_bridge import build_scan_result
    from traust_engine.adapters.tools import AdapterTool

    monkeypatch.setattr(AdapterTool, "check", lambda self: Readiness(ready=True))
    monkeypatch.setattr(grype, "scan", lambda t, **_: build_scan_result(str(t), "grype", []))
    run = load_engine_core(home).services().assessment.run_tools(tmp_path, [ToolName("grype")])
    assert run.data("grype", AdapterResult).metadata.tool == "grype"


def test_plain_core_registers_no_engine_tools(home: Path) -> None:
    assert load_core(home).tools.names() == []
