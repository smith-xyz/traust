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
