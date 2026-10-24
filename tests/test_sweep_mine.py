"""`traust sweep mine`: the CLI layer only. The pack directory becomes a core `RulePack`, then one
`DetectionQualityService.mine_rules`; a refused input is exit 2. Mining itself is traust-core's."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.detection_quality import RuleMining, RulePack, RuleRef

from traust.cli.groups import sweep

RULES = {
    "rules": [
        {"id": "py-sqli", "languages": ["Python"], "metadata": {"cwe": "cwe-89"}},
        {"id": "go-cmd", "languages": ["go"], "metadata": {"cwe": ["CWE-78", "CWE-77"]}},
    ]
}
EXPECTED = RulePack(
    name="pack",
    version="",
    rules=(
        RuleRef(id="go-cmd", languages=("go",), cwes=("CWE-78", "CWE-77")),
        RuleRef(id="py-sqli", languages=("python",), cwes=("CWE-89",)),
    ),
)


@pytest.fixture
def pack(tmp_path: Path) -> Path:
    root = tmp_path / "pack"
    for name, rule in (("go", RULES["rules"][1]), ("python", RULES["rules"][0])):
        (root / name).mkdir(parents=True)
        (root / name / "r.yaml").write_text(yaml.safe_dump({"rules": [rule]}))
    return root


class Door:
    def __init__(self, result: Any) -> None:
        self.calls: list[Any] = []
        self.result = result

    def __call__(self, pack: RulePack) -> Any:
        self.calls.append(pack)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@pytest.fixture
def mined(monkeypatch: pytest.MonkeyPatch) -> Door:
    door = Door(RuleMining(pack=EXPECTED))
    services = SimpleNamespace(detection_quality=SimpleNamespace(mine_rules=door))
    monkeypatch.setattr(Context, "services", lambda self: services)
    return door


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "core.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def call(home: Path, engine: Any, **args: Any) -> tuple[int, Any]:
    ns = SimpleNamespace(**{"config_home": home, "pack": None, "out": None, **args})
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = sweep.call_mine(engine, ns)
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


def bundled(directory: Path | Exception) -> Any:
    def rule_pack_dir() -> Path:
        if isinstance(directory, Exception):
            raise directory
        return directory

    return SimpleNamespace(adapters=SimpleNamespace(rule_pack_dir=rule_pack_dir))


def test_the_pack_dir_becomes_one_mine_rules_call(mined: Door, home: Path, pack: Path) -> None:
    rc, out = call(home, bundled(ValueError("unused")), pack=pack)
    assert rc == 0
    assert mined.calls == [EXPECTED]
    assert (out["pack"], out["pack_rules"], out["confirmed_tps"]) == (str(pack), 2, 0)
    assert out["uncovered"] == [] and "corpus" not in out


def test_without_a_pack_the_deployment_pack_is_used(mined: Door, home: Path, pack: Path) -> None:
    rc, out = call(home, bundled(pack))
    assert rc == 0 and out["pack"] == str(pack)


def test_out_also_writes_the_whole_mining(
    mined: Door, home: Path, pack: Path, tmp_path: Path
) -> None:
    target = tmp_path / "metrics" / "rule-mining.json"
    rc, _ = call(home, bundled(pack), out=target)
    assert rc == 0
    assert RuleMining.model_validate_json(target.read_text()) == RuleMining(pack=EXPECTED)


@pytest.mark.parametrize(
    "engine_pack", [ValueError("no opengrep rule pack configured"), Path("/nonexistent/pack")]
)
def test_no_usable_pack_is_exit_2(mined: Door, home: Path, engine_pack: Path | Exception) -> None:
    rc, err = call(home, bundled(engine_pack))
    assert rc == 2 and "ERROR:" in err
    assert mined.calls == []


def test_a_refusing_door_is_exit_2(mined: Door, home: Path, pack: Path) -> None:
    mined.result = ConfigError("no findings store")
    rc, err = call(home, bundled(pack), pack=pack)
    assert rc == 2 and "no findings store" in err
