"""The shadow run on the security pack: `traust-engine record` around a real traust door, and
`traust-engine shadow` routing with traust.ops.router (docs/continuous-operations.md)."""

from __future__ import annotations

import contextlib
import io
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.models.common import every_item
from traust_core.v1.models.operations import OrderFilter, OrderState, RunOrder
from traust_engine.ops import cli
from traust_engine.ops.shadow import Tick

from tests.test_security_router_engine import _audited, forge  # noqa: F401  (fixture)

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "packs" / "security" / "assets.yaml"
PINS = ("--pin", str(ROOT / "config" / "external-tools.yaml"))
ROUTER = ("--router", "traust.ops.router:SecurityRouter")


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "core.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def _engine(home: Path, op: str, *argv: str) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = cli.main([op, "--core", str(home / "core.yaml"), "--pack", str(PACK), *PINS, *argv])
    return rc, out.getvalue()


def _orders(home: Path) -> list[RunOrder]:
    ops = Context.from_file(home / "core.yaml").services().ops
    return list(every_item(lambda p: ops.list(OrderFilter(states=tuple(OrderState)), p)))


def test_a_traust_door_is_recorded_as_it_answered(home: Path) -> None:
    audit = [sys.executable, "-m", "traust.cli", "ledger", "audit", "--config-home", str(home)]
    rc, _ = _engine(home, "record", "ledger_audit", "--", *audit)
    (order,) = _orders(home)
    assert (rc, order.asset, order.state) == (5, "ledger_audit", OrderState.REFUSED)
    assert order.reason and "no ledger configured" in order.reason


def test_shadow_routes_a_recorded_repo_state_with_the_security_router(
    home: Path,
    forge: dict[str, Any],  # noqa: F811
) -> None:
    context = Context.from_file(home / "core.yaml")
    repository_id = _audited(context, "app")
    with context.repository_observation() as observation:
        observation.service.record_forge_facts(repository_id=repository_id)
    url = "https://github.com/org/app"
    _engine(home, "record", "repo_state", "--repo", url, "--", sys.executable, "-c", "pass")

    rc, line = _engine(home, "shadow", *ROUTER, "--once")
    tick = Tick.model_validate_json(line)
    (routed,) = [d for d in tick.due if d.lane]
    assert rc == 0
    assert (routed.asset, routed.repository_id, routed.lane, routed.rule) == (
        "diff_scan_quarterly",
        repository_id,
        "diff-scan-quarterly",
        "rule-5",
    )
    assert "repo_state" not in {d.asset for d in tick.due}  # the recorded run counts
    assert [o.asset for o in _orders(home)] == ["repo_state"]  # the shadow planned nothing
