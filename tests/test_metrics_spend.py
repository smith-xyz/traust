"""`traust metrics collect-spend --append` / `attribute-spend --reconcile` on traust-core, and
the transcript reader they share; pricing, attribution and views are core's tests."""

from __future__ import annotations

import contextlib
import io
import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_core.v1.models.common import TimeWindow
from traust_core.v1.models.operations import (
    SpendBreakdown,
    SpendDimension,
    SpendFilter,
    SpendRollup,
)

from tests.test_products_doors import _postgres
from traust.cli.groups import metrics

REGISTRY = Path(__file__).resolve().parents[1] / "config" / "model-registry.yaml"
DAY1, DAY2 = "2026-10-05", "2026-10-06"


def record(ts: str, model: str = "claude-haiku-5-5", **usage: int) -> dict[str, Any]:
    tokens = {"input_tokens": 1000, "output_tokens": 100, **usage}
    return {"timestamp": f"{ts}T10:00:00.000Z", "message": {"model": model, "usage": tokens}}


def skill_call(name: str) -> dict[str, Any]:
    block = {"type": "tool_use", "name": "Skill", "input": {"skill": name}}
    return {"timestamp": f"{DAY1}T09:00:00Z", "message": {"content": [block]}}


def transcripts(tmp_path: Path) -> list[Path]:
    """One session that runs `triage` midway, with a synthetic message and a torn line."""
    project = tmp_path / "projects" / "-w-workspace"
    project.mkdir(parents=True)
    lines = [
        json.dumps(record(DAY1)),
        json.dumps(skill_call("triage")),
        json.dumps(record(DAY1, cache_read_input_tokens=50)),
        json.dumps(record(DAY1, model="<synthetic>")),
        '{"usage": torn',
        json.dumps(record(DAY2)),
    ]
    (project / "session.jsonl").write_text("\n".join(lines) + "\n")
    return [project]


def test_the_reader_attributes_each_request_to_the_skill_running_then(tmp_path: Path) -> None:
    usages = list(metrics.session_usages(transcripts(tmp_path), {"triage"}))
    assert [(u.occurred_at.date().isoformat(), u.skill, u.cache_read) for u in usages] == [
        (DAY1, None, 0),
        (DAY1, "triage", 50),
        (DAY2, "triage", 0),
    ]
    assert {(u.provider, u.model, u.tokens_in, u.tokens_out) for u in usages} == {
        ("anthropic", "claude-haiku-5-5", 1000, 100)
    }


def test_the_reader_only_takes_skills_that_exist(tmp_path: Path) -> None:
    assert {u.skill for u in metrics.session_usages(transcripts(tmp_path), set())} == {None}


class Spend:
    def __init__(self, recorded: int = 3, lossless: bool = True) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.recorded, self.lossless = recorded, lossless

    def collect(self, source: Any, window: TimeWindow) -> int:
        self.calls.append((source, window))
        return self.recorded

    def attribute_by(self, filter: SpendFilter, by: SpendDimension) -> SpendBreakdown:
        self.calls.append((filter, by))
        part = SpendRollup(events=1, tokens_in=1, tokens_out=1, cost_usd=Decimal(1))
        total = SpendRollup(
            events=2 if self.lossless else 3, tokens_in=2, tokens_out=2, cost_usd=Decimal(2)
        )
        return SpendBreakdown(filter=filter, by=by, rows=(part,), unattributed=part, total=total)


@pytest.fixture
def spend(monkeypatch: pytest.MonkeyPatch) -> Spend:
    door = Spend()
    core = SimpleNamespace(services=lambda: SimpleNamespace(spend=door))
    monkeypatch.setattr(metrics, "load_spend_core", lambda home: core)
    monkeypatch.setattr("traust_engine.metrics.attribute_spend.known_skills", lambda _: {"triage"})
    return door


def engine(monkeypatch: pytest.MonkeyPatch, dirs: list[Path]) -> None:
    fake = SimpleNamespace(
        metrics=SimpleNamespace(
            workspace=lambda: Path("/w/workspace"), session_project_dirs=lambda ws: dirs
        )
    )
    monkeypatch.setattr(metrics, "load_engine", lambda home: fake)


def args(**kw: Any) -> Any:
    values = {"config_home": None, "workspace": None, "date": None, "month": None, "json": False}
    return SimpleNamespace(**{**values, **kw})


def call(fn: Any, *a: Any) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = fn(*a)
    return rc, out.getvalue()


def test_append_collects_every_transcript_day_into_core(
    spend: Spend, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine(monkeypatch, transcripts(tmp_path))
    rc, out = call(metrics.call_collect_spend, args(append=True))
    assert (rc, out.strip()) == (0, "recorded 3 day×model×skill spend event(s)")
    [(source, window)] = spend.calls
    assert [u.skill for u in source.usages] == [None, "triage", "triage"]
    assert window.start == datetime(2026, 10, 5, tzinfo=UTC)
    assert window.end > datetime.now(UTC) - timedelta(minutes=1)


def test_append_of_no_usage_records_nothing(
    spend: Spend, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    engine(monkeypatch, [empty])
    rc, out = call(metrics.call_collect_spend, args(append=True))
    assert (rc, spend.calls) == (0, []) and "recorded 0" in out


@pytest.mark.parametrize(
    ("kw", "window"),
    [
        ({"month": "2026-09"}, TimeWindow.month_of(datetime(2026, 9, 1, tzinfo=UTC))),
        (
            {"date": "2026-09-14"},
            TimeWindow(
                start=datetime(2026, 9, 14, tzinfo=UTC), end=datetime(2026, 9, 15, tzinfo=UTC)
            ),
        ),
    ],
)
def test_reconcile_splits_the_period_by_skill(
    spend: Spend, kw: dict[str, str], window: TimeWindow
) -> None:
    rc, out = call(metrics.call_attribute_spend, args(reconcile=True, **kw))
    assert rc == 0 and "lossless: True" in out
    assert spend.calls == [(SpendFilter(window=window), SpendDimension.SKILL)]


def test_reconcile_exits_1_when_the_split_is_not_lossless(spend: Spend) -> None:
    spend.lossless = False
    rc, out = call(metrics.call_attribute_spend, args(reconcile=True, json=True))
    assert rc == 1 and json.loads(out)["lossless"] is False


def test_the_legacy_spend_dashboard_says_what_it_no_longer_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    built = SimpleNamespace(build_spend_dashboard=lambda **kw: Path("spend-dashboard.md"))
    fake = SimpleNamespace(metrics=built, ctx=SimpleNamespace(budget_policy=None))
    monkeypatch.setattr(metrics, "load_engine", lambda home: fake)
    err = io.StringIO()
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
        rc = metrics.call_spend(SimpleNamespace(config_home=None, out_dir=None, budget=None))
    assert rc == 0 and "traust dashboard view spend" in err.getvalue()


@pytest.mark.parametrize("database", ["sqlite", "postgres"])
def test_capture_on_core_is_idempotent_and_reconciles(
    tmp_path: Path, database: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("traust_engine.metrics.attribute_spend.known_skills", lambda _: {"triage"})
    config = tmp_path / "config"
    config.mkdir()
    (config / "model-registry.yaml").write_text(REGISTRY.read_text())
    core: dict[str, Any] = {"home": str(tmp_path / "store")}
    engine(monkeypatch, transcripts(tmp_path))
    with contextlib.ExitStack() as stack:
        if database == "postgres":
            core["database"] = {"url": stack.enter_context(_postgres())}
        (config / "core.yaml").write_text(yaml.safe_dump(core))
        append = args(append=True, config_home=config)
        assert call(metrics.call_collect_spend, append)[1].startswith("recorded 3")
        assert call(metrics.call_collect_spend, append)[1].startswith("recorded 0")
        reconciled = args(reconcile=True, config_home=config, month="2026-10", json=True)
        rc, out = call(metrics.call_attribute_spend, reconciled)
    answer = json.loads(out)
    assert rc == 0 and answer["lossless"] is True
    assert answer["total"]["events"] == 3 and answer["unattributed"]["events"] == 1
    # three requests priced at the registry's claude-haiku-5-5 list rates, one with cache reads
    assert Decimal(answer["total"]["cost_usd"]) == Decimal("0.0004505")


def test_capture_without_a_model_registry_is_exit_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "config"
    config.mkdir()
    (config / "core.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    err = io.StringIO()
    with pytest.raises(SystemExit) as exit, contextlib.redirect_stderr(err):
        engine(monkeypatch, transcripts(tmp_path))
        metrics.call_collect_spend(args(append=True, config_home=config))
    assert exit.value.code == 2 and "spend not resolvable" in err.getvalue()
