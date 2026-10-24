"""`traust dashboard view`: the CLI layer only. Scope flags become one `ViewFilter`, then one
`InsightService.publish`; `<stem>.{md,html,json}` land where asked. Views are core's tests."""

from __future__ import annotations

import contextlib
import io
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.errors import ValidationError
from traust_core.v1.models import insight
from traust_core.v1.models.common import TimeBucket, TimeWindow
from traust_core.v1.models.insight import FindingsTrend, RenderedView, ViewFilter, ViewName

from tests.test_products_doors import _postgres
from traust.cli import dashboard_view

ALPHA = SimpleNamespace(id=uuid.uuid4(), slug="alpha", name="Alpha")
TEAM = uuid.uuid4()
AS_OF = datetime(2026, 9, 30, tzinfo=UTC)
RENDERED = RenderedView(
    view=ViewName.FINDINGS_TREND,
    stem="findings-trend",
    model=FindingsTrend(as_of=AS_OF, repositories=2),
    markdown="# Findings trend\n",
    html="<!doctype html><title>Findings trend</title>",
)


class Door:
    def __init__(self, result: Any) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.result = result

    def __call__(self, *args: Any) -> Any:
        self.calls.append(args)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@pytest.fixture
def publish(monkeypatch: pytest.MonkeyPatch) -> Door:
    door = Door(RENDERED)
    services = SimpleNamespace(
        insight=SimpleNamespace(publish=door),
        portfolio=SimpleNamespace(find_product=lambda slug: {"alpha": ALPHA}.get(str(slug))),
    )
    monkeypatch.setattr(Context, "services", lambda self: services)
    return door


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "core.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def run(home: Path, *argv: str) -> tuple[int, Any]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = dashboard_view.main(["--config-home", str(home), *argv])
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


def test_no_scope_is_one_publish_and_three_files(publish: Door, home: Path, tmp_path: Path) -> None:
    out = tmp_path / "trends"
    rc, answer = run(home, "findings-trend", "--out", str(out))
    assert rc == 0
    assert publish.calls == [(ViewName.FINDINGS_TREND, ViewFilter())]
    assert sorted(p.name for p in out.iterdir()) == [
        "findings-trend.html",
        "findings-trend.json",
        "findings-trend.md",
    ]
    assert (out / "findings-trend.md").read_text() == RENDERED.markdown
    assert json.loads((out / "findings-trend.json").read_text())["repositories"] == 2
    assert answer["model"]["repositories"] == 2


def test_scope_window_and_bucket_go_into_one_filter(
    publish: Door, home: Path, tmp_path: Path
) -> None:
    since = datetime(2026, 1, 1, tzinfo=UTC)
    argv = ("--product", "alpha", "--product", "alpha", "--team-id", str(TEAM))
    rc, _ = run(
        home,
        "program",
        *argv,
        "--since",
        since.isoformat(),
        "--as-of",
        AS_OF.isoformat(),
        "--bucket",
        "week",
        "--out",
        str(tmp_path),
    )
    assert rc == 0
    assert publish.calls == [
        (
            ViewName.PROGRAM,
            ViewFilter(
                product_ids=(ALPHA.id,),
                team_ids=(TEAM,),
                as_of=AS_OF,
                window=TimeWindow(start=since, end=AS_OF),
                bucket=TimeBucket.WEEK,
            ),
        )
    ]


def test_until_closes_the_window(publish: Door, home: Path, tmp_path: Path) -> None:
    since, until = datetime(2026, 1, 1, tzinfo=UTC), datetime(2026, 4, 1, tzinfo=UTC)
    argv = ("--since", since.isoformat(), "--until", until.isoformat(), "--out", str(tmp_path))
    rc, _ = run(home, "program", *argv)
    assert rc == 0
    [(_, scope)] = publish.calls
    assert scope.window == TimeWindow(start=since, end=until) and scope.as_of is None


def test_executive_summary_as_of_writes_its_files(
    publish: Door, home: Path, tmp_path: Path
) -> None:
    publish.result = RenderedView(
        view=ViewName.EXECUTIVE_SUMMARY,
        stem="executive-summary-findings",
        model=insight.ExecutiveSummary(
            rollup=insight.FindingsRollup(as_of=AS_OF, total=insight.FindingTally()),
            privileges=insight.LeastPrivilege(
                profiles=0,
                privileged=0,
                scc_requesting=0,
                wildcard_repositories=0,
                wildcard_rules=0,
            ),
        ),
        markdown="# Executive summary: findings\n",
        html="<!doctype html><title>Executive summary: findings</title>",
    )
    out = tmp_path / "dashboards"
    rc, answer = run(home, "executive-summary", "--as-of", AS_OF.isoformat(), "--out", str(out))
    assert rc == 0
    assert publish.calls == [(ViewName.EXECUTIVE_SUMMARY, ViewFilter(as_of=AS_OF))]
    assert sorted(p.name for p in out.iterdir()) == [
        "executive-summary-findings.html",
        "executive-summary-findings.json",
        "executive-summary-findings.md",
    ]
    assert answer["model"]["exposure"] is None


@pytest.mark.parametrize(
    ("argv", "reason"),
    [
        (("--product", "gamma"), "product gamma is not registered"),
        (("--as-of", "2026-09-01T00:00:00"), "time zone"),
        (("--since", "2026-01-01"), "time zone"),
    ],
)
def test_a_refused_request_is_exit_2_and_writes_nothing(
    publish: Door, home: Path, tmp_path: Path, argv: tuple[str, ...], reason: str
) -> None:
    out = tmp_path / "out"
    rc, err = run(home, "findings-trend", *argv, "--out", str(out))
    assert rc == 2 and reason in err
    assert publish.calls == [] and not out.exists()


def test_a_door_refusal_is_exit_2(publish: Door, home: Path, tmp_path: Path) -> None:
    publish.result = ValidationError("the program view needs a window")
    rc, err = run(home, "program", "--out", str(tmp_path / "out"))
    assert rc == 2 and "needs a window" in err
    assert not (tmp_path / "out").exists()


def test_an_unknown_view_is_a_usage_error(publish: Door, home: Path, tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exit, contextlib.redirect_stderr(io.StringIO()):
        dashboard_view.main(["--config-home", str(home), "nope", "--out", str(tmp_path)])
    assert exit.value.code == 2 and publish.calls == []


@pytest.fixture
def policies(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """The SLA policy each `services()` call saw registered on its Context."""
    seen: list[Any] = []
    services = SimpleNamespace(insight=SimpleNamespace(publish=Door(RENDERED)))

    def build(self: Context) -> SimpleNamespace:
        seen.append(self.sla_policy)
        return services

    monkeypatch.setattr(Context, "services", build)
    return seen


SLA_TEMPLATE = Path(__file__).resolve().parents[1] / "config" / "sla-policy.example.yaml"


def test_the_config_homes_sla_policy_is_registered(
    policies: list[Any], home: Path, tmp_path: Path
) -> None:
    (home / "sla-policy.yaml").write_text(SLA_TEMPLATE.read_text())
    rc, _ = run(home, "sla", "--out", str(tmp_path / "sla"))
    assert rc == 0
    assert [p.policy_name for p in policies] == ["example-sla-policy"]


def test_sla_policy_flag_wins_and_no_policy_registers_none(
    policies: list[Any], home: Path, tmp_path: Path
) -> None:
    other = tmp_path / "other.yaml"
    other.write_text(SLA_TEMPLATE.read_text().replace("example-sla-policy", "fedramp"))
    assert run(home, "sla", "--sla-policy", str(other), "--out", str(tmp_path))[0] == 0
    assert run(home, "findings-trend", "--out", str(tmp_path))[0] == 0
    assert [p and p.policy_name for p in policies] == ["fedramp", None]


@pytest.mark.parametrize("policy", ["missing.yaml", "invalid.yaml"])
def test_an_unresolvable_sla_policy_is_exit_2_and_writes_nothing(
    policies: list[Any], home: Path, tmp_path: Path, policy: str
) -> None:
    (tmp_path / "invalid.yaml").write_text("policy_name: x\n")
    out = tmp_path / "out"
    with pytest.raises(SystemExit) as exit, contextlib.redirect_stderr(io.StringIO()) as err:
        argv = ["sla", "--sla-policy", str(tmp_path / policy), "--out", str(out)]
        dashboard_view.main(["--config-home", str(home), *argv])
    assert exit.value.code == 2 and "SLA policy not resolvable" in err.getvalue()
    assert policies == [] and not out.exists()


def test_threat_register_writes_its_files(publish: Door, home: Path, tmp_path: Path) -> None:
    publish.result = RenderedView(
        view=ViewName.THREAT_REGISTER,
        stem="threat-register",
        model=insight.ThreatRegister(as_of=AS_OF, repository_urls={}, models=0),
        markdown="# Threat register\n",
        html="<!doctype html><title>Threat register</title>",
    )
    out = tmp_path / "threat-register"
    argv = ("--product", "alpha", "--as-of", AS_OF.isoformat(), "--out", str(out))
    rc, answer = run(home, "threat-register", *argv)
    assert rc == 0
    assert publish.calls == [
        (ViewName.THREAT_REGISTER, ViewFilter(product_ids=(ALPHA.id,), as_of=AS_OF))
    ]
    assert sorted(p.name for p in out.iterdir()) == [
        "threat-register.html",
        "threat-register.json",
        "threat-register.md",
    ]
    assert (answer["model"]["models"], answer["model"]["threats"]) == (0, [])


@pytest.mark.parametrize("database", ["sqlite", "postgres"])
def test_threat_register_on_core_renders_an_empty_fleet(tmp_path: Path, database: str) -> None:
    config = tmp_path / "config"
    config.mkdir()
    core: dict[str, Any] = {"home": str(tmp_path / "store")}
    with contextlib.ExitStack() as stack:
        if database == "postgres":
            core["database"] = {"url": stack.enter_context(_postgres())}
        (config / "core.yaml").write_text(yaml.safe_dump(core))
        out = tmp_path / "out"
        rc, answer = run(config, "threat-register", "--out", str(out))
    assert rc == 0, answer
    assert answer["model"]["threats"] == [] and answer["model"]["quick_wins"] == []
    assert "_No threat models recorded._" in (out / "threat-register.md").read_text()
