"""The security pack's router in traust-engine's loop over real traust-core services on SQLite:
a `repo_state` completion routes the repository once, a lane over budget is withheld, a
forge host past its quota is deferred, and a threat-model PR stamp reaches the diff scan's
session."""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
import yaml
from traust_core.v1.context import Config, Context
from traust_core.v1.context.context import Services
from traust_core.v1.models.assessment import Assessment, AssessmentKind
from traust_core.v1.models.common import every_item
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.inventory import RepositoryRef
from traust_core.v1.models.operations import (
    Budget,
    JobResult,
    OrderFilter,
    OrderRequest,
    OrderState,
    RunOrder,
    WorkerId,
)
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import ActorKind, BudgetEnforcement, RefKind
from traust_core.v1.providers.process import ProcessResult, ProcessRunner
from traust_core.v1.repositories.contract import SqlTraustUnitOfWork
from traust_engine import EngineLoop, Pack
from traust_engine.ops.runner import Runner

from tests.test_session_run import ANCHOR, Processes
from traust.cli import session
from traust.ops.router import SecurityRouter

PACK = Path(__file__).resolve().parents[1] / "packs" / "security" / "assets.yaml"
T0 = datetime(2026, 10, 1, 6, tzinfo=UTC)
PINNED = "a" * 40
WORKER = WorkerId("runner-1")
OPERATOR = Principal(identity="op@example.com", kind=ActorKind.HUMAN, display="op")


class Clock:
    def __init__(self) -> None:
        self.at = T0

    def now(self) -> datetime:
        return self.at


def _forge(changed_lines: int) -> dict[str, Any]:
    """Each repository at its forge: pushed since the audit, `changed_lines` in one file."""
    answers: dict[str, Any] = {"rate_limit": 4000}
    for name in ("app", "lib"):
        answers |= {
            f"repos/org/{name}": {
                "pushed_at": "2026-09-30T00:00:00Z",
                "archived": False,
                "default_branch": "main",
                "visibility": "private",
                "fork": False,
            },
            f"repos/org/{name}/branches/main": {"sha": "b" * 40},
            f"repos/org/{name}/compare/{PINNED}...HEAD": {
                "ahead_by": 1,
                "status": "ahead",
                "files": [{"filename": "src/app.py", "changes": changed_lines}],
            },
        }
    return answers


@pytest.fixture
def forge(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    answers = _forge(changed_lines=12)  # below every threshold: rule 5, the quarterly pool

    def run(self: ProcessRunner, argv: list[str], **kwargs: Any) -> ProcessResult:
        answer = answers[argv[2]]
        out = str(answer) if isinstance(answer, int) else json.dumps(answer)
        return ProcessResult(tuple(argv), 0, out.encode(), b"", 0)

    monkeypatch.setattr(ProcessRunner, "run", run)
    return answers


def _context(tmp_path: Path, clock: Clock, budgets: tuple[Budget, ...] = ()) -> Context:
    return Context(Config(home=tmp_path / "home", budgets=budgets), clock=clock)


def _audited(context: Context, name: str) -> UUID:
    """An inventory repository with a completed audit pinned at PINNED."""
    url = HttpsRepoUrl.parse(f"https://github.com/org/{name}", ["github.com"])
    repo = context.services().portfolio.register_repository(url, False)
    assert repo.id is not None
    with SqlTraustUnitOfWork(context.database) as uow:
        ref = uow.repository_refs.add(RepositoryRef(repository_id=repo.id, sha=PINNED))
        uow.assessments.add(
            Assessment(
                repository_ref_id=ref.id,
                kind=AssessmentKind.SECURE_CODE,
                status="completed",
                assessor="skill:secure-code-audit",
                assessor_version="1",
                occurred_at=datetime(2026, 9, 1, tzinfo=UTC),
            )
        )
        uow.commit()
    return repo.id


def _threat_modelled(context: Context, repository_id: UUID) -> None:
    """A completed threat model on the repository's default branch, at PINNED."""
    with SqlTraustUnitOfWork(context.database) as uow:
        main = RepositoryRef(
            repository_id=repository_id,
            name="main",
            kind=RefKind.BRANCH,
            is_default=True,
            sha=PINNED,
        )
        uow.assessments.add(
            Assessment(
                repository_ref_id=uow.repository_refs.add(main).id,
                kind=AssessmentKind.THREAT_MODEL,
                status="completed",
                assessor="skill:threat-model",
                assessor_version="1",
                occurred_at=datetime(2026, 9, 1, tzinfo=UTC),
            )
        )
        uow.commit()


def _materialize_repo_state(context: Context, repository_id: UUID) -> None:
    """What a runner does for a repo_state order: observe, then complete it (and whatever else it
    claims on the way)."""
    services = context.services()
    with context.repository_observation() as observation:
        observation.service.record_forge_facts(repository_id=repository_id)
    request = OrderRequest(asset="repo_state", priority=20, repository_id=repository_id)
    mine = services.ops.submit(request, OPERATOR)
    while (order := services.ops.claim(WORKER, timedelta(minutes=5))) is not None:
        services.ops.complete(order.id, WORKER, JobResult.succeeded())  # type: ignore[arg-type]
        if order.id == mine.id:
            return
    raise AssertionError("the repo_state order was never claimed")


def _orders(services: Services, asset: str) -> list[RunOrder]:
    every = every_item(lambda p: services.ops.list(OrderFilter(states=tuple(OrderState)), p))
    return [o for o in every if o.asset == asset]


@pytest.fixture
def loop(tmp_path: Path, forge: dict[str, Any]) -> Iterator[tuple[Context, Clock, EngineLoop]]:
    clock = Clock()
    context = _context(tmp_path, clock)
    with context.repository_observation() as observation:
        engine = EngineLoop(
            context.services(),
            clock,
            Pack.load(PACK),
            SecurityRouter(),
            lambda rid: observation.query.repo_state(repository_id=rid),
        )
        yield context, clock, engine


def test_a_repo_state_completion_routes_the_repository_once(
    loop: tuple[Context, Clock, EngineLoop],
) -> None:
    context, clock, engine = loop
    repository_id = _audited(context, "app")
    _materialize_repo_state(context, repository_id)
    clock.at += timedelta(minutes=1)

    first = engine.run_once()
    (order,) = _orders(context.services(), "diff_scan_quarterly")
    assert first.tick.routed == 1
    assert (order.repository_id, order.lane, order.rule) == (
        repository_id,
        "diff-scan-quarterly",
        "rule-5",
    )
    assert order.state == OrderState.AWAITING_APPROVAL  # an operator approves the drain

    clock.at += timedelta(minutes=1)
    assert engine.run_once().tick.routed == 0  # nothing new materialized
    clock.at += timedelta(hours=25)
    _materialize_repo_state(context, repository_id)
    clock.at += timedelta(minutes=1)
    assert engine.run_once().tick.routed == 1
    assert len(_orders(context.services(), "diff_scan_quarterly")) == 1  # re-routes are idempotent


def test_an_iac_change_routes_the_cloud_config_lane_beside_the_tables(
    loop: tuple[Context, Clock, EngineLoop], forge: dict[str, Any]
) -> None:
    context, clock, engine = loop
    files = forge[f"repos/org/app/compare/{PINNED}...HEAD"]["files"]
    files.append({"filename": "infra/main.tf", "changes": 3})
    repository_id = _audited(context, "app")
    _materialize_repo_state(context, repository_id)
    clock.at += timedelta(minutes=1)

    assert engine.run_once().tick.routed == 1
    routed = [
        (o.asset, o.lane, o.rule)
        for asset in ("diff_scan_quarterly", "cloud_config_audit")
        for o in _orders(context.services(), asset)
    ]
    assert routed == [
        ("diff_scan_quarterly", "diff-scan-quarterly", "rule-5"),
        ("cloud_config_audit", "iac-baseline", "lever-6"),  # no cloud-config baseline yet
    ]


def test_a_threat_model_pr_stamp_reaches_the_diff_scans_session(
    loop: tuple[Context, Clock, EngineLoop],
    forge: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, clock, engine = loop
    files = forge[f"repos/org/app/compare/{PINNED}...HEAD"]["files"]
    files.append({"filename": "api/handlers.py", "changes": 4})  # an interface-bearing path
    repository_id = _audited(context, "app")
    _threat_modelled(context, repository_id)
    _materialize_repo_state(context, repository_id)
    clock.at += timedelta(minutes=1)
    engine.run_once()
    services = context.services()
    (order,) = _orders(services, "diff_scan_quarterly")
    assert order.rule == "rule-5+threat-model-pr"
    services.ops.approve(order.id, OPERATOR)  # type: ignore[arg-type]

    commands: list[list[str]] = []

    def record(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    runner = Runner(
        services, Pack.load(PACK), WORKER, timedelta(minutes=5), ("github.com",), record
    )
    while runner.claim_once() is not None:
        pass
    assert services.ops.get(order.id).state == OrderState.SUCCEEDED  # type: ignore[arg-type]
    (scan,) = [c for c in commands if "vuln-scan" in c]
    assert scan[:5] == ["python3", "-m", "traust.cli", "session", "run"]

    processes = Processes()
    monkeypatch.setattr(session.subprocess, "run", processes)
    with contextlib.redirect_stdout(io.StringIO()):
        assert session.run(scan[5:]) == 0
    prompts = [c[0][-1] for c in processes.agent_calls()]
    clone = prompts[0].split()[1]
    assert prompts == [f"/vuln-scan {clone} --diff", f"/threat-model pr {clone} --base {ANCHOR}"]


def test_a_lane_over_its_budget_is_withheld(tmp_path: Path, forge: dict[str, Any]) -> None:
    clock = Clock()
    budget = Budget(
        lane="diff-scan-quarterly", monthly_usd=Decimal("5"), enforcement=BudgetEnforcement.ENFORCED
    )
    context = _context(tmp_path, clock, (budget,))
    repository_id = _audited(context, "app")
    _materialize_repo_state(context, repository_id)
    clock.at += timedelta(minutes=1)
    with context.repository_observation() as observation:
        report = EngineLoop(
            context.services(),
            clock,
            Pack.load(PACK),
            SecurityRouter(),
            lambda rid: observation.query.repo_state(repository_id=rid),
        ).run_once()
    (order,) = _orders(context.services(), "diff_scan_quarterly")
    assert report.admission.withheld == 1
    assert (order.state, order.reason) == (OrderState.WITHHELD, "budget-over")  # 6.24 > 5


def test_a_forge_host_past_its_quota_is_deferred(tmp_path: Path, forge: dict[str, Any]) -> None:
    raw = yaml.safe_load(PACK.read_text())
    raw["assets"]["repo_state"]["admission"]["quota"]["per_hour"] = 1
    pack = tmp_path / "assets.yaml"
    pack.write_text(yaml.safe_dump(raw))
    clock = Clock()
    context = _context(tmp_path, clock)
    for name in ("app", "lib"):
        _audited(context, name)
    report = EngineLoop(context.services(), clock, Pack.load(pack)).run_once()
    states = sorted(o.state for o in _orders(context.services(), "repo_state"))
    assert report.admission.deferred == 1
    assert states == [OrderState.PLANNED, OrderState.QUEUED]
