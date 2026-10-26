"""The security pack's router against the legacy router's characterization corpus
(`fixtures/routing/`, see its README): every decision-table, risk-tier and status case gives
the same rule and lane through traust-core's `RepoState` and `PortfolioPolicy`."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from traust_core.v1.models.inventory import ExposureClass, RepoState, RiskTier
from traust_core.v1.models.observation import Designation
from traust_core.v1.models.vocabulary import ComparisonStatus
from traust_core.v1.services.portfolio import PortfolioPolicy

from traust.ops.router import LANES, SecurityRouter, decide, priority

FIXTURES = Path(__file__).parent / "fixtures" / "routing"
DECISIONS = json.loads((FIXTURES / "python_decisions.json").read_text(encoding="utf-8"))
PRIMARY = json.loads((FIXTURES / "python_primary.json").read_text(encoding="utf-8"))
POLICY = PortfolioPolicy()
OBSERVED = datetime(2026, 9, 28, tzinfo=UTC)


def _state(**fields: Any) -> RepoState:
    base: dict[str, Any] = {
        "repository_id": uuid4(),
        "repo": None,
        "status": ComparisonStatus.OK,
        "risk_tier": RiskTier.P2,
        "exposure": ExposureClass.PRIVATE_INTERNAL,
        "open_critical_high": 0,
        "audit_age_days": None,
        "changed_lines": None,
        "churn_ratio": None,
        "sensitive_changed": None,
        "sensitive_lines": None,
        "deps_only": None,
        "ahead_by": None,
        "compare_truncated": None,
        "push_changed": None,
        "observed_at": OBSERVED,
    }
    return RepoState(**(base | fields))


def _exposure(value: str) -> ExposureClass:
    # The legacy corpus leaves exposure blank when it doesn't matter: never the external band.
    return ExposureClass(value) if value else ExposureClass.PRIVATE_INTERNAL


def _table_state(ctx: dict[str, Any]) -> RepoState:
    return _state(
        risk_tier=RiskTier(ctx["tier"]),
        exposure=_exposure(ctx["exposure"]),
        changed_lines=ctx["C"],
        churn_ratio=ctx["R"],
        sensitive_changed=ctx["S"],
        sensitive_lines=ctx["S_lines"],
        deps_only=ctx["deps_only"],
        audit_age_days=ctx["audit_age_days"],
        push_changed=ctx["changed"],
        ahead_by=ctx["ahead_by"],
    )


def _primary_state(supplied: dict[str, Any]) -> RepoState:
    audit = supplied.get("Audit")
    if audit is None:
        designation = (supplied["Inventory"] or {}).get("Designation")
        return _state(
            status=ComparisonStatus.NEVER_AUDITED,
            exposure=POLICY.exposure_class(
                Designation(designation) if designation else None, None, False
            ),
        )
    risk, change = audit.get("Risk", {}), audit.get("Change") or {}
    live = risk.get("LiveCriticalHigh", 0)
    lines = change.get("ChangedLines", 0) if "Change" in audit else None
    ratio = change.get("CoverageChangeRatio") or None
    return _state(
        status=ComparisonStatus(audit["Status"]),
        risk_tier=POLICY.risk_tier(live, risk.get("Archived", False), risk.get("Dormant", False)),
        open_critical_high=live,
        exposure=_exposure(audit.get("Exposure", "")),
        audit_age_days=audit.get("AuditAgeDays"),
        push_changed=audit.get("PushChanged", False),
        changed_lines=lines,
        churn_ratio=ratio,
        sensitive_changed=change.get("SensitiveChange"),
        sensitive_lines=change.get("SensitiveChangedLines"),
        deps_only=change.get("DependenciesOnly"),
        ahead_by=change.get("CommitsAhead"),
    )


# One decision, from the table or a status rule. Event rows (rule 1) wait on the feed.
STATUS_CASES = [
    c
    for c in PRIMARY["primary"]
    if len(c["want"]["Decisions"]) == 1 and c["want"]["Decisions"][0]["EventIndex"] is None
]


@pytest.mark.parametrize("case", DECISIONS["table"], ids=lambda c: c["name"])
def test_decision_table_matches_the_legacy_router(case: dict[str, Any]) -> None:
    rule, lane = decide(_table_state(case["input"]))
    assert (rule.id, lane) == (case["want"]["Rule"], case["want"]["Lane"])


@pytest.mark.parametrize("case", DECISIONS["risk"], ids=lambda c: c["name"])
def test_core_risk_tier_matches_the_legacy_router(case: dict[str, Any]) -> None:
    risk = case["input"]
    tier = POLICY.risk_tier(risk["LiveCriticalHigh"], risk["Archived"], risk["Dormant"])
    assert tier == case["want"]


@pytest.mark.parametrize("case", STATUS_CASES, ids=lambda c: c["name"])
def test_status_rules_match_the_legacy_router(case: dict[str, Any]) -> None:
    (want,) = case["want"]["Decisions"]
    state = _primary_state(case["input"])
    rule, lane = decide(state)
    assert (rule.id, lane, state.risk_tier) == (want["Rule"], want["Lane"], want["RiskTier"])
    if want["Exposure"]:
        assert state.exposure == want["Exposure"]


def test_the_corpus_covers_every_status() -> None:
    covered = {_primary_state(c["input"]).status for c in STATUS_CASES}
    assert covered == set(ComparisonStatus)


@pytest.mark.parametrize(
    ("fields", "lane"),
    [
        ({"changed_lines": 8000}, "full-audit"),
        ({"changed_lines": 1}, "diff-scan-quarterly"),
        ({"sensitive_changed": True, "sensitive_lines": 200}, "diff-scan"),
        ({"status": ComparisonStatus.NEVER_AUDITED}, "full-audit"),
    ],
)
def test_route_names_the_lane_and_the_rule(fields: dict[str, Any], lane: str) -> None:
    state = _state(**fields)
    route = SecurityRouter().route(state, (), ())
    rule, _ = decide(state)
    assert (route.lane, route.reason, route.priority) == (lane, rule.id, priority(lane, state))


@pytest.mark.parametrize(
    "fields",
    [
        {"deps_only": True, "changed_lines": 10},  # rule 3b: dependency_watch covers it
        {"status": ComparisonStatus.QUOTA_DEFERRED, "changed_lines": 9000},
        {"push_changed": True, "ahead_by": 0},
        {},
    ],
)
def test_classifications_without_a_queue_plan_nothing(fields: dict[str, Any]) -> None:
    route = SecurityRouter().route(_state(**fields), (), ())
    assert route.lane is None and route.reason == decide(_state(**fields))[0].id


def test_priority_orders_by_lane_then_exposure_then_tier() -> None:
    ranked = sorted(
        (
            (priority(lane, _state(exposure=e, risk_tier=t)), lane, e, t)
            for lane in LANES
            for e in ExposureClass
            for t in RiskTier
        ),
        key=lambda r: r[0],
    )
    keys = [r[0] for r in ranked]
    assert len(set(keys)) == len(keys)
    assert [r[1] for r in ranked] == sorted((r[1] for r in ranked), key=LANES.index)
    first = [r for r in ranked if r[1] == "diff-scan-quarterly"][:2]
    assert [(r[2], r[3]) for r in first] == [
        (ExposureClass.PUBLIC_EXTERNAL, RiskTier.P0),
        (ExposureClass.PUBLIC_EXTERNAL, RiskTier.P1),
    ]
