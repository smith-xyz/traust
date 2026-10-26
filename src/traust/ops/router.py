"""The security pack's router: a repository's routing state (traust-core `RepoState`) to its
work lane, the decision table `build rescan-worklist` applied per repository (stage 2)."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from traust_core.v1.models.inventory import ExposureClass, RepoState, RiskTier
from traust_core.v1.models.operations import LaneName, Refusal, Route
from traust_core.v1.models.vocabulary import ComparisonStatus

CHURN_FULL_LINES = 8000
CHURN_FULL_RATIO = 0.10
SENSITIVE_MIN_LINES = 200
TIER_CEILING_DAYS = {RiskTier.P0: 180, RiskTier.P1: 270, RiskTier.P2: 365}
# The external band (customer-facing impact) tightens the ceiling one notch (policy v1.4).
TIGHTENED_CEILING_DAYS = {RiskTier.P0: 180, RiskTier.P1: 180, RiskTier.P2: 270}
EXTERNAL = frozenset({ExposureClass.PUBLIC_EXTERNAL, ExposureClass.PRIVATE_EXTERNAL})

# contracts' work_lane values, in the legacy worklist's dispatch order: an order's priority.
LANES = (
    "full-audit+validate",
    "full-audit",
    "impact-lane",
    "iac-lane",
    "iac-baseline",
    "release-passthrough",
    "threat-model-review",
    "deps-lane",
    "diff-scan",
    "diff-scan-quarterly",
    "threat-model-quarterly",
    "none",
)
EXPOSURE_ORDER = (
    ExposureClass.PUBLIC_EXTERNAL,
    ExposureClass.PRIVATE_EXTERNAL,
    ExposureClass.PUBLIC_INTERNAL,
    ExposureClass.PRIVATE_INTERNAL,
)
TIER_ORDER = (RiskTier.P0, RiskTier.P1, RiskTier.P2, RiskTier.P3)
# Routed orders rank after the pack's standing jobs (priorities below 100).
PRIORITY_BASE = 100
# Classified but not queued: rule 3b's manifest-only change is covered advisory-first by the
# `dependency_watch` asset, which never read the worklist rows.
UNQUEUED = frozenset({"deps-lane", "none"})


@dataclass(frozen=True)
class Rule:
    id: str
    applies: Callable[[RepoState], bool]
    lane: Callable[[RepoState], str]
    reason: str


def _lines(s: RepoState) -> int:
    return s.changed_lines or 0


def _over_ceiling(s: RepoState) -> bool:
    table = TIGHTENED_CEILING_DAYS if s.exposure in EXTERNAL else TIER_CEILING_DAYS
    ceiling = table.get(s.risk_tier)
    return ceiling is not None and s.audit_age_days is not None and s.audit_age_days > ceiling


# First match wins. The status rules come first: their metrics are missing or unmeasurable.
RULES: tuple[Rule, ...] = (
    Rule(
        "rule-1-bootstrap",
        lambda s: s.status == ComparisonStatus.NEVER_AUDITED,
        lambda s: "full-audit",
        "never audited: full audit + threat-model bootstrap (self-heals into change detection)",
    ),
    Rule(
        "quota-deferred",
        lambda s: s.status == ComparisonStatus.QUOTA_DEFERRED,
        lambda s: "none",
        "changed, but the compare was deferred to the next observation (API quota)",
    ),
    Rule(
        "no-pinned-sha",
        lambda s: s.status == ComparisonStatus.NO_PINNED_SHA and bool(s.push_changed),
        lambda s: "full-audit",
        "changed since audit but churn unmeasurable: a full audit re-establishes the anchor",
    ),
    Rule(
        "no-pinned-sha",
        lambda s: s.status == ComparisonStatus.NO_PINNED_SHA,
        lambda s: "none",
        "no push signal; the anchor is re-established at the next audit",
    ),
    Rule(
        "rule-2",
        lambda s: (
            (s.churn_ratio is not None and s.churn_ratio >= CHURN_FULL_RATIO)
            or _lines(s) >= CHURN_FULL_LINES
        ),
        lambda s: "full-audit",
        "coverage-map churn (R>=10% or C>=8000 first-party lines)",
    ),
    Rule(
        "rule-3",
        lambda s: bool(s.sensitive_changed) and (s.sensitive_lines or 0) >= SENSITIVE_MIN_LINES,
        lambda s: "full-audit" if s.risk_tier in (RiskTier.P0, RiskTier.P1) else "diff-scan",
        "sensitive-identifier files changed, >=200 lines",
    ),
    Rule(
        "rule-3b",
        lambda s: bool(s.deps_only),
        lambda s: "deps-lane",
        "dependency manifests only (deterministic osv/impact lane)",
    ),
    Rule(
        "rule-4",
        _over_ceiling,
        lambda s: "full-audit",
        "audit age over tier ceiling (P0 180d / P1 270d / P2 365d)",
    ),
    Rule(
        "rule-5",
        lambda s: _lines(s) > 0,
        lambda s: "diff-scan-quarterly",
        "below-threshold change (accumulates for the quarterly batch)",
    ),
    Rule(
        "rule-6",
        lambda s: bool(s.push_changed) and s.ahead_by == 0,
        lambda s: "none",
        "pushed_at moved but 0 commits ahead (tag/branch noise)",
    ),
    Rule(
        "rule-7",
        lambda s: True,
        lambda s: "none",
        "no qualifying change (dormant repos re-enter on push)",
    ),
)


def decide(state: RepoState) -> tuple[Rule, str]:
    """The first rule that applies, and the lane it picks (a work_lane value)."""
    rule = next(r for r in RULES if r.applies(state))
    return rule, rule.lane(state)


def priority(lane: str, state: RepoState) -> int:
    """Lower runs sooner: lane, then exposure, then tier, as the legacy worklist sorted."""
    return PRIORITY_BASE + (
        LANES.index(lane) * 16
        + EXPOSURE_ORDER.index(state.exposure) * 4
        + TIER_ORDER.index(state.risk_tier)
    )


class SecurityRouter:
    """The pack router `traust-engine` calls when a repository's `repo_state` materializes."""

    def route(
        self, state: RepoState, events: Sequence[object], refusals: Sequence[Refusal]
    ) -> Route:
        # NEED(feed): rule 1's events (external report, methodology, CVE, release) and refusal
        # re-routing arrive once *Order reads and the feed* lands; the controller passes ().
        rule, lane = decide(state)
        return Route(
            lane=None if lane in UNQUEUED else LaneName(lane),
            priority=priority(lane, state),
            reason=rule.id,
        )
