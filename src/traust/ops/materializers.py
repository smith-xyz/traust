"""Materializers: one pack asset, one traust-core service call, its outcome as a JobResult."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from uuid import UUID

from traust_core.v1.context import Services
from traust_core.v1.errors import ConfigError, NotFoundError, ValidationError
from traust_core.v1.models.dependencies import FeedName
from traust_core.v1.models.insight import RenderedView, ViewFilter, ViewName
from traust_core.v1.models.observation import ComparisonStatus
from traust_core.v1.models.operations import AssetRequest, JobResult
from traust_core.v1.models.values import HttpsRepoUrl

# The forge answered, or there was nothing to ask; any other status is a gap, never green.
ANSWERED = frozenset(
    {ComparisonStatus.OK, ComparisonStatus.NO_PINNED_SHA, ComparisonStatus.NEVER_AUDITED}
)


class RepoStateMaterializer:
    """`repo_state`: observe one inventory repository at its forge and keep what it answered."""

    asset = "repo_state"

    def __init__(self, services: Services, hosts: Iterable[str]) -> None:
        self._portfolio = services.portfolio
        self._hosts = tuple(hosts)

    def materialize(self, request: AssetRequest) -> JobResult:
        try:
            url = HttpsRepoUrl.parse(request.partition or "", self._hosts)
        except ValidationError as e:
            return JobResult.failed(f"bad request: {e}")
        try:
            facts = self._portfolio.record_forge_facts(repo_url=str(url))
        except NotFoundError as e:
            return JobResult.refused(str(e))
        if facts.status in ANSWERED:
            return JobResult.succeeded()
        return JobResult.partly({facts.status.value: 1})


# A run by hand, not for an engine order.
MANUAL = "manual"


def _order_id(run_id: str) -> UUID | None:
    return None if run_id == MANUAL else UUID(run_id)


class FeedsCacheMaterializer:
    """`feeds_cache`: snapshot every security feed (or the one in ``partition``)."""

    asset = "feeds_cache"

    def __init__(self, services: Services) -> None:
        self._exposure = services.exposure

    def materialize(self, request: AssetRequest) -> JobResult:
        try:
            order = _order_id(request.run_id)
        except ValueError:
            return JobResult.failed(f"bad request: run id {request.run_id!r} is not an order id")
        feeds = None if request.partition is None else [FeedName(request.partition)]
        try:
            statuses = self._exposure.refresh_feeds(feeds, order)
        except ConfigError as e:
            return JobResult.failed(f"bad request: {e}")
        failed = [s for s in statuses if s.last_error]
        reason = "; ".join(f"{s.name}: {s.last_error}" for s in failed) or None
        if any(s.fetched_at is None for s in failed):
            return JobResult.failed(f"no usable snapshot: {reason}")
        return JobResult.partly({s.name: 1 for s in failed}).model_copy(update={"reason": reason})


class LedgerAuditMaterializer:
    """`ledger_audit`: verify every ledger layer. A layer that fails is `failed`; one signed but
    unverifiable here (no public key, no backend) is `unverified`; neither is ever green."""

    asset = "ledger_audit"

    def __init__(self, services: Services) -> None:
        self._ledger = services.ledger

    def materialize(self, request: AssetRequest) -> JobResult:
        if self._ledger is None:
            return JobResult.refused("no ledger configured (core.yaml `ledger:`); nothing to audit")
        results = self._ledger.audit()
        failed = sum(1 for r in results if r.errors)
        unverified = sum(1 for r in results if r.warnings and not r.errors)
        return JobResult.partly(
            {k: n for k, n in (("failed", failed), ("unverified", unverified)) if n}
        )


def write_view(view: RenderedView, directory: Path, stem: str | None = None) -> tuple[Path, ...]:
    """`<stem>.md`, `.html` and `.json` (the model) under `directory`; core stores no view."""
    directory.mkdir(parents=True, exist_ok=True)
    base = directory / (stem or view.stem)
    out = {
        base.with_suffix(".md"): view.markdown,
        base.with_suffix(".html"): view.html,
        base.with_suffix(".json"): view.model.model_dump_json(indent=2),
    }
    for path, text in out.items():
        path.write_text(text, encoding="utf-8")
    return tuple(out)


class DashboardsMaterializer:
    """`dashboards`: render every built insight view (or the one in ``partition``) under
    ``<out>/<view>/``. A view that fails is degraded; the rest are still written."""

    asset = "dashboards"

    def __init__(self, services: Services, out: Path) -> None:
        self._insight = services.insight
        self._out = out

    def materialize(self, request: AssetRequest) -> JobResult:
        try:
            views = None if request.partition is None else [ViewName(request.partition)]
            result = self._insight.refresh(views, ViewFilter())
        except (ValueError, ConfigError) as e:
            return JobResult.failed(f"bad request: {e}")
        written = tuple(
            str(path)
            for view in result.rendered.values()
            for path in write_view(view, self._out / view.view)
        )
        reason = "; ".join(f"{name}: {why}" for name, why in result.failed.items()) or None
        degraded = {name.value: 1 for name in result.failed}
        return JobResult.partly(degraded, written).model_copy(update={"reason": reason})
