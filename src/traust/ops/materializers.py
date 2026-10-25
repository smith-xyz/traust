"""Materializers: one pack asset, one traust-core service call, its outcome as a JobResult."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from pathlib import Path
from uuid import UUID

from traust_core.v1.context import Services
from traust_core.v1.errors import ConfigError, NotFoundError, ValidationError
from traust_core.v1.models.dependencies import FeedName
from traust_core.v1.models.insight import RenderedView, ViewFilter, ViewName
from traust_core.v1.models.observation import ComparisonStatus
from traust_core.v1.models.operations import AssetRequest, JobResult, OrderReason
from traust_core.v1.models.values import HttpsRepoUrl

log = logging.getLogger(__name__)

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
            log.warning("run %s: %s: %s", request.run_id, OrderReason.BAD_REQUEST, e)
            return JobResult.failed(OrderReason.BAD_REQUEST)
        try:
            facts = self._portfolio.record_forge_facts(repo_url=str(url))
        except NotFoundError as e:
            log.warning("run %s: %s: %s", request.run_id, OrderReason.NOT_FOUND, e)
            return JobResult.refused(OrderReason.NOT_FOUND)
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
            log.warning(
                "run %s: %s: run id is not an order id", request.run_id, OrderReason.BAD_REQUEST
            )
            return JobResult.failed(OrderReason.BAD_REQUEST)
        feeds = None if request.partition is None else [FeedName(request.partition)]
        try:
            statuses = self._exposure.refresh_feeds(feeds, order)
        except ConfigError as e:
            log.warning("run %s: %s: %s", request.run_id, OrderReason.BAD_REQUEST, e)
            return JobResult.failed(OrderReason.BAD_REQUEST)
        failed = [s for s in statuses if s.last_error]
        for status in failed:
            log.warning("run %s feed %s: %s", request.run_id, status.name, status.last_error)
        if any(s.fetched_at is None for s in failed):
            return JobResult.failed(OrderReason.SNAPSHOT_UNAVAILABLE)
        return JobResult.partly({s.name: 1 for s in failed}).model_copy(
            update={"reason": OrderReason.SOURCE_UNAVAILABLE if failed else None}
        )


class LedgerAuditMaterializer:
    """`ledger_audit`: verify every ledger layer. A layer that fails is `failed`; one signed but
    unverifiable here (no public key, no backend) is `unverified`; neither is ever green."""

    asset = "ledger_audit"

    def __init__(self, services: Services) -> None:
        self._ledger = services.ledger

    def materialize(self, request: AssetRequest) -> JobResult:
        if self._ledger is None:
            log.warning("run %s: no ledger configured; nothing to audit", request.run_id)
            return JobResult.refused(OrderReason.LEDGER_UNCONFIGURED)
        results = self._ledger.audit()
        failed = sum(1 for r in results if r.errors)
        unverified = sum(1 for r in results if r.warnings and not r.errors)
        return JobResult.partly(
            {k: n for k, n in (("failed", failed), ("unverified", unverified)) if n}
        )


def write_view(view: RenderedView, base: Path, model: bool = False) -> tuple[Path, ...]:
    """The rendered pair, `<base>.md` and `<base>.html` (and its model as `<base>.json`);
    core stores no view."""
    base.parent.mkdir(parents=True, exist_ok=True)
    out = {base.with_suffix(".md"): view.markdown, base.with_suffix(".html"): view.html}
    if model:
        out[base.with_suffix(".json")] = view.model.model_dump_json(indent=2)
    for path, text in out.items():
        path.write_text(text, encoding="utf-8")
    return tuple(out)


class DashboardsMaterializer:
    """`dashboards`: render every built insight view (or the one in ``partition``) to
    ``<out>/<view>/<stem>.{md,html,json}``. A view that fails is degraded; the rest are written."""

    asset = "dashboards"

    def __init__(self, services: Services, out: Path) -> None:
        self._insight = services.insight
        self._out = out

    def materialize(self, request: AssetRequest) -> JobResult:
        try:
            views = None if request.partition is None else [ViewName(request.partition)]
            result = self._insight.refresh(views, ViewFilter())
        except (ValueError, ConfigError) as e:
            log.warning("run %s: %s: %s", request.run_id, OrderReason.BAD_REQUEST, e)
            return JobResult.failed(OrderReason.BAD_REQUEST)
        written: list[Path] = []
        for view in result.rendered.values():
            written += write_view(view, self._out / view.view / view.stem, model=True)
        for name, why in result.failed.items():
            log.warning("run %s view %s: %s", request.run_id, name, why)
        degraded = {name.value: 1 for name in result.failed}
        return JobResult.partly(degraded, tuple(map(str, written))).model_copy(
            update={"reason": OrderReason.SOURCE_UNAVAILABLE if result.failed else None}
        )
