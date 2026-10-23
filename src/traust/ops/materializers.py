"""Materializers: one pack asset, one traust-core service call, its outcome as a JobResult."""

from __future__ import annotations

from collections.abc import Iterable

from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.observation import ComparisonStatus
from traust_core.v1.models.operations import AssetRequest, JobResult
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.services.portfolio import PortfolioService

# The forge answered, or there was nothing to ask; any other status is a gap, never green.
ANSWERED = frozenset(
    {ComparisonStatus.OK, ComparisonStatus.NO_PINNED_SHA, ComparisonStatus.NEVER_AUDITED}
)


class RepoStateMaterializer:
    """`repo_state`: observe one inventory repository at its forge and keep what it answered."""

    asset = "repo_state"

    def __init__(self, portfolio: PortfolioService, hosts: Iterable[str]) -> None:
        self._portfolio = portfolio
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
