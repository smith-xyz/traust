"""``traust portfolio liveness``: census's repo-liveness artifact on traust-core.

Every registered repository's archived flag and default-branch push as last observed by
``traust portfolio observe`` (no forge call here). ``status`` keeps the artifact's words:
``archived``, ``active``, or ``unknown`` when never observed (``reason`` says why).
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from traust_core.v1.models.common import every_item
from traust_core.v1.models.inventory import RepositoryFilter

from traust.cli._doors import parser, run
from traust.context import load_services


def main(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "liveness", "Each registered repository's archived flag and push.")
    args = ap.parse_args(argv)

    def call() -> Any:
        services = load_services(args.config_home)
        repos = {
            row.url: {
                "status": "archived" if row.archived else "unknown" if row.unobserved else "active"
            }
            | row.model_dump(mode="json", exclude={"url", "repository_id"}, exclude_none=True)
            for row in every_item(
                lambda page: services.portfolio.liveness(RepositoryFilter(), page)
            )
        }
        counts = Counter(entry["status"] for entry in repos.values())
        return {"counts": dict(sorted(counts.items())), "repos": dict(sorted(repos.items()))}

    return run(call)
