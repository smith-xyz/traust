"""``traust dashboard view``: publish one traust-core insight view for a scope and write its
`<stem>.{md,html,json}`; core builds and renders it and stores nothing."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from traust_core.v1.context import Context
from traust_core.v1.models.common import TimeBucket, TimeWindow
from traust_core.v1.models.insight import ViewFilter, ViewName

from traust.cli import _doors
from traust.cli._doors import parser, run, when
from traust.context import load
from traust.ops.materializers import write_view


def main(argv: list[str] | None = None) -> int:
    ap = parser("dashboard", "view", "Write one insight view (e.g. findings-trend, program).")
    ap.add_argument("view", choices=[v.value for v in ViewName])
    ap.add_argument("--product", action="append", default=[], help="a product slug (repeatable)")
    ap.add_argument("--team-id", action="append", default=[], type=uuid.UUID, help="(repeatable)")
    ap.add_argument("--as-of", help="ISO time with a zone (default: now)")
    ap.add_argument("--since", help="window start, ISO time with a zone")
    ap.add_argument("--until", help="window end (default: --as-of, else now)")
    ap.add_argument("--bucket", choices=[b.value for b in TimeBucket], default="month")
    ap.add_argument(
        "--artifact-id", type=uuid.UUID, help="the document a one-item view renders (oscal)"
    )
    ap.add_argument("--out", type=Path, required=True, help="the folder the view is written to")
    ap.add_argument(
        "--sla-policy", type=Path, help="the sla view's policy (default: the config home's)"
    )
    ap.add_argument(
        "--invoice",
        type=Path,
        help="the spend view's billed amounts: CSV period,amount_usd[,note]",
    )
    args = ap.parse_args(argv)

    def call() -> dict[str, Any]:
        as_of, since = when(args.as_of), when(args.since)
        until = when(args.until) or as_of or datetime.now(UTC)
        services = _core(ViewName(args.view), args).services()
        scope = ViewFilter(
            product_ids=tuple(p.id for p in _doors.products(services, args.product)),
            team_ids=tuple(args.team_id),
            as_of=as_of,
            window=None if since is None else TimeWindow(start=since, end=until),
            bucket=TimeBucket(args.bucket),
            artifact_id=args.artifact_id,
        )
        rendered = services.insight.publish(ViewName(args.view), scope)
        written = write_view(rendered, args.out / rendered.stem, model=True)
        model = rendered.model.model_dump(mode="json")
        return {"written": [str(p) for p in written], "model": model}

    return run(call)


def _core(view: ViewName, args: Any) -> Context:
    core = load(args.config_home, sla_policy=args.sla_policy, invoices=args.invoice)
    if view is ViewName.FRESHNESS:
        # freshness reads the feed snapshots. NEED(core: feeds registered lazily by name)
        core.register_feeds()
    return core
