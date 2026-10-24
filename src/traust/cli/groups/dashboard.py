"""``traust dashboard …`` — deterministic dashboard rebuild and the team report."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

REFRESH = passthrough_op(
    "refresh_dashboards",
    "Rebuild every deterministic dashboard in dependency order.",
)

TEAM_REPORT = passthrough_op(
    "team_report", "Write a product or team's executive-summary pair.", "main"
)

DASHBOARD: dict[str, object] = {"refresh": REFRESH, "team-report": TEAM_REPORT}
