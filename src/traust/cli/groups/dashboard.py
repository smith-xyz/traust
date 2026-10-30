"""``traust dashboard …`` — deterministic dashboard rebuild, the team report, one view and the
SLA policy."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

REFRESH = passthrough_op(
    "refresh_dashboards",
    "Rebuild every deterministic dashboard in dependency order.",
)

TEAM_REPORT = passthrough_op(
    "team_report", "Write a product or team's executive-summary pair.", "main"
)

VIEW = passthrough_op("dashboard_view", "Write one insight view for a scope.", "main")

SLA_POLICY = passthrough_op("dashboard_view", "Record the deployment's SLA policy.", "sla_policy")

DASHBOARD: dict[str, object] = {
    "refresh": REFRESH,
    "team-report": TEAM_REPORT,
    "view": VIEW,
    "sla-policy": SLA_POLICY,
}
