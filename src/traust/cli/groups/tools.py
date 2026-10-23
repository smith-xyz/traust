"""``traust tools …`` — deprecated aliases for migrated command groups."""

from __future__ import annotations

from traust.cli.groups.admin import ADMIN
from traust.cli.groups.build import BUILD
from traust.cli.groups.check import CHECK
from traust.cli.groups.dashboard import DASHBOARD
from traust.cli.groups.feeds import FEEDS
from traust.cli.groups.impact import IMPACT
from traust.cli.groups.ledger import LEDGER

TOOLS: dict[str, object] = {
    "attest-target": ADMIN["attest-target"],
    "build-rescan-worklist": BUILD["rescan-worklist"],
    "build-skills-reference": BUILD["skills-reference"],
    "build-symbol-index": BUILD["symbol-index"],
    "calibrate-rule-pack": IMPACT["calibrate-rule-pack"],
    "check-citations": CHECK["citations"],
    "check-content-licenses": CHECK["content-licenses"],
    "check-docs-consistency": CHECK["docs-consistency"],
    "check-drift": CHECK["drift"],
    "check-fix-propagation": CHECK["fix-propagation"],
    "check-location-paths": CHECK["location-paths"],
    "check-reference-integrity": CHECK["reference-integrity"],
    "check-skill-alignment": CHECK["skill-alignment"],
    "check-skill-security": CHECK["skill-security"],
    "checkpoint": ADMIN["checkpoint"],
    "cluster-state-diff": IMPACT["cluster-state-diff"],
    "emit-doc-variance": LEDGER["doc-variance"],
    "fetch-feeds": FEEDS["fetch"],
    "query-index": ADMIN["query-index"],
    "refresh-dashboards": DASHBOARD["refresh"],
    "scan-internal-refs": ADMIN["scan-internal-refs"],
    "toolchain": ADMIN["toolchain"],
}
