"""``traust impact …`` — the impact-analysis skill's doors on traust-core, and sweep tooling."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

IMPACT: dict[str, object] = {
    "find": passthrough_op("impact", "Print an advisory as its source states it now.", "find"),
    "package": passthrough_op(
        "impact", "Print the advisories affecting one package version.", "package"
    ),
    "sbom": passthrough_op("impact", "Record a commit's manifest SBOM.", "sbom"),
    "symbols": passthrough_op(
        "impact", "Print the functions an advisory's fix touched.", "symbols"
    ),
    "analyze": passthrough_op(
        "impact", "Assess and record the commits an advisory reaches.", "analyze"
    ),
    "document": passthrough_op(
        "impact", "Print a feed source's document for one identifier.", "document"
    ),
    "enrich": passthrough_op(
        "impact", "EPSS, KEV and product reach for an artifact's CVEs.", "enrich"
    ),
    "sweep": passthrough_op(
        "impact", "Which known advisories touch the recorded SBOMs at all.", "sweep"
    ),
    "below-range": passthrough_op(
        "impact",
        "Evidence packets for advisories whose stated range starts above the installed version.",
        "below_range",
    ),
    "calibrate-rule-pack": passthrough_op(
        "calibrate_rule_pack", "Score a rule pack's recorded scans against confirmed TPs."
    ),
    "cluster-state-diff": passthrough_op(
        "cluster_state_diff", "Cluster state diffing — validation-improvement-plan P5, sweep lane."
    ),
}
