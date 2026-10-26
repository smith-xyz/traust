from __future__ import annotations

import re
from pathlib import Path

import yaml
from traust_engine import Pack

PACK = Path(__file__).resolve().parents[1] / "packs" / "security" / "assets.yaml"


def test_the_security_pack_loads_and_every_source_asset_has_a_cadence() -> None:
    pack = Pack.load(PACK)
    sources = [name for name, asset in pack.assets.items() if not asset.deps]
    assert {"feeds_cache", "repo_state"} <= set(sources)
    assert all(pack.assets[name].trigger.every is not None for name in sources)


STANDING_JOBS = Path(__file__).resolve().parents[1] / "docs" / "continuous-operations.md"

# Standing-jobs row (its Job cell, markup stripped) -> the asset that runs it.
ASSETS = {
    # the refresh half; its rescan router is the pack router (route_on: repo_state)
    "Fleet refresh + rescan router": "repo_state",
    "Weekly diff-drain tranche": "diff_scan_quarterly",
    "/dependency-watch (deps lane end to end)": "dependency_watch",
    "Feed router — security-data refresh (EPSS / KEV / vendor CVE and VEX feeds)": "feeds_cache",
    "Verify-remediation treadmill": "verify_remediation",
    "Rule-mining lane": "rule_mining",
    "Ledger audit": "ledger_audit",
    "Validation benchmark": "validation_benchmark",
    "Recall benchmark": "recall_benchmark",
    "Class-sweep rotation": "class_sweep",
    "Spend capture (/financial-tracking capture)": "spend_capture",
    "Dashboards rebuild (all deterministic dashboards: census + exec summary, trends, "
    "insecure-patterns, validation-fuzz, rbac-tenancy, sla, compliance, attack-coverage, loc, "
    "spend, scoreboard)": "dashboards",
}

# The rescan router's routed lanes: assets planned from traust.ops.router's lane, not a row.
ROUTED = {"Fleet refresh + rescan router": ("full_audit", "diff_scan")}

# Rows that stay outside the pack, and why.
EXCLUDED = {
    "Release/dist-git event feeder": "derived on demand from recorded releases "
    "(PortfolioService.release_changes); dist-git heads are repo_state observations",
    "Threat-model re-model lanes": "routed lanes the router can't decide yet: the release review "
    "waits on recorded releases reaching it, the quarterly backstop on the model's age in RepoState",
    "/drift-watch": "replaced by each asset's freshness (FreshnessQuery.stale)",
    "Feed-source liveness": "cached sources: feeds_cache degrades per source; live-tier probes "
    "retired, back as core readiness once the live sources are core providers",
    "CVE-replay FN monitor": "retired with the hub; Detection quality rebuilds it",
    "Census + repo-liveness refresh": "intake-triggered; the schema has no event trigger",
    "FP-precedent cache rebuild": "drift-triggered; the schema has no event trigger",
    "Threshold re-derivation": "human-decision: a person edits the decision table",
    "IaC quarterly re-baseline": "human-decision, drift-flagged",
    "Portfolio-graph heavyweight rebuild": "human-decision, drift-flagged",
    "ADR / pin / external-tool advances": "human-decision, never automated",
    "Docs semantic sweep": "a reviewer sweep, not a job",
}


def _standing_jobs() -> list[str]:
    text = STANDING_JOBS.read_text().split("## Standing jobs", 1)[1].split("\n## ", 1)[0]
    rows = [line for line in text.splitlines() if line.startswith("|")][2:]
    return [re.sub(r"[*`]", "", row.split("|")[1]).strip() for row in rows]


def test_every_standing_job_is_an_asset_or_an_explicit_exclusion() -> None:
    jobs = _standing_jobs()
    assert sorted(jobs) == sorted([*ASSETS, *EXCLUDED])
    pack = Pack.load(PACK)
    assert set(ASSETS.values()) <= set(pack.assets)
    assert set(pack.assets) <= {*ASSETS.values(), *(a for row in ROUTED.values() for a in row)}


def test_every_asset_has_a_trigger_freshness_and_runner_labels() -> None:
    raw = yaml.safe_load(PACK.read_text())["assets"]
    for name, asset in raw.items():
        assert asset.get("trigger") or asset.get("deps"), name
        # a routed lane has no cadence to fall behind: nothing is due until the router routes
        assert asset.get("freshness") or asset.get("trigger", {}).get("lanes"), name
        assert asset.get("runner", {}).get("labels"), name
