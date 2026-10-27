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
    "Below-range verification (packets, then review)": "below_range_packets",
    "Weekly diff-drain tranche": "diff_scan_quarterly",
    # the calendar backstop; the release review waits on recorded releases reaching the router,
    # and the `pr` stamp rides diff_scan's rule
    "Threat-model re-model lanes": "threat_model_quarterly",
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
ROUTED = {"Fleet refresh + rescan router": ("full_audit", "diff_scan", "cloud_config_audit")}

# Assets a row's asset feeds: they run once its output is fresh, as the same standing job.
FOLLOWS = {"below_range_review": "below_range_packets"}

# Rows that stay outside the pack, and why.
EXCLUDED = {
    "Release/dist-git event feeder": "derived on demand from recorded releases "
    "(PortfolioService.release_changes); dist-git heads are repo_state observations",
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
    routed = {a for row in ROUTED.values() for a in row}
    assert set(pack.assets) <= {*ASSETS.values(), *routed, *FOLLOWS}
    assert all(pack.assets[a].deps == (FOLLOWS[a],) for a in FOLLOWS)


def test_every_asset_has_a_trigger_freshness_and_runner_labels() -> None:
    raw = yaml.safe_load(PACK.read_text())["assets"]
    for name, asset in raw.items():
        assert asset.get("trigger") or asset.get("deps"), name
        # a routed lane has no cadence to fall behind: nothing is due until the router routes
        assert asset.get("freshness") or asset.get("trigger", {}).get("lanes"), name
        assert asset.get("runner", {}).get("labels"), name


REGISTRY = Path(__file__).resolve().parents[1] / "config" / "model-registry.yaml"
# What traust-engine's claim-once runner fills in: the order's id, its repository's URL, a
# skill session's model role, and a routed order's rule.
RUNNER_PARAMS = {"run_id", "repo_url", "role", "rule"}


def test_every_skill_session_names_a_registry_role() -> None:
    roles = set(yaml.safe_load(REGISTRY.read_text())["roles"])
    sessions = {n: a.model.role for n, a in Pack.load(PACK).assets.items() if a.model}
    assert sessions and set(sessions.values()) <= roles, sessions


def test_every_command_param_is_one_the_runner_fills() -> None:
    raw = yaml.safe_load(PACK.read_text())["assets"]
    for name, asset in raw.items():
        named = {m[1] for t in asset.get("run", []) if (m := re.fullmatch(r"\{(\w+)\}", t))}
        assert named <= RUNNER_PARAMS, (name, named)
        assert "repo_url" not in named or asset.get("partitions") == "dynamic:repo", name
        assert "rule" not in named or "lanes" in asset["trigger"], name


def test_every_runnable_skill_session_starts_through_traust_session_with_its_role() -> None:
    from traust.paths import skill_dir

    for name, asset in yaml.safe_load(PACK.read_text())["assets"].items():
        if "model" not in asset or "run" not in asset:
            continue
        run = asset["run"]
        assert run[3:5] == ["session", "run"] and "{role}" in run, name
        skill_dir(run[run.index("--skill") + 1])


def test_only_the_scheduled_threat_model_check_up_applies_ratings() -> None:
    # The 2026-10-01 decision: the quarterly (and, once routed, the release) review writes OWASP
    # ratings; every other threat-model lane stays report-only.
    runs = {n: a.run for n, a in Pack.load(PACK).assets.items() if "--apply-ratings" in a.run}
    assert list(runs) == ["threat_model_quarterly"]
    run = runs["threat_model_quarterly"]
    assert run[run.index("--mode") + 1] == "review" and "--auto" in run
