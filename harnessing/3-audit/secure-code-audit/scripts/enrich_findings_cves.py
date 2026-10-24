#!/usr/bin/env python3
"""Exploitation-context enrichment for CVE-bearing findings (C8).

Joins every CVE id found in the input artifacts against the EPSS and
CISA KEV feeds (traust-core's latest `traust feeds fetch` snapshots) and, where
the repository is known to repo-graph, adds deployment-reachability
context (how many products ship the repo, owning team). Output is an
ENRICHMENT TAGGER artifact: it routes prioritization and joins evidence —
it never changes a severity, never concludes, and never emits findings
(docs/deterministic-inferential-mix.md).

Accepted inputs (repeat --in): any JSON artifact with a `findings` list
(report schema, findings-current) or a `candidates` list (run_osv_scanner,
run_govulncheck, run_gitleaks outputs). CVE ids are extracted
deterministically (regex over each item) so schema drift cannot silently
drop coverage.

Deployment reachability tiers (weakest→strongest):
  product_shipped   repo appears in repo-graph `ships` edges
  deployed          only when --workloads names it (an `oc` inventory from
                    an authorized lab cluster, validate-core-ocp blast
                    radius); absent input ⇒ "unknown", never guessed

Usage:
    python3 enrich_findings_cves.py --in <artifact.json> [--in ...]
        [--refresh] [--repo-graph FILE]
        [--workloads FILE] [--out FILE]
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import subprocess
import sys
from pathlib import Path

from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.dependencies import AdvisoryIdentifier

from traust.context import (
    add_config_home_arg,
    analysis_results_dir,
    load_core,
)
from traust.paths import HARNESS_ROOT
from traust.registry.feeds_config import registry_path

CVE_RX = re.compile(r"CVE-\d{4}-\d{4,7}")
REPO_RX = re.compile(r"github\.com[/:]([\w.-]+/[\w.-]+?)(?:\.git|/|$)")


def harness_version():
    try:
        v = (HARNESS_ROOT / "VERSION").read_text().strip()
    except OSError:
        return None
    try:
        sha = subprocess.run(
            ["git", "-C", str(HARNESS_ROOT), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        ).stdout.strip()
        return f"{v}-{sha}"
    except (subprocess.SubprocessError, OSError):
        return v


def load_repo_graph(path: Path) -> dict[str, dict]:
    """label 'org/name' -> {products: [...], owner: str|None}"""
    g = json.loads(path.read_text(encoding="utf-8"))
    by_id, by_label, labels = {}, {}, {}
    for n in g.get("nodes") or []:
        if n.get("type") == "repo":
            entry = {"products": [], "owner": None}
            by_id[n["id"]] = entry
            by_label[n.get("label") or ""] = entry
        labels[n["id"]] = n.get("label") or n["id"].split(":", 1)[-1]
    for e in g.get("edges") or []:
        rel = e.get("rel")
        if rel == "ships" and e.get("to") in by_id:
            by_id[e["to"]]["products"].append(labels.get(e.get("from"), e.get("from")))
        elif rel == "owned-by":
            if e.get("from") in by_id:
                by_id[e["from"]]["owner"] = str(e.get("to", "")).split(":", 1)[-1]
            elif e.get("to") in by_id:
                by_id[e["to"]]["owner"] = str(e.get("from", "")).split(":", 1)[-1]
    return by_label


def repo_label(doc: dict) -> str | None:
    """Best-effort 'org/name' from artifact metadata."""
    meta = doc.get("metadata") or {}
    for v in (meta.get("repository"), meta.get("repo"), meta.get("repository_url")):
        if isinstance(v, str):
            m = REPO_RX.search(v)
            if m:
                return m.group(1)
    return None


def items_of(doc: dict) -> tuple[str, list[dict]]:
    if isinstance(doc.get("findings"), list):
        return "findings", doc["findings"]
    if isinstance(doc.get("candidates"), list):
        return "candidates", doc["candidates"]
    return "none", []


def item_id(item: dict) -> str:
    for k in ("id", "fingerprint", "osv_id"):
        if item.get(k):
            return str(item[k])
    return "(unidentified)"


def enrich_items(items: list[dict], epss: dict, kev: dict) -> list[dict]:
    out = []
    for item in items:
        cves = sorted(set(CVE_RX.findall(json.dumps(item))))
        if not cves:
            continue
        per_cve = []
        for c in cves:
            e = epss.get(c) or {}
            k = kev.get(c)
            per_cve.append(
                {
                    "cve": c,
                    "epss": e.get("epss"),
                    "epss_percentile": e.get("percentile"),
                    "kev": k is not None,
                    "kev_date_added": (k or {}).get("date_added"),
                    "kev_ransomware": (k or {}).get("ransomware", False),
                }
            )
        out.append(
            {
                "id": item_id(item),
                "cves": per_cve,
                "max_epss": max(
                    (c["epss"] for c in per_cve if c["epss"] is not None), default=None
                ),
                "kev_any": any(c["kev"] for c in per_cve),
            }
        )
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_config_home_arg(ap)
    ap.add_argument(
        "--in",
        dest="inputs",
        action="append",
        required=True,
        type=Path,
        help="findings/candidates artifact (repeatable)",
    )
    ap.add_argument(
        "--refresh", action="store_true", help="refresh the feeds cache first (network)"
    )
    ap.add_argument("--max-age-hours", type=float, default=24.0)
    ap.add_argument("--repo-graph", type=Path, default=None)
    ap.add_argument(
        "--workloads",
        type=Path,
        default=None,
        help="JSON list of repo labels running in an "
        "authorized lab cluster (validate-core-ocp "
        "inventory) — upgrades deployment to yes/no",
    )
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)

    core = load_core(args.config_home)
    results_root = analysis_results_dir(core)
    if args.repo_graph is None:
        args.repo_graph = results_root / "graph" / "repo-graph.json"
    core = load_core(args.config_home)
    core.register_feeds(registry_path())
    exposure = core.services().exposure
    if args.refresh:
        for feed in exposure.refresh_feeds():
            print(f"  {feed.name}: {feed.last_error or 'refreshed'}")
    docs = []
    for path in args.inputs:
        try:
            docs.append((path, json.loads(path.read_text(encoding="utf-8"))))
        except (OSError, json.JSONDecodeError) as e:
            print(f"[!] skipping {path}: {e}", file=sys.stderr)
    cves = sorted({c for _, doc in docs for c in CVE_RX.findall(json.dumps(doc))})
    try:
        signals = exposure.exploit_signals([AdvisoryIdentifier(c) for c in cves])
    except NotFoundError as e:
        print(f"ERROR: feeds unusable ({e}) — run `traust feeds fetch` first", file=sys.stderr)
        return 1
    epss = {
        s.identifier: {"epss": s.epss, "percentile": s.epss_percentile}
        for s in signals
        if s.epss is not None
    }
    kev = {
        s.identifier: {
            "date_added": s.kev_added and s.kev_added.isoformat(),
            "ransomware": s.kev_ransomware,
        }
        for s in signals
        if s.kev_ransomware is not None
    }
    now = datetime.datetime.now(datetime.UTC)
    max_age = datetime.timedelta(hours=args.max_age_hours)
    status = {
        f.name: {
            "retrieved_at": f.fetched_at and f.fetched_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "max_age_hours": args.max_age_hours,
            "stale": f.fetched_at is None or now - f.fetched_at > max_age,
        }
        for f in exposure.feed_statuses()
    }

    graph = {}
    if args.repo_graph.is_file():
        try:
            graph = load_repo_graph(args.repo_graph)
        except (OSError, json.JSONDecodeError) as e:
            print(f"[!] repo-graph unavailable ({e}); no reachability context", file=sys.stderr)
    workloads = None
    if args.workloads:
        workloads = set(json.loads(args.workloads.read_text(encoding="utf-8")))

    sources, totals = [], {"items_with_cves": 0, "kev_hits": 0}
    for path, doc in docs:
        kind, items = items_of(doc)
        enriched = enrich_items(items, epss, kev)
        label = repo_label(doc)
        g = graph.get(label) if label else None
        reach = {
            "repo": label,
            "in_repo_graph": g is not None,
            "products_shipping": sorted((g or {}).get("products") or []),
            "owner_team": (g or {}).get("owner"),
            "deployed": ((label in workloads) if (workloads is not None and label) else "unknown"),
        }
        sources.append(
            {
                "source": str(path),
                "kind": kind,
                "items_scanned": len(items),
                "repository_reach": reach,
                "items": enriched,
            }
        )
        totals["items_with_cves"] += len(enriched)
        totals["kev_hits"] += sum(1 for i in enriched if i["kev_any"])

    doc = {
        "metadata": {
            "artifact": "cve-exploitation-enrichment",
            "role": (
                "enrichment tagger — joins exploitation evidence "
                "(EPSS, KEV) and deployment reachability onto "
                "CVE-bearing items to route prioritization; never "
                "a severity change, finding, or verdict. "
                "Attribution: EPSS at https://www.first.org/epss; "
                "KEV is CC0-1.0."
            ),
            "harness_version": harness_version(),
            "feeds": status,
            "generated_at": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "summary": totals,
        "sources": sources,
    }
    out = args.out or Path.cwd() / "cve-enrichment.json"
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}")
    print(f"  {totals['items_with_cves']} CVE-bearing items, {totals['kev_hits']} on KEV")
    return 0


if __name__ == "__main__":
    sys.exit(main())
