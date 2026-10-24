"""``traust compliance …`` — posture dashboard; boundary doors on traust-core."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from traust_contracts import DeploymentConfigMissing

from traust.cli.groups._registry import OpSpec, passthrough_op


def add_dashboard_args(ap) -> None:
    ap.add_argument("--assessments", type=Path, default=None)
    ap.add_argument("--out-dir", type=Path, default=None)
    ap.add_argument("--findings-db", type=Path, default=None)
    ap.add_argument("--results-root", type=Path, default=None)


def call_dashboard(engine, args) -> int:
    compliance = engine.compliance
    doc = compliance.build(
        assessments_dir=args.assessments,
        findings_db=args.findings_db,
        results_root=args.results_root,
    )
    out_dir = args.out_dir
    if out_dir is None:
        try:
            out_dir = compliance.dashboard_out_dir()
        except DeploymentConfigMissing:
            print(
                "--out-dir required when metrics root is not configured",
                file=sys.stderr,
            )
            return 2
    out_dir.mkdir(parents=True, exist_ok=True)

    hist_p = out_dir / "compliance-history.jsonl"
    history = []
    if hist_p.is_file():
        history = [json.loads(x) for x in hist_p.read_text(encoding="utf-8").splitlines() if x]
    snap = {
        "generated_at": doc["metadata"]["generated_at"],
        "targets": doc["metadata"]["targets"],
        "not_satisfied_total": sum(len(t["not_satisfied"]) for t in doc["targets"]),
        "not_assessed_total": sum(
            cov["not_assessed"] for t in doc["targets"] for cov in t["coverage"].values()
        ),
    }
    history.append(snap)
    with hist_p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(snap) + "\n")

    (out_dir / "compliance-dashboard.json").write_text(
        json.dumps(doc, indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "compliance-dashboard.md").write_text(
        compliance.render_md(doc, history), encoding="utf-8"
    )
    print(
        f"wrote {out_dir}/compliance-dashboard.{{json,md}} "
        f"({doc['metadata']['targets']} target(s); history "
        f"{len(history)} snapshot(s))"
    )
    return 0


DASHBOARD = OpSpec(
    add_args=add_dashboard_args,
    call=call_dashboard,
    help="Aggregate compliance assessments into a posture dashboard",
)


DECLARE = passthrough_op("compliance", "Record one compliance boundary declaration.", "declare")
SCOPES = passthrough_op("compliance", "The current declaration of each boundary.", "scopes")
RESOLVE = passthrough_op("compliance", "A boundary's repositories now.", "resolve")
