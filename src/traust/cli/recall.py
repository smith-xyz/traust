"""``traust sweep benchmark-targets|build-canaries|screen-injection``: recall-benchmark's doors on
traust-core.

benchmark-targets  record the benchmark-targets manifest (YAML or JSON) as a new answer-key
                   version; the newest is the one scored. Duplicate target ids and held-out seeded
                   targets are refused
build-canaries     commit every canary (or seeded-fixture) source into a deterministic local repo
                   (traust-engine's materialiser) and record them as targets of a new version
screen-injection   screen recorded audit reports for the shape of obeyed prompt injection; every
                   signal is a human review item, never a verdict. Exit 1 when any is flagged
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import yaml
from traust_core.v1.models.artifacts import BenchmarkTargetArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.vocabulary import SourceType

from traust.cli._doors import parser, run
from traust.context import load


def targets(argv: list[str] | None = None) -> int:
    ap = parser("sweep", "benchmark-targets", "Record the recall benchmark's answer key.")
    ap.add_argument("manifest", type=Path, help="benchmark-targets.yaml (the answer key)")
    args = ap.parse_args(argv)

    def call() -> dict:
        # YAML dates load as date objects; the schema wants their ISO strings
        raw = json.loads(json.dumps(yaml.safe_load(args.manifest.read_text()), default=str))
        doc = BenchmarkTargetArtifact.from_document(raw)
        result = load(args.config_home).services().detection_quality.record(doc, _provenance())
        return {"artifact_id": result.artifact_id, "version": raw.get("version")}

    return run(call)


def canaries(argv: list[str] | None = None) -> int:
    ap = parser("sweep", "build-canaries", "Materialise canaries and record them as targets.")
    ap.add_argument(
        "--seeded",
        action="store_true",
        help="the seeded fixtures (recall-benchmark/seeded) instead of the canaries",
    )
    args = ap.parse_args(argv)

    def call() -> list[dict]:
        core = load(args.config_home, canaries="seeded" if args.seeded else "canaries")
        built = core.services().detection_quality.build_canaries(_provenance())
        return [
            {"target_id": c.target_id, "repo_url": c.repo.repo_url, "sha": c.repo.sha}
            for c in built
        ]

    return run(call)


def screen(argv: list[str] | None = None) -> int:
    ap = parser("sweep", "screen-injection", "Screen recorded audit reports for prompt injection.")
    ap.add_argument("artifact", nargs="+", type=uuid.UUID, help="a recorded audit report's id")
    args = ap.parse_args(argv)
    flagged = False

    def call() -> dict:
        nonlocal flagged
        quality = load(args.config_home).services().detection_quality
        screens = [quality.screen_injection(a) for a in args.artifact]
        flagged = any(s.flagged for s in screens)
        return {
            "screened": len(screens),
            "flagged": [s.model_dump(mode="json") for s in screens if s.flagged],
        }

    rc = run(call)
    return 1 if rc == 0 and flagged else rc


def _provenance() -> Provenance:
    return Provenance(
        run_id=uuid.uuid4(), source=SourceType.INTERACTIVE, occurred_at=datetime.now(UTC)
    )
