"""``traust sweep benchmark-targets``: recall-benchmark's answer-key door on traust-core.

Records the benchmark-targets manifest (YAML or JSON) as a new version of the answer key; the
newest version is the one scored. Duplicate target ids and held-out seeded targets are refused.
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
from traust.context import load_services


def targets(argv: list[str] | None = None) -> int:
    ap = parser("sweep", "benchmark-targets", "Record the recall benchmark's answer key.")
    ap.add_argument("manifest", type=Path, help="benchmark-targets.yaml (the answer key)")
    args = ap.parse_args(argv)

    def call() -> dict:
        # YAML dates load as date objects; the schema wants their ISO strings
        raw = json.loads(json.dumps(yaml.safe_load(args.manifest.read_text()), default=str))
        doc = BenchmarkTargetArtifact.from_document(raw)
        source = Provenance(
            run_id=uuid.uuid4(), source=SourceType.INTERACTIVE, occurred_at=datetime.now(UTC)
        )
        result = load_services(args.config_home).detection_quality.record(doc, source)
        return {"artifact_id": result.artifact_id, "version": raw.get("version")}

    return run(call)
