"""``traust triage intake|prepare|record|render``: the triage skill's doors on traust-core.

intake   third-party scanner output (SARIF, Dependabot, govulncheck) as an assessment of a commit
prepare  everything a triage of one assessment judges (findings, locations, precedents), as JSON
record   a validated triage: decisions per verdict, review items where a person must look
render   a triage as Markdown, a projection of the JSON
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from traust_core.v1.errors import TraustError
from traust_core.v1.models.artifacts import TriageArtifact
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.findings import CandidateFormat
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import FindingOrigin, SourceType

from traust.context import add_config_home_arg, load_core


def _parser(op: str, about: str) -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog=f"traust triage {op}", description=about)
    add_config_home_arg(ap)
    return ap


def _run(call: Callable[[], object]) -> int:
    """Print the door's result as JSON; a refused input is exit 2 with its reason."""
    try:
        out = call()
    except (OSError, TraustError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    if out is not None:
        print(out if isinstance(out, str) else json.dumps(out, indent=2, default=str))
    return 0


def intake(argv: list[str] | None = None) -> int:
    ap = _parser("intake", "Record third-party scanner output as an assessment of a commit.")
    ap.add_argument("scan", type=Path, help="the scanner output file")
    ap.add_argument("--format", required=True, choices=[f.value for f in CandidateFormat])
    ap.add_argument("--repo-url", required=True, help="https URL of the scanned repository")
    ap.add_argument("--sha", required=True, help="the scanned commit")
    ap.add_argument("--public", action="store_true", help="the repository is public")
    ap.add_argument(
        "--origin",
        required=True,
        choices=[o.value for o in FindingOrigin],
        help="the skill that produced the scan",
    )
    args = ap.parse_args(argv)

    def call() -> dict:
        core = load_core(args.config_home)
        services = core.services()
        url = HttpsRepoUrl.parse(args.repo_url, core.config.forge_hosts)
        repo = services.portfolio.register_repository(url, args.public)
        ref = services.portfolio.register_ref(repo.id, GitSha.parse(args.sha), None, None)
        when = datetime.now(UTC)
        assessment, taken = services.assessment.record_scan(
            ref.id,
            args.scan.read_bytes(),
            CandidateFormat(args.format),
            FindingOrigin(args.origin),
            Provenance(run_id=uuid.uuid4(), source=SourceType.VULN_SCAN_REPORT, occurred_at=when),
        )
        found, new = len(taken.findings), len(taken.created)
        return {"assessment_id": assessment.id, "findings": found, "new": new}

    return _run(call)


def prepare(argv: list[str] | None = None) -> int:
    ap = _parser("prepare", "Print the triage input for one assessment as JSON.")
    ap.add_argument("assessment_id", type=uuid.UUID)
    ap.add_argument("-o", "--out", type=Path, help="write the JSON here instead of stdout")
    args = ap.parse_args(argv)

    def call() -> str | None:
        decisions = load_core(args.config_home).services().findings.decisions
        prepared = decisions.prepare(args.assessment_id)
        text = prepared.model_dump_json(indent=2)
        if args.out is None:
            return text
        args.out.write_text(text + "\n", encoding="utf-8")
        return None

    return _run(call)


def record(argv: list[str] | None = None) -> int:
    ap = _parser("record", "Record a validated triage of one assessment.")
    ap.add_argument("assessment_id", type=uuid.UUID)
    ap.add_argument("triage", type=Path, help="the validated triage JSON")
    ap.add_argument("--repo", type=Path, required=True, help="target repo checkout (read-only)")
    args = ap.parse_args(argv)

    def call() -> dict:
        doc = TriageArtifact.parse(args.triage.read_bytes())
        when = datetime.now(UTC)
        made = (
            load_core(args.config_home)
            .services()
            .findings.decisions.record(
                args.assessment_id,
                doc,
                Provenance(run_id=uuid.uuid4(), source=SourceType.TRIAGE_REPORT, occurred_at=when),
                args.repo,
            )
        )
        return {
            "decisions": len(made),
            "awaiting_countersign": sum(
                d.validity == "false_positive" and not d.auto_accept_tier for d in made
            ),
            "auto_accepted": sum(d.auto_accept_tier for d in made),
        }

    return _run(call)


def render(argv: list[str] | None = None) -> int:
    ap = _parser("render", "Render a validated triage JSON as Markdown.")
    ap.add_argument("triage", type=Path)
    ap.add_argument("-o", "--out", type=Path, help="write the Markdown here instead of stdout")
    args = ap.parse_args(argv)

    def call() -> str | None:
        doc = TriageArtifact.parse(args.triage.read_bytes())
        markdown = load_core(args.config_home).services().findings.decisions.render(doc).decode()
        if args.out is None:
            return markdown
        args.out.write_text(markdown, encoding="utf-8")
        return None

    return _run(call)
