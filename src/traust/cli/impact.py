"""``traust impact find|sbom|symbols|analyze``: the impact-analysis skill's doors on traust-core.

find     an advisory as its source states it now: identity, aliases, affected packages and ranges
sbom     a commit's manifest SBOM (CycloneDX / SPDX JSON from syft or osv-scanner)
symbols  the functions the advisory's fix touched: published, or mined from its fix commits
analyze  every commit the advisory reaches (or one): evidence, classification, an `impact`
         assessment each, and a dependency finding for each `affected` commit
"""

from __future__ import annotations

import argparse
import os
import subprocess
import tempfile
import uuid
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from traust_core.v1.context import Context, Services
from traust_core.v1.errors import NotFoundError, ServiceError
from traust_core.v1.models.common import Provenance
from traust_core.v1.models.dependencies import AdvisoryRecord, parse_advisory_identifier
from traust_core.v1.models.values import GitSha, HttpsRepoUrl
from traust_core.v1.models.vocabulary import ImpactClassification, SourceType

from traust.cli._doors import parser, run
from traust.context import load_core
from traust.paths import HARNESS_ROOT
from traust.registry.feeds_config import registry_path

UNDECIDED = (ImpactClassification.INCONCLUSIVE, ImpactClassification.LIKELY_AFFECTED)


def _parser(op: str, about: str) -> argparse.ArgumentParser:
    return parser("impact", op, about)


def _core(config_home: Path | None) -> Context:
    """Core with the feeds registry's sources, so advisories come from `osv`, never from memory."""
    core = load_core(config_home)
    core.register_feeds(registry_path())
    return core


def _advisory(services: Services, identifier: str) -> AdvisoryRecord:
    record = services.exposure.find_advisory(parse_advisory_identifier(identifier))
    if record is None or record.advisory_id is None:
        raise NotFoundError(f"advisory {identifier}: its source doesn't know it; not assessed")
    return record


def find(argv: list[str] | None = None) -> int:
    ap = _parser("find", "Print an advisory as its source states it now, as JSON.")
    ap.add_argument("advisory", help="CVE-/GHSA-/MAL-/PYSEC-/GO-/RUSTSEC-/OSV- id")
    args = ap.parse_args(argv)

    def call() -> str:
        return _advisory(_core(args.config_home).services(), args.advisory).model_dump_json(
            indent=2
        )

    return run(call)


def sbom(argv: list[str] | None = None) -> int:
    ap = _parser("sbom", "Record a commit's manifest SBOM (CycloneDX or SPDX JSON).")
    ap.add_argument("sbom", type=Path, help="the SBOM document")
    ap.add_argument("--repo-url", required=True, help="https URL of the repository")
    ap.add_argument("--sha", required=True, help="the commit the SBOM was read from")
    ap.add_argument("--public", action="store_true", help="the repository is public")
    args = ap.parse_args(argv)

    def call() -> dict:
        core = _core(args.config_home)
        services = core.services()
        url = HttpsRepoUrl.parse(args.repo_url, core.config.forge_hosts)
        repo = services.portfolio.register_repository(url, args.public)
        ref = services.portfolio.register_ref(repo.id, GitSha.parse(args.sha), None, None)
        kept = services.exposure.ingest_sbom(args.sbom.read_bytes(), ref.id)
        return {"repository_ref_id": ref.id, "sbom_id": kept.id}

    return run(call)


def symbols(argv: list[str] | None = None) -> int:
    ap = _parser("symbols", "Print the functions the advisory's fix touched, as JSON.")
    ap.add_argument("advisory")
    args = ap.parse_args(argv)

    def call() -> str:
        services = _core(args.config_home).services()
        record = _advisory(services, args.advisory)
        assert record.advisory_id is not None
        return services.exposure.resolve_symbols(record.advisory_id).model_dump_json(indent=2)

    return run(call)


def analyze(argv: list[str] | None = None) -> int:
    ap = _parser("analyze", "Assess every commit an advisory reaches, or one, and record each.")
    ap.add_argument("advisory")
    ap.add_argument("--repo-url", help="assess only this repository's commit (with --sha)")
    ap.add_argument("--sha", help="the commit to assess (with --repo-url)")
    ap.add_argument(
        "--scan",
        action="store_true",
        help="clone each commit the SBOMs leave undecided and run the analysis tiers on it",
    )
    ap.add_argument(
        "--symbols",
        default="",
        help="comma-separated vulnerable symbols read off the fix diff (join any found)",
    )
    ap.add_argument("--feature-desc", default=None, help="what capability must be in use")
    args = ap.parse_args(argv)
    if bool(args.repo_url) != bool(args.sha):
        ap.error("--repo-url and --sha go together")

    def call() -> dict:
        core = _core(args.config_home)
        services = core.services()
        exposure = services.exposure
        record = _advisory(services, args.advisory)
        advisory_id = record.advisory_id
        assert advisory_id is not None
        if args.repo_url:
            url = HttpsRepoUrl.parse(args.repo_url, core.config.forge_hosts)
            repo = services.portfolio.register_repository(url, False)
            commits = [
                services.portfolio.register_ref(repo.id, GitSha.parse(args.sha), None, None).id
            ]
        else:
            commits = list(
                dict.fromkeys(
                    r.repository_ref_id
                    for r in exposure.affected(advisory_id)
                    if r.repository_ref_id
                )
            )
        version = harness_version()
        judged = [s.strip() for s in args.symbols.split(",") if s.strip()]
        recorded = []
        for ref_id in commits:
            prepared = exposure.prepare(advisory_id, ref_id, judged=judged)
            if args.scan and prepared.evidence.classification() in UNDECIDED:
                with tempfile.TemporaryDirectory(prefix="impact-") as tmp:
                    subject = prepared.subject
                    checkout = clone(subject.repository_url, subject.sha, Path(tmp) / "repo")
                    prepared = exposure.prepare(advisory_id, ref_id, checkout, judged)
            when = datetime.now(UTC)
            source = Provenance(
                run_id=uuid.uuid4(), source=SourceType.IMPACT_REPORT, occurred_at=when
            )
            doc = prepared.document(version, args.feature_desc)
            done = exposure.record(ref_id, doc, source)
            recorded.append((prepared.subject.repository_url, prepared.subject.sha, done))
        return {
            "advisory": record.identifier,
            "commits": len(recorded),
            "classifications": dict(Counter(d.classification.value for *_, d in recorded)),
            "affected": [
                {"repository": url, "sha": sha, "finding_id": d.finding_id}
                for url, sha, d in recorded
                if d.classification == ImpactClassification.AFFECTED
            ],
        }

    return run(call)


def clone(url: str, sha: str, dest: Path) -> Path:
    """The commit itself (not the default branch's head), shallow, https only."""
    dest.mkdir(parents=True)
    env = {**os.environ, "GIT_ALLOW_PROTOCOL": "https", "GIT_TERMINAL_PROMPT": "0"}
    for step in (
        ["git", "init", "-q"],
        ["git", "fetch", "-q", "--depth", "1", "--", url, sha],
        ["git", "checkout", "-q", "FETCH_HEAD"],
    ):
        try:
            subprocess.run(step, cwd=dest, env=env, check=True, capture_output=True, timeout=600)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            detail = getattr(e, "stderr", b"") or b""
            raise ServiceError(f"cannot check out {url}@{sha}: {detail.decode()[-200:]}") from e
    return dest


def harness_version() -> str:
    """`<VERSION>-<short sha>` of this harness, as the impact artifact records it."""
    version = (HARNESS_ROOT / "VERSION").read_text().strip()
    sha = subprocess.run(
        ["git", "-C", str(HARNESS_ROOT), "rev-parse", "--short", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    return f"{version}-{sha}" if sha else version
