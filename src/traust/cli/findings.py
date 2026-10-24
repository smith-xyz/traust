"""``traust findings …``: track-findings' doors on traust-core.

find      the finding a report entry is (its label, e.g. OPERATOR-abcdef0-001), by fingerprint
status    one finding now: disposition (evidence precedence), effective severity, SLA due
history   every decision on a finding, in judgement order
baseline  a repository's findings as they stood at a time
decide    record your statement on a finding (needs `traust auth`)
import    what people said in an MR / PR / commit / Jira ticket: recorded if it stands, else queued
queue     statements waiting for a person, re-read from their source
confirm   a queued statement, as your decision; reject: close it, recording nothing
refuted   a repository's false positives (the refuted register)
surfaces  review-surface coverage (the audit, with later scans merged)
sarif     a repository's findings as SARIF for code scanning
tickets   the Jira tickets on a repository's findings
summary   a repository's findings counted by state per group (severity, CWE, label, …)
timeline  a repository's findings replayed by day, week or month (open, new, resolved, MTTR, risk)
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from traust_core.v1.context import Context
from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.attestation import AttestationDecision
from traust_core.v1.models.common import PageRequest, TimeBucket
from traust_core.v1.models.findings import (
    FindingDimension,
    FindingFilter,
    RecordDecision,
    ReviewFilter,
)
from traust_core.v1.models.integrity import FingerprintInput
from traust_core.v1.models.inventory import Repository
from traust_core.v1.models.remediation import ExternalRef
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import (
    DispositionResolution,
    EvidenceGrade,
    Severity,
    SourceType,
    Validity,
)
from traust_core.v1.providers.comments import FORGE, JIRA
from traust_core.v1.services.insight import SarifExport

from traust.cli._doors import parser, run, when
from traust.context import load_caller, load_core

_JIRA_KEY = re.compile(r"^[A-Z][A-Z0-9]+-\d+$")
_BROWSE = re.compile(r"/browse/([A-Z][A-Z0-9]+-\d+)")

# What a person states directly; machine reports record through their own skill's doors.
STATEMENT_SOURCES = (
    SourceType.INTERACTIVE,
    SourceType.MR_COMMENT,
    SourceType.COMMIT,
    SourceType.JIRA,
)


def _repository(core: Context, url: str) -> Repository:
    found = core.services().portfolio.find_repository(
        HttpsRepoUrl.parse(url, core.config.forge_hosts)
    )
    if found is None:
        raise NotFoundError(f"repository {url} is not registered")
    return found


def _json(model: Any) -> Any:
    return model.model_dump(mode="json")


def find(argv: list[str] | None = None) -> int:
    ap = parser("findings", "find", "Find the recorded finding a report entry is.")
    ap.add_argument("report", type=Path, help="the report JSON the label comes from")
    ap.add_argument("--label", required=True, help="the entry's id in that report")
    ap.add_argument("--repo-url", required=True, help="https URL of the audited repository")
    args = ap.parse_args(argv)

    def call() -> dict[str, Any]:
        core = load_core(args.config_home)
        entries = json.loads(args.report.read_text(encoding="utf-8")).get("findings") or []
        entry = next((e for e in entries if e.get("id") == args.label), None)
        if entry is None:
            raise NotFoundError(f"{args.report}: no finding {args.label}")
        repo = _repository(core, args.repo_url)
        assert repo.id is not None
        reported = FingerprintInput.from_report(entry, repo.url)
        found = core.services().findings.intake.match(repo.id, reported)
        return {"label": args.label, "finding_id": found}

    return run(call)


def status(argv: list[str] | None = None) -> int:
    ap = parser("findings", "status", "Show one finding's current state.")
    ap.add_argument("finding_id", type=uuid.UUID)
    args = ap.parse_args(argv)
    return run(lambda: _json(load_core(args.config_home).services().findings.get(args.finding_id)))


def history(argv: list[str] | None = None) -> int:
    ap = parser("findings", "history", "List every decision on a finding.")
    ap.add_argument("finding_id", type=uuid.UUID)
    args = ap.parse_args(argv)

    def call() -> list[Any]:
        return [
            _json(d)
            for d in load_core(args.config_home).services().findings.history(args.finding_id)
        ]

    return run(call)


def baseline(argv: list[str] | None = None) -> int:
    ap = parser("findings", "baseline", "List a repository's findings as they stood at a time.")
    ap.add_argument("--repo-url", required=True)
    ap.add_argument("--as-of", help="ISO time with a zone (default: now)")
    args = ap.parse_args(argv)

    def call() -> list[Any]:
        core = load_core(args.config_home)
        repo = _repository(core, args.repo_url)
        assert repo.id is not None
        as_of = when(args.as_of) or datetime.now(UTC)
        return [_json(v) for v in core.services().findings.baseline(repo.id, as_of)]

    return run(call)


def _statement_args(ap: Any) -> None:
    ap.add_argument("--rationale", required=True, help="why, in your words (quoted verbatim)")
    ap.add_argument("--validity", choices=[v.value for v in Validity])
    ap.add_argument("--resolution", choices=[r.value for r in DispositionResolution])
    ap.add_argument("--severity", choices=[s.value for s in Severity], help="a re-rating")
    ap.add_argument("--evidence-grade", choices=[g.value for g in EvidenceGrade])
    ap.add_argument("--reason")
    ap.add_argument(
        "--source",
        default=SourceType.INTERACTIVE.value,
        choices=[s.value for s in STATEMENT_SOURCES],
        help="where it was said (default: interactive)",
    )
    ap.add_argument("--occurred-at", help="when it was said, ISO with a zone (default: now)")


def _statement(args: Any, finding_id: uuid.UUID) -> RecordDecision:
    if not (args.validity or args.resolution or args.severity):
        raise ValidationError("say something: --validity, --resolution or --severity")
    return RecordDecision(
        finding_id=finding_id,
        rationale=args.rationale,
        validity=args.validity,
        resolution=args.resolution,
        severity=args.severity,
        evidence_grade=args.evidence_grade,
        reason=args.reason,
        source_channel=SourceType(args.source),
        occurred_at=when(args.occurred_at),
    )


def _labels(core: Context, repo: Repository, reports: list[Path]) -> dict[str, uuid.UUID]:
    """Each report's labels (`findings[].id`) to the findings they are, by fingerprint."""
    assert repo.id is not None
    intake = core.services().findings.intake
    out: dict[str, uuid.UUID] = {}
    for report in reports:
        for entry in json.loads(report.read_text(encoding="utf-8")).get("findings") or []:
            label = entry.get("id")
            if isinstance(label, str) and entry.get("locations"):
                found = intake.match(repo.id, FingerprintInput.from_report(entry, repo.url))
                if found is not None:
                    out[label] = found
    return out


def _reports_and_repo(ap: Any) -> None:
    ap.add_argument("--repo-url", required=True, help="https URL of the audited repository")
    ap.add_argument(
        "--report",
        type=Path,
        action="append",
        default=[],
        help="a report whose labels the comments use (repeatable)",
    )


def decide(argv: list[str] | None = None) -> int:
    ap = parser("findings", "decide", "Record your statement on a finding.")
    ap.add_argument("finding_id", type=uuid.UUID)
    _statement_args(ap)
    args = ap.parse_args(argv)

    def call() -> Any:
        statement = _statement(args, args.finding_id)
        core = load_core(args.config_home)
        return _json(core.services().findings.decisions.decide(statement, load_caller(core)))

    return run(call)


def import_(argv: list[str] | None = None) -> int:
    ap = parser("findings", "import", "Record what people said in an MR, PR, commit or ticket.")
    ap.add_argument("ref", help="an MR / PR / commit URL, or a Jira key")
    _reports_and_repo(ap)
    args = ap.parse_args(argv)

    def call() -> dict[str, Any]:
        core = load_core(args.config_home)
        repo = _repository(core, args.repo_url)
        source = JIRA if _JIRA_KEY.match(args.ref) else FORGE
        report = core.services().attestation.import_statements(
            source,
            ExternalRef(system=source, ref=args.ref),
            _labels(core, repo, args.report),
            load_caller(core),
        )
        return {
            "recorded": [_json(d) for d in report.recorded],
            "queued": [_json(i) for i in report.queued],
            "unmatched": [
                {"label": s.label, "author": s.author, "url": s.url} for s in report.unmatched
            ],
            "already_imported": report.already_imported,
        }

    return run(call)


def queue(argv: list[str] | None = None) -> int:
    ap = parser("findings", "queue", "List statements waiting for a person, re-read from source.")
    ap.add_argument("--repo-url", help="with --report: re-read each item's statements")
    ap.add_argument("--report", type=Path, action="append", default=[])
    ap.add_argument("--limit", type=int, default=100)
    args = ap.parse_args(argv)

    def call() -> list[dict[str, Any]]:
        core = load_core(args.config_home)
        attestation = core.services().attestation
        names: dict[str, uuid.UUID] = {}
        if args.repo_url:
            names = _labels(core, _repository(core, args.repo_url), args.report)
        out = []
        for item in attestation.pending(ReviewFilter(), PageRequest(limit=args.limit)).items:
            assert item.id is not None
            out.append(
                {
                    **_json(item),
                    "sources": [s.ref for s in attestation.sources(item.finding_id)],
                    "said": [_json(s) for s in attestation.statements(item.id, names)]
                    if names
                    else [],
                }
            )
        return out

    return run(call)


def confirm(argv: list[str] | None = None) -> int:
    ap = parser("findings", "confirm", "Confirm a queued statement as your own decision.")
    ap.add_argument("item_id", type=uuid.UUID)
    ap.add_argument("finding_id", type=uuid.UUID, help="the item's finding (from `queue`)")
    _statement_args(ap)
    args = ap.parse_args(argv)

    def call() -> Any:
        statement = _statement(args, args.finding_id)
        core = load_core(args.config_home)
        caller = load_caller(core)
        attestation = core.services().attestation
        answer = AttestationDecision.CONFIRM
        return _json(attestation.attest(args.item_id, caller, answer, statement))

    return run(call)


def reject(argv: list[str] | None = None) -> int:
    ap = parser("findings", "reject", "Close a queued statement without recording anything.")
    ap.add_argument("item_id", type=uuid.UUID)
    args = ap.parse_args(argv)

    def call() -> Any:
        core = load_core(args.config_home)
        attestation = core.services().attestation
        caller = load_caller(core)
        return _json(attestation.attest(args.item_id, caller, AttestationDecision.REJECT, None))

    return run(call)


def refuted(argv: list[str] | None = None) -> int:
    ap = parser("findings", "refuted", "List a repository's false positives (refuted register).")
    ap.add_argument("--repo-url", required=True)
    args = ap.parse_args(argv)

    def call() -> list[Any]:
        core = load_core(args.config_home)
        repo = _repository(core, args.repo_url)
        assert repo.id is not None
        wanted = FindingFilter(repository_id=repo.id, validity=Validity.FALSE_POSITIVE)
        out, page = [], PageRequest()
        while True:
            got = core.services().findings.list(wanted, page)
            out += [_json(v) for v in got.items]
            if got.next is None:
                return out
            page = PageRequest(cursor=got.next)

    return run(call)


def surfaces(argv: list[str] | None = None) -> int:
    ap = parser("findings", "surfaces", "Review-surface coverage: the audit plus later scans.")
    ap.add_argument("--repo-url", required=True)
    ap.add_argument("--as-of", help="ISO time with a zone (default: now)")
    args = ap.parse_args(argv)

    def call() -> dict[str, Any]:
        core = load_core(args.config_home)
        repo = _repository(core, args.repo_url)
        assert repo.id is not None
        merged = core.services().findings.review_surfaces(repo.id, when(args.as_of))
        return {surface: _json(c) for surface, c in merged.items()}

    return run(call)


def sarif(argv: list[str] | None = None) -> int:
    ap = parser("findings", "sarif", "Export a repository's findings as SARIF (code scanning).")
    ap.add_argument("--repo-url", required=True)
    ap.add_argument("--as-of", help="ISO time with a zone (default: now)")
    ap.add_argument("-o", "--out", type=Path, help="write here instead of stdout")
    args = ap.parse_args(argv)

    def call() -> Any:
        core = load_core(args.config_home)
        repo = _repository(core, args.repo_url)
        assert repo.id is not None
        views = core.services().findings.baseline(repo.id, when(args.as_of) or datetime.now(UTC))
        doc = SarifExport().document(views, repo.url)
        if args.out is None:
            return doc
        args.out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        return None

    return run(call)


def tickets(argv: list[str] | None = None) -> int:
    ap = parser("findings", "tickets", "The Jira tickets filed against a repository's findings.")
    ap.add_argument("--repo-url", required=True)
    args = ap.parse_args(argv)

    def call() -> list[str]:
        core = load_core(args.config_home)
        repo = _repository(core, args.repo_url)
        assert repo.id is not None
        found = (_BROWSE.search(t.ref) for t in core.services().attestation.tickets(repo.id))
        return sorted({m[1] for m in found if m})

    return run(call)


def _filter_args(ap: Any) -> None:
    ap.add_argument("--repo-url", required=True)
    ap.add_argument("--as-of", help="ISO time with a zone (default: now)")
    ap.add_argument("--validity", choices=[v.value for v in Validity])
    state = ap.add_mutually_exclusive_group()
    state.add_argument("--open", dest="open", action="store_const", const=True)
    state.add_argument("--closed", dest="open", action="store_const", const=False)


def _filter(core: Context, args: Any) -> FindingFilter:
    repo = _repository(core, args.repo_url)
    assert repo.id is not None
    return FindingFilter(
        repository_id=repo.id,
        validity=args.validity,
        open=args.open,
        as_of=when(args.as_of) or datetime.now(UTC),
    )


def summary(argv: list[str] | None = None) -> int:
    ap = parser("findings", "summary", "Count a repository's findings by state per group.")
    _filter_args(ap)
    ap.add_argument("--group-by", required=True, choices=[d.value for d in FindingDimension])
    args = ap.parse_args(argv)

    def call() -> list[Any]:
        core = load_core(args.config_home)
        group_by = FindingDimension(args.group_by)
        return [_json(r) for r in core.services().findings.summary(_filter(core, args), group_by)]

    return run(call)


def timeline(argv: list[str] | None = None) -> int:
    ap = parser("findings", "timeline", "Replay a repository's findings bucket by bucket.")
    _filter_args(ap)
    ap.add_argument(
        "--bucket", default=TimeBucket.WEEK.value, choices=[b.value for b in TimeBucket]
    )
    args = ap.parse_args(argv)

    def call() -> list[Any]:
        core = load_core(args.config_home)
        bucket = TimeBucket(args.bucket)
        return [_json(p) for p in core.services().findings.timeline(_filter(core, args), bucket)]

    return run(call)
