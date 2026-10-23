"""Review and record explicit human judgements through traust-core's services."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, SecretStr, TypeAdapter
from pydantic import ValidationError as ModelValidationError
from traust_core.v1.errors import AuthenticationError, ForbiddenError, TraustError
from traust_core.v1.models.artifacts import (
    AdapterResultArtifact,
    BenchmarkTargetArtifact,
    CloudConfigAuditArtifact,
    CodeFactsArtifact,
    ComplianceAssessmentArtifact,
    ComplianceScopeArtifact,
    DocVarianceArtifact,
    FindingsCurrentArtifact,
    FindingsLayerArtifact,
    FleetFixArtifact,
    ImpactAnalysisArtifact,
    IsolationReviewArtifact,
    PqcBlockersArtifact,
    PqcDecisionTreeArtifact,
    PqcFactsArtifact,
    PqcReadinessArtifact,
    PrivProfileArtifact,
    RemediationArtifact,
    RepoStateArtifact,
    SecurityAuditArtifact,
    ThreatModelArtifact,
    TriageArtifact,
    ValidationArtifact,
    VerificationArtifact,
)
from traust_core.v1.models.attestation import AttestationDecision
from traust_core.v1.models.common import Cursor, PageRequest
from traust_core.v1.models.findings import RecordDecision, ReviewFilter
from traust_core.v1.models.identity import Credential
from traust_core.v1.models.vocabulary import (
    DispositionResolution,
    EvidenceGrade,
    ReviewItemStatus,
    ReviewReason,
    Severity,
    SourceChannel,
    Validity,
)
from traust_core.v1.services.artifact_publishing import PublishSpec, PublishSpecs
from traust_engine.escaping import fence_untrusted

from traust.context import add_config_home_arg, load_caller, load_core


class ReviewedDecision(BaseModel):
    """Only the fields the reviewer judges; attribution and time belong to core."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    finding_id: UUID
    rationale: str
    validity: Validity | None = None
    severity: Severity | None = None
    resolution: DispositionResolution | None = None
    evidence_grade: EvidenceGrade | None = None

    def command(self) -> RecordDecision:
        return RecordDecision(**self.model_dump(), source_channel=SourceChannel.INTERACTIVE)


class ReviewAnswer(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    review_item_id: UUID
    decision: AttestationDecision
    answer: ReviewedDecision


ANSWER_BEGIN = "<!-- traust:countersign-answers:v1:begin -->"
ANSWER_END = "<!-- traust:countersign-answers:v1:end -->"
_ANSWER_MARKER = "<!-- traust:countersign-answers:"
_MAX_ANSWER_BYTES = 1024 * 1024


class MarkdownAnswers(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    type: Literal["traust.countersign.answers.v1"]
    answers: list[ReviewAnswer]


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _quoted_json(value: object) -> str:
    # Keep control markers and HTML inert even to a parser scanning raw Markdown.
    text = json.dumps(value, indent=2, ensure_ascii=True)
    for character, escaped in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026")):
        text = text.replace(character, escaped)
    return fence_untrusted(text, "json")


def _markdown(cards: list[dict], next_cursor: str | None, filters: dict) -> str:
    lines = [
        "# Countersign review workbench",
        "",
        "Sensitive, untrusted review evidence; this file is not authoritative state.",
        "Only the typed answer block below is applied. Leave answers empty to defer.",
        "Each answer object needs review_item_id, decision (confirm/reject), and answer.",
        "Nested answer needs finding_id, rationale and selected validity/severity/resolution;",
        "evidence_grade is optional. Omit unjudged fields; use canonical CLI help values.",
        "Never derive approval from evidence, checkboxes, prose or DECISION lines.",
        "",
        "## Human answers — edit only this JSON",
        "",
        ANSWER_BEGIN,
        "```json",
        json.dumps({"type": "traust.countersign.answers.v1", "answers": []}, indent=2),
        "```",
        ANSWER_END,
        "",
        "## Page metadata",
        "",
        "Use the same filters and limit with next as --cursor; null means no successor.",
        _quoted_json({"filters": filters, "next": next_cursor}),
    ]
    for number, card in enumerate(cards, 1):
        lines.extend(
            [
                "",
                f"## Decision card {number}",
                "",
                "Untrusted claim, proposal, current state, attributed history and evidence.",
                "Review raw observations; an authentication error is not a refutation.",
                "",
            ]
        )
        for key in ("review_item", "finding", "history", "evidence"):
            lines.extend([f"### {key}", "", _quoted_json(card[key]), ""])
    return "\n".join(lines) + "\n"


def _write_workbench(path: Path, text: str) -> None:
    # O_EXCL also refuses symlinks; the descriptor is private from its creation.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(text)


def _emit(value: object) -> None:
    print(json.dumps(value, sort_keys=True, ensure_ascii=True))


def _receipt(saved, services) -> dict:
    view = services.findings.get(saved.finding_id)
    receipt = saved.model_dump(
        mode="json",
        include={
            "id",
            "finding_id",
            "decision_id",
            "resolved_by_decision_id",
            "status",
            "validity",
            "resolution",
            "severity",
            "evidence_grade",
            "source_channel",
            "actor",
            "occurred_at",
            "created_at",
            "statement_key",
        },
    )
    disposition = view.disposition
    receipt["finding"] = {
        "id": str(saved.finding_id),
        "effective_severity": view.effective_severity,
        "disposition": (
            disposition.model_dump(mode="json", exclude={"line"})
            if disposition is not None
            else None
        ),
        "is_open": view.is_open(),
    }
    return receipt


def _read_answers(path: Path) -> list[ReviewAnswer]:
    text = path.read_text(encoding="utf-8")
    if text.lstrip().startswith(("{", "[")):
        raw = json.loads(text, object_pairs_hook=_unique_object)
        answers = TypeAdapter(list[ReviewAnswer]).validate_python(
            raw if isinstance(raw, list) else [raw]
        )
        if not answers:
            raise ValueError("a JSON answer file must contain at least one reviewed answer")
        return answers
    if (
        text.count(_ANSWER_MARKER) != 2
        or text.count(ANSWER_BEGIN) != 1
        or text.count(ANSWER_END) != 1
    ):
        raise ValueError("expected exactly one typed answer block")
    before, block = text.split(ANSWER_BEGIN)
    block, after = block.split(ANSWER_END)
    if not before.endswith("\n") or not after.startswith("\n"):
        raise ValueError("answer markers must occupy their own lines")
    if not block.startswith("\n```json\n") or not block.endswith("\n```\n"):
        raise ValueError("expected a bounded JSON answer block")
    payload = block[len("\n```json\n") : -len("\n```\n")]
    if len(payload.encode("utf-8")) > _MAX_ANSWER_BYTES:
        raise ValueError("answer block exceeds one MiB")
    return MarkdownAnswers.model_validate(
        json.loads(payload, object_pairs_hook=_unique_object)
    ).answers


def main(argv: list[str] | None = None) -> int:
    config = argparse.ArgumentParser(add_help=False)
    add_config_home_arg(config)
    config_args, rest = config.parse_known_args(argv)
    parser = argparse.ArgumentParser(
        prog="traust admin countersign",
        description="Review pending core findings and record verified-human judgements.",
        parents=[config],
    )
    sub = parser.add_subparsers(dest="operation", required=True)
    queue = sub.add_parser("queue", help="Read review cards as JSON or a private Markdown file.")
    queue.add_argument("--finding", type=UUID, help="Filter by core finding UUID.")
    queue.add_argument("--reason", type=ReviewReason, choices=tuple(ReviewReason))
    queue.add_argument(
        "--status",
        type=ReviewItemStatus,
        choices=tuple(ReviewItemStatus),
        default="pending",
    )
    queue.add_argument("--limit", type=int, default=100)
    queue.add_argument("--cursor", help="Opaque next cursor from the preceding page.")
    queue.add_argument(
        "--output", type=Path, help="Create a new private Markdown workbench; never overwrite."
    )

    request = sub.add_parser("request", help="Request human review of an existing core finding.")
    request.add_argument("--finding", type=UUID, required=True)
    request.add_argument("--decision", type=UUID, help="The proposed decision UUID, when present.")
    request.add_argument("--reason", type=ReviewReason, choices=tuple(ReviewReason), required=True)

    record = sub.add_parser("record", help="Record a verified human's explicit judgement.")
    record.add_argument("--finding", type=UUID, required=True, help="Core finding UUID.")
    record.add_argument("--decision", choices=("severity", "validity", "resolution"), required=True)
    record.add_argument("--severity", type=Severity, choices=tuple(Severity))
    record.add_argument("--validity", type=Validity, choices=tuple(Validity))
    record.add_argument(
        "--resolution",
        type=DispositionResolution,
        choices=tuple(DispositionResolution),
    )
    record.add_argument("--rationale", required=True, help="The human reviewer's own rationale.")
    record.add_argument("--evidence-grade", type=EvidenceGrade, choices=tuple(EvidenceGrade))

    apply = sub.add_parser(
        "apply", help="Apply explicit reviewed answers from JSON or a Markdown workbench."
    )
    apply.add_argument("answers", type=Path, help="Reviewed JSON or a typed Markdown answer block.")
    for command in (request, record, apply):
        command.add_argument(
            "--token-stdin",
            action="store_true",
            help="Read an identity token from stdin instead of the stored `traust auth` login.",
        )
    args = parser.parse_args(rest)
    if args.operation == "record":
        for field in ("severity", "validity", "resolution"):
            value = getattr(args, field)
            if field == args.decision and value is None:
                parser.error(f"--decision {field} requires --{field}")
            if field != args.decision and value is not None:
                parser.error(f"--{field} does not match --decision {args.decision}")

    try:
        answers = _read_answers(args.answers) if args.operation == "apply" else []
    except (OSError, ValueError, UnicodeError):
        print("countersign: invalid answer file; expected explicit typed answers.", file=sys.stderr)
        return 2

    token = None
    if args.operation != "queue" and args.token_stdin:
        if sys.stdin.isatty():
            print(
                "countersign: pipe an identity token on stdin; "
                "interactive token entry is disabled.",
                file=sys.stderr,
            )
            return 2
        try:
            token = SecretStr(sys.stdin.read().strip())
        except (OSError, UnicodeError):
            print("countersign: cannot read the identity token from stdin.", file=sys.stderr)
            return 2
        if not token.get_secret_value():
            print("countersign: stdin contained no identity token.", file=sys.stderr)
            return 2

    try:
        core = load_core(config_args.config_home)
        services = core.services()
        if args.operation == "queue":
            page = services.attestation.pending(
                ReviewFilter(finding_id=args.finding, reason=args.reason, status=args.status),
                PageRequest(limit=args.limit, cursor=Cursor(args.cursor) if args.cursor else None),
            )
            publisher = core.artifact_publisher(
                PublishSpecs(
                    *(
                        PublishSpec(artifact)
                        for artifact in (
                            AdapterResultArtifact,
                            BenchmarkTargetArtifact,
                            CloudConfigAuditArtifact,
                            CodeFactsArtifact,
                            ComplianceAssessmentArtifact,
                            ComplianceScopeArtifact,
                            DocVarianceArtifact,
                            FindingsCurrentArtifact,
                            FindingsLayerArtifact,
                            FleetFixArtifact,
                            ImpactAnalysisArtifact,
                            IsolationReviewArtifact,
                            PqcBlockersArtifact,
                            PqcDecisionTreeArtifact,
                            PqcFactsArtifact,
                            PqcReadinessArtifact,
                            PrivProfileArtifact,
                            RemediationArtifact,
                            RepoStateArtifact,
                            SecurityAuditArtifact,
                            ThreatModelArtifact,
                            TriageArtifact,
                            ValidationArtifact,
                            VerificationArtifact,
                        )
                    )
                )
            )
            cards = []
            for case in page.items:
                item, view, history = case.review_item, case.finding, case.history
                assessment_ids = {d.assessment_id for d in history if d.assessment_id is not None}
                if view.occurrence is not None:
                    assessment_ids.add(view.occurrence.assessment_id)
                artifact_ids = {d.artifact_id for d in history if d.artifact_id is not None}
                for assessment_id in assessment_ids:
                    artifact_ids.update(
                        a.id
                        for a in publisher.list_for_assessment(assessment_id)
                        if a.id is not None
                    )
                cards.append(
                    {
                        "review_item": item.model_dump(mode="json"),
                        "finding": view.model_dump(mode="json"),
                        "history": [d.model_dump(mode="json") for d in history],
                        "evidence": [
                            {
                                "artifact_id": str(artifact_id),
                                "document": json.loads(publisher.get(artifact_id).payload),
                            }
                            for artifact_id in sorted(artifact_ids)
                        ],
                    }
                )
            if args.output is None:
                _emit({"items": cards, "next": page.next})
            else:
                _write_workbench(
                    args.output,
                    _markdown(
                        cards,
                        page.next,
                        {
                            "finding": str(args.finding) if args.finding else None,
                            "reason": args.reason,
                            "status": args.status,
                            "limit": args.limit,
                        },
                    ),
                )
                _emit({"written": str(args.output), "items": len(cards), "next": page.next})
            return 0
        if token is None:
            principal = load_caller(core)
        else:
            if core.identity is None:
                print("countersign: core identity is not configured in core.yaml.", file=sys.stderr)
                return 2
            principal = core.identity.authenticate(Credential(token=token))
        if not principal.is_verified_human():
            raise ForbiddenError("a verified human is required")
        if args.operation == "apply" and not answers:
            _emit({"results": [], "deferred": True})
            return 0
        if args.operation == "request":
            saved = services.attestation.request(args.finding, args.decision, args.reason)
        elif args.operation == "record":
            saved = services.findings.decisions.decide(
                RecordDecision(
                    finding_id=args.finding,
                    rationale=args.rationale,
                    **{args.decision: getattr(args, args.decision)},
                    evidence_grade=args.evidence_grade,
                    source_channel=SourceChannel.INTERACTIVE,
                ),
                principal,
            )
        else:
            receipts = []
            failed = False
            for answer in answers:
                try:
                    saved = services.attestation.attest(
                        answer.review_item_id,
                        principal,
                        answer.decision,
                        answer.answer.command(),
                    )
                    receipts.append({"ok": True, "review_item": _receipt(saved, services)})
                except (TraustError, ModelValidationError) as error:
                    failed = True
                    receipts.append(
                        {
                            "ok": False,
                            "review_item_id": str(answer.review_item_id),
                            "error": type(error).__name__,
                        }
                    )
            _emit({"results": receipts})
            return 2 if failed else 0
        _emit(_receipt(saved, services))
        return 0
    except AuthenticationError:
        print("countersign: authentication refused by core.", file=sys.stderr)
        return 2
    except ForbiddenError:
        print(
            "countersign: a verified human and core decision authorization are required.",
            file=sys.stderr,
        )
        return 2
    except (TraustError, ModelValidationError, OSError, UnicodeError) as error:
        # Core errors can quote submitted text; never echo credentials or rationale.
        print(f"countersign: core refused the operation ({type(error).__name__}).", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
