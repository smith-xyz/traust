"""Record a direct human severity judgement through traust-core's services."""

from __future__ import annotations

import argparse
import json
import sys
from uuid import UUID

from pydantic import SecretStr
from pydantic import ValidationError as ModelValidationError
from traust_core.v1.errors import AuthenticationError, ForbiddenError, TraustError
from traust_core.v1.models.findings import RecordDecision
from traust_core.v1.models.identity import Credential
from traust_core.v1.models.vocabulary import EvidenceGrade, Severity, SourceChannel

from traust.context import add_config_home_arg, load_services


def main(argv: list[str] | None = None) -> int:
    config = argparse.ArgumentParser(add_help=False)
    add_config_home_arg(config)
    config_args, rest = config.parse_known_args(argv)
    parser = argparse.ArgumentParser(
        prog="traust admin countersign",
        description=(
            "Direct human severity recording; queue/apply and validity actions remain unported."
        ),
        parents=[config],
    )
    sub = parser.add_subparsers(dest="operation", required=True)
    record = sub.add_parser("record", help="Record a verified human's severity judgement.")
    record.add_argument("--finding", type=UUID, required=True, help="Core finding UUID.")
    record.add_argument("--decision", choices=("severity",), required=True)
    record.add_argument("--severity", type=Severity, choices=tuple(Severity), required=True)
    record.add_argument("--rationale", required=True, help="The human reviewer's own rationale.")
    record.add_argument("--evidence-grade", type=EvidenceGrade, choices=tuple(EvidenceGrade))
    record.add_argument(
        "--token-stdin",
        action="store_true",
        required=True,
        help="Read the identity token from stdin.",
    )
    args = parser.parse_args(rest)

    if sys.stdin.isatty():
        print(
            "countersign: pipe an identity token on stdin; interactive token entry is disabled.",
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
        services = load_services(config_args.config_home)
        if services.identity is None:
            print("countersign: core identity is not configured in core.yaml.", file=sys.stderr)
            return 2
        principal = services.identity.authenticate(Credential(token=token))
        if not principal.is_verified_human():
            raise ForbiddenError("a verified human is required")
        saved = services.findings.decisions.decide(
            RecordDecision(
                finding_id=args.finding,
                severity=args.severity,
                rationale=args.rationale,
                evidence_grade=args.evidence_grade,
                source_channel=SourceChannel.INTERACTIVE,
            ),
            principal,
        )
    except AuthenticationError:
        print("countersign: authentication refused by core.", file=sys.stderr)
        return 2
    except ForbiddenError:
        print(
            "countersign: a verified human and core decision authorization are required.",
            file=sys.stderr,
        )
        return 2
    except (TraustError, ModelValidationError) as error:
        # Core errors can quote submitted text; do not echo credentials or rationale.
        print(f"countersign: core refused the decision ({type(error).__name__}).", file=sys.stderr)
        return 2

    receipt = saved.model_dump(
        mode="json",
        include={
            "id",
            "finding_id",
            "severity",
            "evidence_grade",
            "source_channel",
            "actor",
            "occurred_at",
            "created_at",
            "statement_key",
        },
    )
    print(json.dumps(receipt, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
