"""Registered countersign boundaries use real SQLite services and cryptographic identity."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import UUID, uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import SecretStr
from traust_core.v1.models.artifacts import CodeFactsArtifact, TriageArtifact
from traust_core.v1.models.findings import Finding, RecordDecision
from traust_core.v1.models.identity import Credential
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import (
    EvidenceGrade,
    ReviewItemStatus,
    ReviewReason,
    Severity,
    SourceChannel,
    Validity,
)
from traust_core.v1.services.artifact_publishing import PublishSpec, PublishSpecs

from traust.cli import countersign
from traust.cli.__main__ import main
from traust.context import load_core, load_services

RATIONALE = "The human reviewer verified the reachable impact and requested this rating."
ISSUER = "https://identity.example.test"


@dataclass
class RecordFixture:
    config_home: Path
    store_home: Path
    finding_id: UUID
    key: rsa.RSAPrivateKey

    def token(self, *, issuer: str = ISSUER, human: bool = True, expired: bool = False) -> str:
        now = int(time.time())
        claims = {
            "iss": issuer,
            "sub": "reviewer" if human else "service-runner",
            "iat": now - 600 if expired else now,
            "exp": now - 300 if expired else now + 300,
        }
        if issuer != "local":
            claims["aud"] = "traust"
        if human:
            claims["email"] = "reviewer@example.test"
        else:
            claims["azp"] = "service-runner"
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "reviewer"})

    def command(
        self, *, severity: str = "high", grade: str | None = None, rationale: str = RATIONALE
    ) -> list[str]:
        args = [
            "admin",
            "countersign",
            "record",
            "--finding",
            str(self.finding_id),
            "--decision",
            "severity",
            "--severity",
            severity,
            "--rationale",
            rationale,
            "--token-stdin",
            "--config-home",
            str(self.config_home),
        ]
        if grade is not None:
            args.extend(["--evidence-grade", grade])
        return args

    def history(self):
        return load_services(self.config_home).findings.history(self.finding_id)


@pytest.fixture
def writer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[RecordFixture]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwks = {
        "keys": [
            {**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key())), "kid": "reviewer"}
        ]
    }

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            payload = json.dumps(jwks).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config_home = tmp_path / "config"
    config_home.mkdir()
    store_home = tmp_path / "store"
    (config_home / "core.yaml").write_text(
        f"home: {store_home}\n"
        "identity:\n"
        "  issuers:\n"
        f"    - issuer: {ISSUER}\n"
        f"      jwks_url: http://127.0.0.1:{server.server_port}/jwks\n"
        "      audience: traust\n",
        encoding="utf-8",
    )
    services = load_services(config_home)
    repo = services.portfolio.register_repository(
        HttpsRepoUrl.parse("https://github.com/example/severity-fixture", ("github.com",)),
        public=False,
    )
    assert repo.id is not None
    finding = services.findings.intake.record(
        Finding(
            repository_id=repo.id,
            fingerprint_algo="cli-test-v1",
            fingerprint="direct-human-severity",
            title="A sanitized service-backed severity fixture",
        )
    )
    assert finding.id is not None
    (store_home / "local-jwks.json").write_text(json.dumps(jwks), encoding="utf-8")

    def no_engine(*args, **kwargs):
        pytest.fail("a core severity writer must not bootstrap the legacy engine")

    monkeypatch.setattr("traust.cli.__main__.load_engine", no_engine)
    try:
        yield RecordFixture(config_home, store_home, finding.id, key)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def invoke(writer: RecordFixture, monkeypatch: pytest.MonkeyPatch, token: str, **kwargs) -> int:
    monkeypatch.setattr("sys.stdin", io.StringIO(token + "\n"))
    return main(writer.command(**kwargs))


def test_registered_record_persists_reloads_and_reruns_idempotently(
    writer, monkeypatch, capsys, caplog
):
    token = writer.token()
    rationale = RATIONALE + " $(touch /not-executed) `ignored` \x1b[31m | <script>"
    assert invoke(writer, monkeypatch, token, grade="E1", rationale=rationale) == 0
    first = capsys.readouterr()
    receipt = json.loads(first.out)
    (saved,) = writer.history()
    assert receipt["id"] == str(saved.id)
    assert receipt["finding_id"] == str(writer.finding_id)
    assert receipt["actor"] == saved.actor == "human:reviewer@example.test"
    assert receipt["severity"] == saved.severity == Severity.HIGH
    assert receipt["evidence_grade"] == saved.evidence_grade == EvidenceGrade.E1
    assert receipt["source_channel"] == saved.source_channel == SourceChannel.INTERACTIVE
    assert saved.rationale == rationale
    assert "rationale" not in receipt
    assert invoke(writer, monkeypatch, token, grade="E1", rationale=rationale) == 0
    again = capsys.readouterr()
    assert json.loads(again.out) == receipt
    assert writer.history() == [saved]
    assert token not in first.out + first.err + again.out + again.err + caplog.text
    assert rationale not in first.out + first.err + again.out + again.err


def test_an_omitted_grade_stays_ungraded(writer, monkeypatch, capsys):
    assert invoke(writer, monkeypatch, writer.token()) == 0
    assert json.loads(capsys.readouterr().out)["evidence_grade"] is None
    assert writer.history()[0].evidence_grade is None


@pytest.mark.parametrize("grade", [None, "E1", "E2", "E3"])
def test_weaker_or_ungraded_conflict_cannot_write(writer, monkeypatch, capsys, grade):
    token = writer.token()
    assert invoke(writer, monkeypatch, token, severity="high", grade="E0") == 0
    capsys.readouterr()
    original = writer.history()
    assert invoke(writer, monkeypatch, token, severity="low", grade=grade) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert writer.history() == original
    assert token not in output.out + output.err


@pytest.mark.parametrize("credential", ["invalid", "expired", "machine", "unverified-local"])
def test_authentication_and_human_refusals_never_write(
    writer, monkeypatch, capsys, caplog, credential
):
    token = {
        "invalid": "not-a-token-do-not-print",
        "expired": writer.token(expired=True),
        "machine": writer.token(human=False),
        "unverified-local": writer.token(issuer="local"),
    }[credential]
    assert invoke(writer, monkeypatch, token) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert writer.history() == []
    assert token not in output.out + output.err + caplog.text


@pytest.mark.parametrize("rationale", ["", "   ", "short"])
def test_inadequate_rationale_is_rejected_without_writes(writer, monkeypatch, capsys, rationale):
    assert invoke(writer, monkeypatch, writer.token(), rationale=rationale) == 2
    assert capsys.readouterr().out == ""
    assert writer.history() == []


def test_missing_identity_configuration_refuses(writer, monkeypatch, capsys):
    (writer.config_home / "core.yaml").write_text(f"home: {writer.store_home}\n", encoding="utf-8")
    assert invoke(writer, monkeypatch, writer.token()) == 2
    assert writer.history() == []


@pytest.mark.parametrize("token", ["", " \n\t"])
def test_empty_stdin_refuses_without_writing(writer, monkeypatch, capsys, token):
    assert invoke(writer, monkeypatch, token) == 2
    assert writer.history() == []


@pytest.mark.parametrize(
    "change",
    [
        ["--severity", "info"],
        ["--severity", "HIGH"],
        ["--severity", "moderate"],
        ["--evidence-grade", "e0"],
        ["--evidence-grade", "class1"],
        ["--finding", "LEGACY-abc1234-001"],
        ["--decision", "reopen"],
        ["--decision", "override_false_positive"],
        ["--layer", "retired-layer.json"],
        ["--actor", "human:caller-asserted"],
        ["--assessment", str(uuid4())],
    ],
)
def test_bad_values_and_retired_flags_are_parser_errors(monkeypatch, capsys, change):
    def no_services(*args, **kwargs):
        pytest.fail("invalid CLI input must not reach core")

    monkeypatch.setattr(countersign, "load_core", no_services)
    args = [
        "admin",
        "countersign",
        "record",
        "--finding",
        str(uuid4()),
        "--decision",
        "severity",
        "--severity",
        "high",
        "--rationale",
        RATIONALE,
        "--token-stdin",
        *change,
    ]
    with pytest.raises(SystemExit) as error:
        main(args)
    assert error.value.code == 2
    assert "error:" in capsys.readouterr().err


@pytest.mark.parametrize("operation", ["reopen", "override_false_positive", "confirm_mapping"])
def test_retired_operations_are_strict_errors(operation, capsys):
    with pytest.raises(SystemExit) as error:
        main(["admin", "countersign", operation])
    assert error.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


@pytest.mark.parametrize("missing", ["--rationale", "--decision", "--finding", "--severity"])
def test_required_record_arguments_are_not_optional(missing, capsys):
    args = [
        "--finding",
        str(uuid4()),
        "--decision",
        "severity",
        "--severity",
        "high",
        "--rationale",
        RATIONALE,
        "--token-stdin",
    ]
    index = args.index(missing)
    del args[index : index + 2]
    with pytest.raises(SystemExit) as error:
        main(["admin", "countersign", "record", *args])
    assert error.value.code == 2
    assert missing in capsys.readouterr().err


def test_countersign_help_does_not_bootstrap_the_engine(monkeypatch, capsys):
    def no_bootstrap(*args, **kwargs):
        pytest.fail("help must not require engine or core configuration")

    monkeypatch.setattr("traust.cli.__main__.load_engine", no_bootstrap)
    monkeypatch.setattr(countersign, "load_core", no_bootstrap)
    with pytest.raises(SystemExit) as error:
        main(["admin", "countersign", "--help"])
    assert error.value.code == 0
    output = capsys.readouterr().out
    assert "record" in output
    assert "--config-home" in output


def test_explicitly_trusted_local_signature_authenticates_a_human(
    writer, monkeypatch, capsys, caplog
):
    (writer.config_home / "core.yaml").write_text(
        f"home: {writer.store_home}\nidentity:\n  trust_local: true\n",
        encoding="utf-8",
    )
    token = writer.token(issuer="local")
    assert invoke(writer, monkeypatch, token, grade="E1") == 0
    output = capsys.readouterr()
    (saved,) = writer.history()
    assert saved.actor == "human:reviewer@example.test"
    assert json.loads(output.out)["id"] == str(saved.id)
    assert token not in output.out + output.err + caplog.text


@pytest.mark.parametrize("operation", [[], ["record"], ["queue"], ["request"], ["apply"]])
def test_native_cli_help_needs_no_deployment_config(tmp_path, operation):
    env = {**os.environ, "TRAUST_CONFIG_HOME": str(tmp_path / "missing-config")}
    result = subprocess.run(
        [sys.executable, "-m", "traust.cli", "admin", "countersign", *operation, "--help"],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout
    assert not result.stderr


def run_operation(writer, monkeypatch, operation, *arguments, token=None):
    monkeypatch.setattr("sys.stdin", io.StringIO((token or writer.token()) + "\n"))
    return main(
        [
            "admin",
            "countersign",
            operation,
            *map(str, arguments),
            "--config-home",
            str(writer.config_home),
        ]
    )


def request_review(writer, monkeypatch, capsys, *, reason=ReviewReason.AMBIGUOUS_STATEMENT):
    assert (
        run_operation(
            writer,
            monkeypatch,
            "request",
            "--finding",
            writer.finding_id,
            "--reason",
            reason.value,
            "--token-stdin",
        )
        == 0
    )
    return json.loads(capsys.readouterr().out)


def test_request_is_idempotent_and_queue_is_real_filtered_and_paged(writer, monkeypatch, capsys):
    first = request_review(writer, monkeypatch, capsys)
    assert request_review(writer, monkeypatch, capsys) == first
    second = request_review(
        writer,
        monkeypatch,
        capsys,
        reason=ReviewReason.INSUFFICIENT_AUTHORITY,
    )
    assert first["id"] != second["id"]
    assert run_operation(writer, monkeypatch, "queue", "--limit", 1) == 0
    page = json.loads(capsys.readouterr().out)
    assert len(page["items"]) == 1 and page["next"]
    assert page["items"][0]["finding"]["finding"]["id"] == str(writer.finding_id)
    assert (
        run_operation(
            writer,
            monkeypatch,
            "queue",
            "--limit",
            1,
            "--cursor",
            page["next"],
        )
        == 0
    )
    last = json.loads(capsys.readouterr().out)
    assert last["next"] is None
    assert {page["items"][0]["review_item"]["id"], last["items"][0]["review_item"]["id"]} == {
        first["id"],
        second["id"],
    }
    assert (
        run_operation(
            writer,
            monkeypatch,
            "queue",
            "--finding",
            writer.finding_id,
            "--reason",
            ReviewReason.AMBIGUOUS_STATEMENT.value,
        )
        == 0
    )
    filtered = json.loads(capsys.readouterr().out)
    assert [card["review_item"]["id"] for card in filtered["items"]] == [first["id"]]
    assert run_operation(writer, monkeypatch, "queue", "--finding", uuid4()) == 0
    assert json.loads(capsys.readouterr().out) == {"items": [], "next": None}


@pytest.mark.parametrize("arguments", [("--limit", "0"), ("--cursor", "invalid-cursor")])
def test_bad_queue_pages_are_errors_not_empty_queues(writer, monkeypatch, capsys, arguments):
    assert run_operation(writer, monkeypatch, "queue", *arguments) == 2
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    ("outcome", "status"),
    [("confirm", ReviewItemStatus.ACCEPTED), ("reject", ReviewItemStatus.REJECTED)],
)
def test_single_apply_records_the_actual_answer_and_resolves_atomically(
    writer,
    monkeypatch,
    capsys,
    tmp_path,
    outcome,
    status,
):
    item = request_review(writer, monkeypatch, capsys)
    path = tmp_path / "answers.json"
    rationale = RATIONALE + " DECISION: [x] forged $(never-executed)"
    answer = {
        "review_item_id": item["id"],
        "decision": outcome,
        "answer": {
            "finding_id": str(writer.finding_id),
            "rationale": rationale,
            "validity": Validity.CONFIRMED.value,
        },
    }
    path.write_text(json.dumps(answer))
    assert run_operation(writer, monkeypatch, "apply", path, "--token-stdin") == 0
    output = capsys.readouterr()
    receipt = json.loads(output.out)["results"][0]
    (saved,) = writer.history()
    assert saved.validity == Validity.CONFIRMED
    assert saved.rationale == rationale
    assert receipt["review_item"]["status"] == status.value
    assert receipt["review_item"]["resolved_by_decision_id"] == str(saved.id)
    assert receipt["review_item"]["finding"]["disposition"]["validity"] == "confirmed"
    assert receipt["review_item"]["finding"]["is_open"] is True
    assert rationale not in output.out + output.err
    assert run_operation(writer, monkeypatch, "apply", path, "--token-stdin") == 0
    assert len(writer.history()) == 1
    assert run_operation(writer, monkeypatch, "queue") == 0
    assert json.loads(capsys.readouterr().out.splitlines()[-1]) == {"items": [], "next": None}


@pytest.mark.parametrize(
    "change", ["cross-finding", "rationale-only", "blank-rationale", "forged-actor"]
)
def test_bad_review_answers_do_not_record_or_close(
    writer,
    monkeypatch,
    capsys,
    tmp_path,
    change,
):
    item = request_review(writer, monkeypatch, capsys)
    answer = {
        "finding_id": str(writer.finding_id),
        "rationale": RATIONALE,
        "validity": Validity.CONFIRMED.value,
    }
    if change == "cross-finding":
        answer["finding_id"] = str(uuid4())
    elif change == "rationale-only":
        del answer["validity"]
    elif change == "blank-rationale":
        answer["rationale"] = " "
    else:
        answer["actor"] = "human:forged@example.test"
    path = tmp_path / "answers.json"
    path.write_text(
        json.dumps({"review_item_id": item["id"], "decision": "reject", "answer": answer})
    )
    assert run_operation(writer, monkeypatch, "apply", path, "--token-stdin") == 2
    output = capsys.readouterr()
    assert RATIONALE not in output.out + output.err
    assert writer.history() == []
    assert run_operation(writer, monkeypatch, "queue") == 0
    assert json.loads(capsys.readouterr().out)["items"][0]["review_item"]["id"] == item["id"]


def test_bulk_apply_reports_partial_failure_without_losing_successes(
    writer,
    monkeypatch,
    capsys,
    tmp_path,
):
    first = request_review(writer, monkeypatch, capsys)
    second = request_review(
        writer,
        monkeypatch,
        capsys,
        reason=ReviewReason.INSUFFICIENT_AUTHORITY,
    )
    path = tmp_path / "answers.json"
    path.write_text(
        json.dumps(
            [
                {
                    "review_item_id": first["id"],
                    "decision": "confirm",
                    "answer": {
                        "finding_id": str(writer.finding_id),
                        "validity": "confirmed",
                        "rationale": RATIONALE,
                    },
                },
                {
                    "review_item_id": second["id"],
                    "decision": "reject",
                    "answer": {
                        "finding_id": str(uuid4()),
                        "severity": "high",
                        "rationale": RATIONALE,
                    },
                },
            ]
        )
    )
    assert run_operation(writer, monkeypatch, "apply", path, "--token-stdin") == 2
    results = json.loads(capsys.readouterr().out)["results"]
    assert [result["ok"] for result in results] == [True, False]
    assert len(writer.history()) == 1
    assert run_operation(writer, monkeypatch, "queue") == 0
    pending = json.loads(capsys.readouterr().out)
    assert [card["review_item"]["id"] for card in pending["items"]] == [second["id"]]


@pytest.mark.parametrize("operation", ["request", "apply"])
def test_machine_credentials_cannot_request_or_apply_reviews(
    writer,
    monkeypatch,
    capsys,
    tmp_path,
    operation,
):
    item = request_review(writer, monkeypatch, capsys)
    if operation == "request":
        arguments = [
            "--finding",
            writer.finding_id,
            "--reason",
            ReviewReason.INSUFFICIENT_AUTHORITY.value,
        ]
    else:
        path = tmp_path / "answer.json"
        path.write_text(
            json.dumps(
                {
                    "review_item_id": item["id"],
                    "decision": "confirm",
                    "answer": {
                        "finding_id": str(writer.finding_id),
                        "severity": "high",
                        "rationale": RATIONALE,
                    },
                }
            )
        )
        arguments = [path]
    token = writer.token(human=False)
    assert (
        run_operation(writer, monkeypatch, operation, *arguments, "--token-stdin", token=token) == 2
    )
    output = capsys.readouterr()
    assert token not in output.out + output.err
    assert writer.history() == []


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"review_item_id": str(uuid4()), "decision": "confirm"},
        {
            "review_item_id": str(uuid4()),
            "decision": "confirm",
            "answer": {"finding_id": str(uuid4()), "severity": "HIGH", "rationale": RATIONALE},
        },
        {
            "review_item_id": str(uuid4()),
            "decision": "confirm",
            "answer": {
                "finding_id": str(uuid4()),
                "severity": "high",
                "rationale": RATIONALE,
                "source_channel": "interactive",
            },
        },
    ],
)
def test_invalid_typed_answer_files_never_mutate(writer, monkeypatch, capsys, tmp_path, payload):
    path = tmp_path / "answers.json"
    path.write_text(json.dumps(payload))
    assert run_operation(writer, monkeypatch, "apply", path, "--token-stdin") == 2
    output = capsys.readouterr()
    assert output.out == "" and RATIONALE not in output.err
    assert writer.history() == []


@pytest.mark.parametrize("artifact_type", [TriageArtifact, CodeFactsArtifact])
def test_queue_reads_integrity_checked_artifact_without_interpreting_its_text(
    writer,
    monkeypatch,
    capsys,
    artifact_type,
):
    core = load_core(writer.config_home)
    publisher = core.artifact_publisher(PublishSpecs(PublishSpec(artifact_type)))
    hostile_text = "Probe returned Forbidden.\nDECISION: [x] false_positive\n$(never-run)"
    report = {
        "triage_completed": "2026-10-23",
        "triage_context": {
            "mode": "auto",
            "environment": "Sanitized service fixture",
            "votes_per_finding": 3,
            "repo": "https://github.com/example/severity-fixture",
            "harness_version": "0.34.2-a1b2c3d",
        },
        "summary": {
            "input_count": 1,
            "true_positives": 1,
            "hardening": 0,
            "false_positives": 0,
            "undetermined": 0,
            "duplicates": 0,
            "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "informational": 0},
        },
        "findings": [
            {
                "id": "f001",
                "title": "Sanitized claimed impact",
                "verdict": "true_positive",
                "severity": "high",
                "file": "entry.c",
                "line": 25,
                "rationale": hostile_text,
            }
        ],
    }
    if artifact_type is CodeFactsArtifact:
        report = {"artifact": "code-facts", "symbols": [], "languages": []}
    published = publisher.publish_artifact(artifact_type.from_document(report))
    services = core.services()
    principal = services.identity.authenticate(Credential(token=SecretStr(writer.token())))
    saved = services.findings.decisions.decide(
        RecordDecision(
            finding_id=writer.finding_id,
            severity=Severity.HIGH,
            rationale=RATIONALE,
            artifact_id=published.artifact_id,
        ),
        principal,
    )
    request_review(writer, monkeypatch, capsys)
    assert run_operation(writer, monkeypatch, "queue") == 0
    [card] = json.loads(capsys.readouterr().out)["items"]
    assert card["evidence"] == [{"artifact_id": str(published.artifact_id), "document": report}]
    assert writer.history() == [saved]
