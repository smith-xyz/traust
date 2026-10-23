"""The registered severity writer uses real SQLite services and cryptographic identity verification."""

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
from traust_core.v1.models.findings import Finding
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.models.vocabulary import EvidenceGrade, Severity, SourceChannel

from traust.cli import countersign
from traust.cli.__main__ import main
from traust.context import load_services

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

    monkeypatch.setattr(countersign, "load_services", no_services)
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


@pytest.mark.parametrize("operation", ["queue", "apply", "reopen", "override_false_positive"])
def test_retired_operations_are_strict_errors(operation, capsys):
    with pytest.raises(SystemExit) as error:
        main(["admin", "countersign", operation])
    assert error.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


@pytest.mark.parametrize(
    "missing", ["--rationale", "--token-stdin", "--decision", "--finding", "--severity"]
)
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
    del args[index : index + (1 if missing == "--token-stdin" else 2)]
    with pytest.raises(SystemExit) as error:
        main(["admin", "countersign", "record", *args])
    assert error.value.code == 2
    assert missing in capsys.readouterr().err


def test_record_help_uses_core_enum_types(capsys):
    with pytest.raises(SystemExit) as error:
        main(["admin", "countersign", "record", "--help"])
    assert error.value.code == 0
    help_text = capsys.readouterr().out
    assert all(value.value in help_text for value in Severity)
    assert all(value.value in help_text for value in EvidenceGrade)


@pytest.mark.parametrize("severity", list(Severity))
def test_each_core_severity_is_persisted_without_aliases(writer, monkeypatch, capsys, severity):
    assert invoke(writer, monkeypatch, writer.token(), severity=severity.value) == 0
    assert json.loads(capsys.readouterr().out)["severity"] == severity.value
    assert writer.history()[0].severity == severity


def test_countersign_help_does_not_bootstrap_the_engine(monkeypatch, capsys):
    def no_bootstrap(*args, **kwargs):
        pytest.fail("help must not require engine or core configuration")

    monkeypatch.setattr("traust.cli.__main__.load_engine", no_bootstrap)
    monkeypatch.setattr(countersign, "load_services", no_bootstrap)
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


@pytest.mark.parametrize("operation", [[], ["record"]])
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
