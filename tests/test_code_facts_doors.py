"""`traust adapters route-guards|config-matrix|sanitizers|fork-lag|priv-profile`: each is one traust-core
code-facts call; services are stubbed (the pre-scans' behaviour is traust-core's tests)."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.artifacts import PrivProfileArtifact
from traust_core.v1.models.code_facts import (
    CodeFactKind,
    ConfigClass,
    ConfigFact,
    ConfigSink,
    ConfigSource,
    ConfigSystem,
    ConfigTriple,
    ForkLagFact,
    ForkUpstream,
    RouteFamily,
    RouteGuardFact,
    RouteGuardRow,
    RouteHandler,
    SanitizerFact,
    SinkStatus,
)
from traust_core.v1.models.common import CodeSpan
from traust_core.v1.models.vocabulary import Ecosystem

from traust.cli import code_facts
from traust.cli.groups import GROUPS

ROW = RouteGuardRow(
    family=RouteFamily.GO_HTTP,
    method="HandleFunc",
    pattern="/callback",
    handler=RouteHandler(expr="handleCallback", path="server.go", line=4),
    registration=CodeSpan(path="server.go", line=4),
    judgement_required=True,
)
TRIPLE = ConfigTriple(
    key="DB_PASSWORD",
    effective_default="<hardcoded literal, 8 chars>",
    source=ConfigSource(system=ConfigSystem.ENV_CHAIN_PYTHON, path="m.py", line=2),
    sink=ConfigSink(status=SinkStatus.UNRESOLVED),
    config_class=ConfigClass.SECRET,
    judgement_required=True,
    weak_default=True,
    literal_redacted=True,
)
CANDIDATE = SanitizerFact(function="sanitize", path="m.py", line=3, arg="v", is_method=False)
FORK = ForkLagFact(
    upstreams=(
        ForkUpstream(identity="github.com/coredns/coredns", package="github.com/coredns/coredns",
                     ecosystem=Ecosystem.GO),
    ),
)  # fmt: skip

PROFILE = PrivProfileArtifact.from_document(
    {"repo": "widget", "workloads": [], "rbac_rules": [{"verbs": ["get"]}],
     "summary": {"workloads": 0, "rbac_rules": 1, "no_scc_request_recorded": True}}
)  # fmt: skip


class CodeFacts:
    def __init__(self, fail: Exception | None = None) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.fail = fail

    def _answer(self, call: tuple[Any, ...], result: Any) -> Any:
        self.calls.append(call)
        if self.fail:
            raise self.fail
        return result

    def route_guards(self, request, *, resolve_handlers):
        return self._answer(("route_guards", request.workspace, resolve_handlers),
                            RouteGuardFact(routes=(ROW,)))  # fmt: skip

    def enumerate(self, kind, request):
        found = {CodeFactKind.CONFIG: [ConfigFact(triples=(TRIPLE,))],
                 CodeFactKind.SANITIZER: [CANDIDATE]}[kind]  # fmt: skip
        return self._answer(("enumerate", kind, request.workspace), found)

    def fork_lag(self, request, *, offline):
        return self._answer(("fork_lag", request.workspace, offline), FORK)

    def priv_profile(self, request, repo):
        return self._answer(("priv_profile", request.workspace, repo), PROFILE)


@pytest.fixture
def facts(monkeypatch: pytest.MonkeyPatch) -> CodeFacts:
    stub = CodeFacts()
    services = SimpleNamespace(code_facts=stub)
    monkeypatch.setattr(code_facts, "load_services", lambda home: services)
    core = SimpleNamespace(register_feeds=lambda path: stub.calls.append(("feeds", path)),
                           services=lambda: services)  # fmt: skip
    monkeypatch.setattr(code_facts, "load_core", lambda home: core)
    return stub


def _json(capsys: pytest.CaptureFixture[str]) -> dict:
    return json.loads(capsys.readouterr().out)


def test_route_guards_is_one_call(facts, capsys, tmp_path):
    assert code_facts.route_guards([str(tmp_path)]) == 0
    assert facts.calls == [("route_guards", tmp_path, False)]
    [row] = _json(capsys)["routes"]
    assert (row["pattern"], row["judgement_required"]) == ("/callback", True)


def test_route_guards_resolves_handlers_on_request(facts, tmp_path):
    assert code_facts.route_guards([str(tmp_path), "--resolve-handlers"]) == 0
    assert facts.calls == [("route_guards", tmp_path, True)]


def test_config_matrix_keeps_the_class_field_name(facts, capsys, tmp_path):
    assert code_facts.config_matrix([str(tmp_path)]) == 0
    assert facts.calls == [("enumerate", CodeFactKind.CONFIG, tmp_path)]
    [triple] = _json(capsys)["triples"]
    assert (triple["class"], triple["literal_redacted"]) == ("secret", True)


def test_sanitizers_lists_candidates(facts, capsys, tmp_path):
    assert code_facts.sanitizers([str(tmp_path)]) == 0
    assert facts.calls == [("enumerate", CodeFactKind.SANITIZER, tmp_path)]
    assert _json(capsys) == {"candidates": [CANDIDATE.model_dump(mode="json")]}


@pytest.mark.parametrize(("extra", "offline"), [([], False), (["--offline"], True)])
def test_fork_lag_reads_advisories_through_the_feeds_registry(
    facts, capsys, tmp_path, extra, offline
):
    assert code_facts.fork_lag([str(tmp_path), *extra]) == 0
    assert facts.calls[0][0] == "feeds"
    assert facts.calls[1] == ("fork_lag", tmp_path, offline)
    doc = _json(capsys)
    assert (doc["fork_detected"], doc["network"]) == (True, "skipped")


def test_out_writes_the_file_and_prints_counts(facts, capsys, tmp_path):
    out = tmp_path / "sub" / "route-guards.json"
    assert code_facts.route_guards([str(tmp_path), "--out", str(out)]) == 0
    assert _json(capsys) == {"wrote": str(out), "routes": 1, "asymmetries": 0, "coverage_gaps": 0}
    assert json.loads(out.read_text())["routes"][0]["pattern"] == "/callback"


def test_a_refused_checkout_exits_2(facts, capsys, tmp_path):
    facts.fail = ValidationError("workspace is not a directory: /nope")
    assert code_facts.config_matrix([str(tmp_path / "nope")]) == 2
    assert "not a directory" in capsys.readouterr().err


@pytest.mark.parametrize("op", ["route-guards", "config-matrix", "sanitizers", "fork-lag"])
def test_ops_are_registered_under_adapters(op):
    assert op in GROUPS["adapters"]


def test_priv_profile_is_one_call_and_prints_the_contract_document(facts, capsys, tmp_path):
    assert code_facts.priv_profile([str(tmp_path), "--name", "widget"]) == 0
    assert facts.calls == [("priv_profile", tmp_path, "widget")]
    assert _json(capsys) == json.loads(PROFILE.payload)


def test_priv_profile_out_writes_the_document_for_reporting_record(facts, capsys, tmp_path):
    out = tmp_path / "widget-priv-profile.json"
    assert code_facts.priv_profile([str(tmp_path), "--name", "widget", "--out", str(out)]) == 0
    assert _json(capsys) == {"wrote": str(out), "workloads": 0, "rbac_rules": 1}
    assert PrivProfileArtifact.parse(out.read_bytes()).repo == "widget"


def test_priv_profile_needs_a_name(facts, tmp_path):
    with pytest.raises(SystemExit):
        code_facts.priv_profile([str(tmp_path)])
    assert facts.calls == []


def test_priv_profile_is_registered_under_adapters():
    assert "priv-profile" in GROUPS["adapters"]
