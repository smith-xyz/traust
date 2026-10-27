"""`traust session run`: the role's model, the skill's prompt, a checkout outside the harness when
asked, the agent started in the harness, and the outcome as a JobResult."""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from traust.cli import session
from traust.paths import HARNESS_ROOT

REPO = "https://github.com/example/app"
HEAD = "b" * 40
ANCHOR = "a" * 40
PREPARED = json.dumps({"kind": "vuln-scan", "diff": {"anchor": ANCHOR}})


class Processes:
    """Answers `registry models resolve`, `git clone`, `git rev-parse`, `assessments prepare` and
    the agent; records each call."""

    def __init__(
        self,
        model: str = "claude-opus-5-5",
        agent: int = 0,
        clone: int = 0,
        prepare: tuple[int, str] = (0, PREPARED),
        pr_agent: int = 0,
        unknown_role: str = "",
    ) -> None:
        self.model, self.agent, self.clone = model, agent, clone
        self.prepare, self.pr_agent, self.unknown_role = prepare, pr_agent, unknown_role
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def __call__(self, argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append((argv, kw))
        if argv[1:5] == ["-m", "traust.cli", "registry", "models"]:
            ok = bool(self.model) and argv[-1] != self.unknown_role
            return subprocess.CompletedProcess(argv, 0 if ok else 1, self.model + "\n", "no role")
        if argv[1:5] == ["-m", "traust.cli", "assessments", "prepare"]:
            code, out = self.prepare
            return subprocess.CompletedProcess(argv, code, out, "not registered")
        if argv[:2] == ["git", "clone"]:
            if self.clone:
                raise subprocess.CalledProcessError(self.clone, argv, stderr=b"not found")
            Path(argv[-1]).mkdir(parents=True)
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        if argv[0] == "git" and argv[-2:] == ["rev-parse", "HEAD"]:
            return subprocess.CompletedProcess(argv, 0, HEAD + "\n", "")
        pr = argv[-1].startswith("/threat-model pr ")
        return subprocess.CompletedProcess(argv, self.pr_agent if pr else self.agent)

    def agent_call(self) -> tuple[list[str], dict[str, Any]]:
        (call,) = self.agent_calls()
        return call

    def agent_calls(self) -> list[tuple[list[str], dict[str, Any]]]:
        return [c for c in self.calls if c[0][0] == "claude"]

    def argv_of(self, *op: str) -> list[list[str]]:
        return [c[0] for c in self.calls if c[0][3 : 3 + len(op)] == list(op)]


@pytest.fixture
def processes(monkeypatch: pytest.MonkeyPatch) -> Processes:
    fake = Processes()
    monkeypatch.setattr(session.subprocess, "run", fake)
    return fake


def run(*argv: str) -> tuple[int, dict[str, Any]]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = session.run(list(argv))
    return rc, json.loads(out.getvalue())


def test_a_session_runs_the_skill_on_the_roles_model_in_the_harness(processes: Processes) -> None:
    rc, result = run(
        "--skill", "verify-remediation", "--role", "verification-verdict", "--", "full-sweep"
    )
    assert (rc, result["outcome"]) == (0, "succeeded")
    argv, kw = processes.agent_call()
    assert argv[-3:] == ["--model", "claude-opus-5-5", "/verify-remediation full-sweep"]
    assert kw["cwd"] == HARNESS_ROOT
    resolve = processes.calls[0][0]
    assert resolve[-1] == "verification-verdict"


def test_a_repository_is_passed_by_url(processes: Processes) -> None:
    run("--skill", "secure-code-audit", "--role", "deep-audit", "--repo", REPO)
    assert processes.agent_call()[0][-1] == f"/secure-code-audit {REPO}"


def test_a_checkout_is_a_temporary_directory_outside_the_harness(processes: Processes) -> None:
    rc, _ = run(
        "--skill", "vuln-scan", "--role", "vuln-scan", "--repo", REPO, "--checkout", "--", "--diff"
    )
    clone = next(c for c in processes.calls if c[0][:2] == ["git", "clone"])
    assert clone[0][-2] == REPO and clone[1]["env"]["GIT_ALLOW_PROTOCOL"] == "https"
    prompt = processes.agent_call()[0][-1]
    path = Path(prompt.split()[1])
    assert prompt.startswith("/vuln-scan ") and prompt.endswith(" --diff") and rc == 0
    assert not path.is_relative_to(HARNESS_ROOT) and not path.exists()  # gone after the session


def test_a_mode_token_comes_before_the_checkout(processes: Processes) -> None:
    run(
        *("--skill", "threat-model", "--mode", "review", "--role", "threat-model"),
        *("--repo", REPO, "--checkout", "--", "--auto", "--apply-ratings"),
    )
    skill, mode, path, *flags = processes.agent_call()[0][-1].split()
    assert (skill, mode, flags) == ("/threat-model", "review", ["--auto", "--apply-ratings"])
    assert Path(path).name == "checkout"


@pytest.mark.parametrize(
    ("fake", "argv", "outcome", "reason"),
    [
        (
            Processes(agent=3),
            ["--skill", "dependency-watch", "--role", "fact-judge"],
            "failed",
            "runner-crashed",
        ),
        (
            Processes(model=""),
            ["--skill", "dependency-watch", "--role", "nope"],
            "failed",
            "bad_request",
        ),
        (
            Processes(),
            ["--skill", "no-such-skill", "--role", "fact-judge"],
            "failed",
            "bad_request",
        ),
        (
            Processes(clone=128),
            ["--skill", "vuln-scan", "--role", "vuln-scan", "--repo", REPO, "--checkout"],
            "refused",
            "not_found",
        ),
        (
            Processes(),
            [
                "--skill",
                "vuln-scan",
                "--role",
                "vuln-scan",
                "--repo",
                "http://x.io/a/b",
                "--checkout",
            ],
            "refused",
            "not_found",
        ),
    ],
    ids=["session fails", "unknown role", "unknown skill", "clone fails", "not https"],
)
def test_what_cannot_run_is_answered_with_a_registered_reason(
    monkeypatch: pytest.MonkeyPatch, fake: Processes, argv: list[str], outcome: str, reason: str
) -> None:
    monkeypatch.setattr(session.subprocess, "run", fake)
    rc, result = run(*argv)
    assert (result["outcome"], result["reason"]) == (outcome, reason)
    assert rc == {"failed": 1, "refused": 5}[outcome]


def test_checkout_needs_a_repository() -> None:
    with pytest.raises(SystemExit):
        session.run(["--skill", "vuln-scan", "--role", "vuln-scan", "--checkout"])


STAMPED_SCAN = (
    *("--skill", "vuln-scan", "--role", "vuln-scan", "--repo", REPO, "--checkout"),
    *("--rule", "rule-5+threat-model-pr", "--", "--diff"),
)


def test_a_stamped_diff_scan_runs_threat_model_pr_on_the_same_checkout_at_its_anchor(
    processes: Processes,
) -> None:
    rc, result = run(*STAMPED_SCAN)
    assert (rc, result["outcome"]) == (0, "succeeded")
    (scan, _), (pr, kw) = processes.agent_calls()
    clone = scan[-1].split()[1]
    assert scan[-1] == f"/vuln-scan {clone} --diff"
    assert pr[-1] == f"/threat-model pr {clone} --base {ANCHOR}" and kw["cwd"] == HARNESS_ROOT
    assert [a[-1] for a in processes.argv_of("registry", "models")] == ["vuln-scan", "threat-model"]
    (prepare,) = processes.argv_of("assessments", "prepare")
    assert prepare[5:] == [
        *("--kind", "vuln-scan", "--repo-url", REPO, "--sha", HEAD, "--diff", clone)
    ]


@pytest.mark.parametrize("rule", ["rule-5", "rule-3+preroute"])
def test_an_unstamped_rule_runs_only_the_scan(processes: Processes, rule: str) -> None:
    rc, _ = run(
        *("--skill", "vuln-scan", "--role", "vuln-scan", "--repo", REPO, "--checkout"),
        *("--rule", rule, "--", "--diff"),
    )
    assert rc == 0 and len(processes.agent_calls()) == 1
    assert processes.argv_of("assessments", "prepare") == []


def test_a_refused_diff_skips_the_pr_pass_and_says_why(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    refusal = {"refuse": True, "recommend": "full-audit", "reason": "anchor not reachable"}
    fake = Processes(prepare=(3, json.dumps(refusal)))
    monkeypatch.setattr(session.subprocess, "run", fake)
    rc, result = run(*STAMPED_SCAN)
    assert (rc, result["outcome"]) == (0, "succeeded")
    assert [c[0][-1].split()[0] for c in fake.agent_calls()] == ["/vuln-scan"]
    assert "+threat-model-pr skipped: diff refused: anchor not reachable" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("fake", "agents", "reason"),
    [
        (Processes(agent=3), ["/vuln-scan"], "runner-crashed"),
        (Processes(pr_agent=3), ["/vuln-scan", "/threat-model"], "runner-crashed"),
        (Processes(prepare=(2, "")), ["/vuln-scan"], "runner-crashed"),
        (Processes(unknown_role="threat-model"), [], "bad_request"),
    ],
    ids=["scan fails", "pr session fails", "prepare fails", "no threat-model model"],
)
def test_a_stamped_scan_that_cannot_finish_fails(
    monkeypatch: pytest.MonkeyPatch, fake: Processes, agents: list[str], reason: str
) -> None:
    monkeypatch.setattr(session.subprocess, "run", fake)
    rc, result = run(*STAMPED_SCAN)
    assert (rc, result["outcome"], result["reason"]) == (1, "failed", reason)
    assert [c[0][-1].split()[0] for c in fake.agent_calls()] == agents


def test_the_stamp_needs_a_checkout() -> None:
    with pytest.raises(SystemExit):
        session.run(
            [
                "--skill",
                "vuln-scan",
                "--role",
                "vuln-scan",
                "--repo",
                REPO,
                "--rule",
                "r+threat-model-pr",
            ]
        )
