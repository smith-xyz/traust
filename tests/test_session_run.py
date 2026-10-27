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
from traust_core.v1.providers.checkout import GitCheckout
from traust_core.v1.providers.process import ProcessRunner

from traust.cli import session
from traust.paths import HARNESS_ROOT

REPO = "https://github.com/example/app"


class Processes:
    """Answers `registry models resolve`, `git clone` and the agent; records each call."""

    def __init__(self, model: str = "claude-opus-5-5", agent: int = 0, clone: int = 0) -> None:
        self.model, self.agent, self.clone = model, agent, clone
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def __call__(self, argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append((argv, kw))
        if argv[1:5] == ["-m", "traust.cli", "registry", "models"]:
            ok = bool(self.model)
            return subprocess.CompletedProcess(argv, 0 if ok else 1, self.model + "\n", "no role")
        if argv[:2] == ["git", "clone"]:
            if self.clone:
                raise subprocess.CalledProcessError(self.clone, argv, stderr=b"not found")
            Path(argv[-1]).mkdir(parents=True)
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        return subprocess.CompletedProcess(argv, self.agent)

    def agent_call(self) -> tuple[list[str], dict[str, Any]]:
        (call,) = [c for c in self.calls if c[0][0] == "claude"]
        return call


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


def _git(*argv: str) -> str:
    done = subprocess.run(["git", *argv], capture_output=True, text=True, check=True)
    return done.stdout.strip()


def test_a_checkout_holds_the_history_a_diff_scan_anchors_at(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    origin = tmp_path / "origin"
    _git("init", "-q", "-b", "main", str(origin))
    for name in ("audited.py", "changed.py"):
        (origin / name).write_text("x = 1\n")
        _git("-C", str(origin), "add", name)
        _git("-C", str(origin), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", name)
    anchor = _git("-C", str(origin), "rev-parse", "HEAD~1")
    # The https URL is served from the local repository; only the protocol allowlist widens.
    monkeypatch.setitem(session._GIT_ENV, "GIT_ALLOW_PROTOCOL", "https:file")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", f"url.{origin.as_uri()}.insteadOf")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", REPO)

    clone = session.checkout(REPO, tmp_path / "checkout")

    git = GitCheckout(ProcessRunner(["git"]))
    assert git.reachable(clone, anchor)  # what `assessments prepare --diff` refuses without
    assert [r.path for r in git.numstat(clone, anchor)] == ["changed.py"]
