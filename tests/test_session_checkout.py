"""`traust session run`'s checkout: the history a diff scan anchors at, read the way
`traust assessments prepare --diff` reads it (traust-core's `GitCheckout`)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from traust_core.v1.providers.checkout import GitCheckout
from traust_core.v1.providers.process import ProcessRunner

from traust.cli import session

REPO = "https://github.com/example/app"


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
