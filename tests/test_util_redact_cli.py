"""``traust util redact`` scrubs through core's redaction door (``services.redaction``)."""

from __future__ import annotations

import io
import json
import shutil
from pathlib import Path

import pytest
import yaml

from traust.cli.__main__ import main

TOKEN = "ghp_" + "a" * 36
FIXTURE = Path(__file__).parent / "fixtures" / "config"


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    shutil.copytree(FIXTURE, config)
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def redact(home: Path, monkeypatch, *argv: str, stdin: str = "") -> int:
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    return main(["util", "redact", "--config-home", str(home), *argv])


def test_stdin_is_scrubbed(home, monkeypatch, capsys):
    assert redact(home, monkeypatch, stdin=f"token={TOKEN}\n") == 0
    out, err = capsys.readouterr()
    assert out == "token=ghp_a...REDACTED\n"
    assert "1 hit(s) on stdin" in err


def test_clean_stdin_passes_through(home, monkeypatch, capsys):
    assert redact(home, monkeypatch, stdin="nothing here\n") == 0
    assert capsys.readouterr() == ("nothing here\n", "")


def test_scan_only_lists_each_secret_once(home, monkeypatch, capsys):
    """Behaviour change: the engine's scan listed this token as github-token and bearer-token."""
    assert redact(home, monkeypatch, "--scan-only", stdin=f"Authorization: Bearer {TOKEN}") == 1
    assert json.loads(capsys.readouterr().out) == [
        {"category": "github-token", "match_prefix": "ghp_a"}
    ]


def test_scan_only_clean_exits_0(home, monkeypatch, capsys):
    assert redact(home, monkeypatch, "--scan-only", stdin="clean") == 0
    assert json.loads(capsys.readouterr().out) == []


def test_files_are_redacted_in_place(home, monkeypatch, tmp_path, capsys):
    tree = tmp_path / "tree"
    (tree / "sub").mkdir(parents=True)
    (tree / "sub" / "a.txt").write_text(f"key {TOKEN}\n")
    (tree / "b.txt").write_text("clean\n")
    assert redact(home, monkeypatch, str(tree)) == 0
    assert (tree / "sub" / "a.txt").read_text() == "key ghp_a...REDACTED\n"
    assert (tree / "b.txt").read_text() == "clean\n"
    out = capsys.readouterr().out
    assert "a.txt: github-token (ghp_a…)" in out
    assert "redact: 1 hit(s) across 1 path(s)" in out


def test_scan_only_leaves_files_alone_and_fails(home, monkeypatch, tmp_path, capsys):
    f = tmp_path / "a.txt"
    f.write_text(f"key {TOKEN}\n")
    assert redact(home, monkeypatch, "--scan-only", str(f)) == 1
    assert f.read_text() == f"key {TOKEN}\n"
