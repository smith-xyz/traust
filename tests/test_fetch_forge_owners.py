"""inventory-repositories/scripts/fetch_forge_owners.py — URL gate + file fetch.

No network: the forge CLI is stubbed.
"""

from __future__ import annotations

import base64
import importlib.util
import json

import pytest

from traust.paths import skill_dir

SCRIPT = skill_dir("inventory-repositories") / "scripts" / "fetch_forge_owners.py"


def _load():
    spec = importlib.util.spec_from_file_location("ffo", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize(
    "url,host,path",
    [
        ("https://github.com/acme/api", "github.com", "acme/api"),
        ("https://github.com/acme/api.git/", "github.com", "acme/api"),
        ("https://gitlab.example.com/grp/sub/proj", "gitlab.example.com", "grp/sub/proj"),
    ],
)
def test_repo_url_gate_accepts_https_forges(url, host, path):
    assert _load().parse_repo_url(url) == (host, path)


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/acme/api",  # not https
        "https://github.com/acme",  # no repo
        "https://example.com/acme/api",  # unknown host
        "git@github.com:acme/api.git",  # ssh
        "https://github.com/acme/api;rm -rf /",  # shell metacharacters
    ],
)
def test_repo_url_gate_rejects_everything_else(url):
    with pytest.raises(SystemExit):
        _load().parse_repo_url(url)


def test_github_file_uses_gh_api_only(monkeypatch):
    m = _load()
    calls: list[list[str]] = []

    def fake_run(argv):
        calls.append(argv)
        assert argv[:3] == ["gh", "api", "repos/acme/api/contents/bundle/x.yaml"]
        return base64.b64encode(b"kind: ClusterServiceVersion\n").decode()

    monkeypatch.setattr(m, "_run", fake_run)
    monkeypatch.setattr(m.shutil, "which", lambda _: "/usr/bin/gh")
    assert m.github("acme/api", "bundle/x.yaml") == "kind: ClusterServiceVersion\n"
    assert len(calls) == 1


def test_gitlab_file_names_the_host_and_quotes_the_path(monkeypatch):
    m = _load()
    calls: list[list[str]] = []
    monkeypatch.setattr(m, "_run", lambda argv: calls.append(argv) or "text")
    monkeypatch.setattr(m.shutil, "which", lambda _: "/usr/bin/glab")
    assert m.gitlab("gitlab.example.com", "grp/proj", "bundle/x.yaml") == "text"
    assert calls == [
        [
            "glab",
            "api",
            "--hostname",
            "gitlab.example.com",
            "projects/grp%2Fproj/repository/files/bundle%2Fx.yaml/raw?ref=HEAD",
        ]
    ]


def test_main_emits_the_file_as_json(monkeypatch, capsys):
    m = _load()
    monkeypatch.setattr(m, "github", lambda path, file: None)
    argv = ["--repo-url", "https://github.com/acme/api", "--file", "missing.yaml"]
    assert m.main(argv) == 0
    assert json.loads(capsys.readouterr().out) == {
        "repo": "acme/api",
        "host": "github.com",
        "file": None,
    }


def test_main_needs_a_file():
    with pytest.raises(SystemExit):
        _load().main(["--repo-url", "https://github.com/acme/api"])
