"""`traust portfolio plan|onboard|owner-hints|import-owners` end to end on traust-core, in-process
on SQLite and Postgres; the forge CLI is replayed from recorded answers."""

from __future__ import annotations

import base64
import contextlib
import io
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from traust_core.v1.providers.process import ProcessResult, ProcessRunner

from tests.test_products_doors import _postgres
from traust.cli import auth, portfolio_onboard, products

FIXTURES = Path(__file__).parent / "fixtures" / "inventory"
ORG = "example-org"
LISTED = [
    json.loads(line)["url"]
    for line in (FIXTURES / "github-org-repos.jsonl").read_text().splitlines()
    if not json.loads(line)["archived"]
]
EXTRA = "https://github.com/other-org/tool"


def _endpoint(argv: list[str]) -> str:
    return next(a for a in argv[2:] if "/" in a and a[0] not in "-.{")


class Forge:
    """`gh api` answers by endpoint; `fail` makes every call exit like an expired login."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.fail = False

    def __call__(self, argv: list[str], **_: Any) -> ProcessResult:
        self.calls.append(list(argv))
        if self.fail:
            return ProcessResult(tuple(argv), 1, b"", b"HTTP 401: Bad credentials", 0)
        endpoint = _endpoint(argv)
        if endpoint.startswith(f"orgs/{ORG}/repos"):
            out = (FIXTURES / "github-org-repos.jsonl").read_text()
        elif endpoint.endswith("/contents/OWNERS"):
            out = base64.b64encode((FIXTURES / "OWNERS").read_bytes()).decode()
        elif endpoint.endswith("/contributors?per_page=10"):
            out = (FIXTURES / "github-contributors.txt").read_text()
        elif endpoint.count("/") == 2:
            out = json.dumps(
                {"visibility": "private" if endpoint == "repos/other-org/tool" else "public"}
            )
        else:
            return ProcessResult(tuple(argv), 1, b"", b"HTTP 404: Not Found", 0)
        return ProcessResult(tuple(argv), 0, out.encode(), b"", 0)


@pytest.fixture
def forge(monkeypatch: pytest.MonkeyPatch) -> Forge:
    fake = Forge()
    monkeypatch.setattr(ProcessRunner, "run", fake)
    return fake


@pytest.fixture(params=["sqlite", "postgres"])
def home(request: pytest.FixtureRequest, tmp_path: Path, forge: Forge) -> Iterator[Path]:
    config = tmp_path / "config"
    config.mkdir()
    core: dict[str, Any] = {"home": str(tmp_path / "store"), "identity": {"trust_local": True}}
    with contextlib.ExitStack() as stack:
        if request.param == "postgres":
            core["database"] = {"url": stack.enter_context(_postgres())}
        (config / "core.yaml").write_text(yaml.safe_dump(core))
        yield config


def run(door: Any, home: Path, *argv: str) -> tuple[int, Any]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = door(["--config-home", str(home), *argv])
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


def logged_in(home: Path) -> None:
    rc, made = run(auth.local, home, "--identity", "alice@example.com")
    assert rc == 0, made


REQUEST = ("--product", "example", "--org", ORG, "--repo", EXTRA)


def test_plan_lists_what_onboard_would_add_and_writes_nothing(home: Path) -> None:
    rc, plan = run(portfolio_onboard.plan, home, *REQUEST)
    assert rc == 0, plan
    assert sorted(s["url"] for s in plan["new"]) == sorted([EXTRA, *LISTED])
    assert plan["existing_repository_ids"] == []
    assert [g["subject"] for g in plan["gaps"]] == ["example"]
    rc, again = run(portfolio_onboard.plan, home, *REQUEST)
    assert again == plan


def test_onboard_registers_once_and_reruns_are_no_ops(home: Path, forge: Forge) -> None:
    logged_in(home)
    rc, first = run(portfolio_onboard.onboard, home, *REQUEST, "--label", "Example")
    assert rc == 0, first
    assert len(first["repository_ids"]) == len(LISTED) + 1 == 12
    assert first["order_ids"] == []

    rc, second = run(portfolio_onboard.onboard, home, *REQUEST)
    assert (rc, second) == (0, first)
    rc, plan = run(portfolio_onboard.plan, home, *REQUEST)
    assert (plan["new"], plan["gaps"]) == ([], [])
    assert sorted(plan["existing_repository_ids"]) == sorted(first["repository_ids"])

    rc, listed = run(products.list_, home)
    assert [(p["name"], p["label"], p["ownership"]) for p in listed] == [
        ("example", "Example", None)
    ]
    assert not any(a in c for c in forge.calls for a in ("curl", "clone"))


def test_onboard_refuses_an_unregistered_product_without_a_label(home: Path) -> None:
    logged_in(home)
    rc, err = run(portfolio_onboard.onboard, home, *REQUEST)
    assert rc == 2 and "product is not registered" in err
    rc, plan = run(portfolio_onboard.plan, home, *REQUEST)
    assert len(plan["new"]) == 12


def test_onboard_needs_a_login(home: Path) -> None:
    rc, err = run(portfolio_onboard.onboard, home, *REQUEST, "--label", "Example")
    assert rc == 2 and "traust auth" in err
    rc, plan = run(portfolio_onboard.plan, home, *REQUEST)
    assert len(plan["new"]) == 12


@pytest.mark.parametrize(
    "argv,reason",
    [
        (("--product", "example"), "--repo or --org"),
        (("--product", "example", "--repo", "https://example.com/a/b"), "host not allowed"),
        (("--product", "example", "--repo", "http://github.com/a/b"), "must be https"),
        (("--product", "example", "--org", "bad org"), "cannot list"),
        (("--product", "not a slug", "--repo", EXTRA), "slug"),
    ],
)
def test_bad_input_is_refused_before_any_write(
    home: Path, argv: tuple[str, ...], reason: str
) -> None:
    logged_in(home)
    rc, err = run(portfolio_onboard.onboard, home, *argv, "--label", "Example")
    assert rc == 2 and reason in err, err


def test_a_forge_refusal_surfaces_and_registers_nothing(home: Path, forge: Forge) -> None:
    logged_in(home)
    forge.fail = True
    rc, err = run(portfolio_onboard.onboard, home, *REQUEST, "--label", "Example")
    assert rc == 2 and "Bad credentials" in err
    forge.fail = False
    rc, plan = run(portfolio_onboard.plan, home, *REQUEST)
    assert len(plan["new"]) == 12


def test_owner_hints_are_approvers_then_contributors_without_bots(home: Path) -> None:
    rc, hints = run(portfolio_onboard.owner_hints, home, "--repo", LISTED[0])
    assert rc == 0, hints
    assert [(h["handle"], h["origin"]) for h in hints] == [
        ("approver-a", "owners-file"),
        ("approver-b", "owners-file"),
        ("approver-c", "owners-file"),
        ("approver-d", "owners-file"),
        ("person-a", "contributor"),
        ("person-b", "contributor"),
        ("person-c", "contributor"),
        ("approver-b", "contributor"),
        ("person-d", "contributor"),
    ]


def test_owner_hints_surface_a_forge_refusal(home: Path, forge: Forge) -> None:
    forge.fail = True
    rc, err = run(portfolio_onboard.owner_hints, home, "--repo", LISTED[0])
    assert rc == 2 and "Bad credentials" in err


def source(tmp_path: Path, doc: Any) -> str:
    path = tmp_path / "owners.yaml"
    path.write_text(yaml.safe_dump(doc))
    return str(path)


def test_import_owners_mirrors_the_declared_source(home: Path, tmp_path: Path) -> None:
    logged_in(home)
    run(portfolio_onboard.onboard, home, *REQUEST, "--label", "Example")
    descriptor = {
        "segments": {"services": {"kind": "services"}},
        "org_teams": {ORG: "Platform Team"},
        "assignments": [
            {"repo": EXTRA, "teams": ["Tools Team"]},
            {"repo": "https://github.com/other-org/unknown", "teams": ["Nobody"]},
        ],
    }
    rc, first = run(portfolio_onboard.import_owners, home, "--source", source(tmp_path, descriptor))
    assert rc == 0, first
    assert (len(first["added"]), first["removed"]) == (12, [])
    assert first["skipped"] == ["https://github.com/other-org/unknown"]

    rc, again = run(portfolio_onboard.import_owners, home, "--source", source(tmp_path, descriptor))
    assert (len(again["added"]), sorted(again["unchanged"])) == (0, sorted(first["added"]))

    rc, dropped = run(portfolio_onboard.import_owners, home, "--source", source(tmp_path, {}))
    assert (dropped["added"], sorted(dropped["removed"])) == ([], sorted(first["added"]))


@pytest.mark.parametrize(
    "doc,reason",
    [
        ({"assignments": [{"repo": EXTRA}]}, "not an ownership source"),
        ({"assignments": [{"repo": "https://example.com/a/b", "teams": ["T"]}]}, "host"),
        (["not", "a", "mapping"], "not an ownership source"),
    ],
)
def test_import_owners_refuses_a_malformed_source(
    home: Path, tmp_path: Path, doc: Any, reason: str
) -> None:
    rc, err = run(portfolio_onboard.import_owners, home, "--source", source(tmp_path, doc))
    assert rc == 2 and reason in err, err


def test_import_owners_refuses_a_file_that_is_not_yaml(home: Path, tmp_path: Path) -> None:
    path = tmp_path / "owners.yaml"
    path.write_text("org_teams: {unclosed\n")
    rc, err = run(portfolio_onboard.import_owners, home, "--source", str(path))
    assert rc == 2 and "not an ownership source" in err


def test_import_owners_needs_the_source_file(home: Path, tmp_path: Path) -> None:
    rc, err = run(portfolio_onboard.import_owners, home, "--source", str(tmp_path / "missing.yaml"))
    assert rc == 2 and "missing.yaml" in err
