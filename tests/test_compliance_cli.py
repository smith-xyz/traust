"""`traust compliance declare|scopes|resolve`: the CLI layer only. Arguments become the
`ComplianceService` door calls; a refused input is exit 2. The doors are traust-core's tests."""

from __future__ import annotations

import contextlib
import io
import json
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.errors import ConflictError
from traust_core.v1.models.artifacts import ComplianceScopeArtifact
from traust_core.v1.models.common import Page, PageRequest
from traust_core.v1.models.compliance import ComplianceScope, ScopeFilter

from traust.cli import compliance

DECLARATION = {
    "version": 1,
    "updated": "2026-10-24",
    "boundaries": {
        "widget-prod": {
            "frameworks": ["nist-800-53-rev5"],
            "resolves_via": "explicit",
            "include": [{"repo": "acme/widget", "reason": "the service"}],
            "declared_by": "jdoe",
            "declared_at": "2026-10-24",
        }
    },
}


def scope(boundary: str) -> ComplianceScope:
    return ComplianceScope(
        scope_id=uuid.uuid4(),
        boundary=boundary,
        frameworks=("nist-800-53-rev5",),
        resolves_via="explicit",
        declared_by="jdoe",
        declared_at="2026-10-24",
    )


WIDGET, OTHER = scope("widget-prod"), scope("other")
CALLER = object()


class Door:
    def __init__(self, result: Any) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.result = result

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append((*args, *kwargs.items()))
        result = self.result(*args) if callable(self.result) else self.result
        if isinstance(result, Exception):
            raise result
        return result


class Dumps:
    def __init__(self, body: dict) -> None:
        self.body = body

    def model_dump_json(self, **_: Any) -> str:
        return json.dumps(self.body)


@pytest.fixture
def doors(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    pages = {
        None: Page(items=(OTHER,), next="c1"),
        "c1": Page(items=(WIDGET,), next=None),
    }
    stub = SimpleNamespace(
        set_scope=Door(Dumps({"boundary": "widget-prod"})),
        scopes=Door(lambda f, page: pages[page.cursor]),
        get_scope=Door(lambda scope_id: WIDGET),
        resolve=Door(Dumps({"members": []})),
    )
    services = SimpleNamespace(compliance=stub)
    monkeypatch.setattr(Context, "services", lambda self: services)
    monkeypatch.setattr(compliance, "load_caller", lambda core: CALLER)
    return stub


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "core.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def call(op: str, home: Path, *argv: str) -> tuple[int, Any]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = getattr(compliance, op)(["--config-home", str(home), *argv])
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


@pytest.fixture
def declaration(tmp_path: Path) -> Path:
    path = tmp_path / "scope.yaml"
    path.write_text(yaml.safe_dump(DECLARATION))
    return path


@pytest.mark.parametrize(("flags", "replace"), [((), False), (("--replace",), True)])
def test_declare_records_the_document_as_the_verified_caller(
    doors: SimpleNamespace, home: Path, declaration: Path, flags: tuple[str, ...], replace: bool
) -> None:
    rc, out = call("declare", home, str(declaration), *flags)
    assert (rc, out) == (0, {"boundary": "widget-prod"})
    ((doc, caller, kwarg),) = doors.set_scope.calls
    assert isinstance(doc, ComplianceScopeArtifact) and caller is CALLER
    assert kwarg == ("replace", replace)


def test_declaring_an_existing_boundary_is_exit_2(
    doors: SimpleNamespace, home: Path, declaration: Path
) -> None:
    doors.set_scope.result = ConflictError("boundary 'widget-prod' already declared")
    rc, err = call("declare", home, str(declaration))
    assert rc == 2 and "already declared" in err


def test_a_declaration_that_fails_its_schema_is_exit_2(
    doors: SimpleNamespace, home: Path, tmp_path: Path
) -> None:
    bad = tmp_path / "bad.yaml"
    entry = {**DECLARATION["boundaries"]["widget-prod"], "frameworks": ["nist-800-53-r5"]}
    bad.write_text(yaml.safe_dump({**DECLARATION, "boundaries": {"widget-prod": entry}}))
    rc, err = call("declare", home, str(bad))
    assert rc == 2 and "frameworks" in err
    assert not doors.set_scope.calls


@pytest.mark.parametrize(
    ("flags", "wanted"),
    [
        ((), ScopeFilter()),
        (("--draft",), ScopeFilter(draft=True)),
        (("--signed", "--product", "widget"), ScopeFilter(draft=False, product="widget")),
        (("--framework", "soc2-tsc"), ScopeFilter(framework="soc2-tsc")),
    ],
)
def test_scopes_pass_the_filter_and_page(
    doors: SimpleNamespace, home: Path, flags: tuple[str, ...], wanted: ScopeFilter
) -> None:
    rc, out = call("scopes", home, *flags)
    assert rc == 0 and out["next"] == "c1"
    assert doors.scopes.calls == [(wanted, PageRequest())]


def test_resolve_finds_a_boundary_by_name_across_pages(doors: SimpleNamespace, home: Path) -> None:
    rc, out = call("resolve", home, "widget-prod")
    assert (rc, out) == (0, {"members": []})
    assert doors.resolve.calls == [(WIDGET.scope_id,)]
    assert len(doors.scopes.calls) == 2


def test_resolve_takes_a_scope_id(doors: SimpleNamespace, home: Path) -> None:
    rc, _ = call("resolve", home, str(WIDGET.scope_id))
    assert rc == 0
    assert doors.get_scope.calls == [(WIDGET.scope_id,)]
    assert not doors.scopes.calls


def test_an_undeclared_boundary_is_exit_2(doors: SimpleNamespace, home: Path) -> None:
    rc, err = call("resolve", home, "nope")
    assert rc == 2 and "'nope'" in err
    assert not doors.resolve.calls


def test_a_superseded_declaration_is_exit_2(doors: SimpleNamespace, home: Path) -> None:
    doors.resolve.result = ConflictError("compliance scope is superseded")
    rc, err = call("resolve", home, str(WIDGET.scope_id))
    assert rc == 2 and "superseded" in err
