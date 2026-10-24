"""`traust remediation fleet-targets|fleet-record|fleet-apply`: the CLI layer only. Arguments become one door
call; the answer is printed as JSON; a typed error is exit 2. The doors are traust-core's tests."""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.errors import (
    ForbiddenError,
    IntegrityError,
    NotFoundError,
    ServiceError,
    ValidationError,
)
from traust_core.v1.models.artifacts import FleetFixArtifact
from traust_core.v1.models.remediation import FleetScope, FleetTarget, PatchResult

from traust.cli import remediation

SPEC = Path(__file__).parents[1] / "harnessing/7-remediate/fleet-fix/specs"
REPO = "https://github.com/example-org/example-service"
REPO_ID, PACKAGE_ID = uuid.uuid4(), uuid.uuid4()
TARGET = FleetTarget(repository_id=REPO_ID, url=REPO, product_reach=2, evidence="named")


class Door:
    def __init__(self, result: Any) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.result = result

    def __call__(self, *args: Any) -> Any:
        self.calls.append(args)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


@pytest.fixture
def doors(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    stub = SimpleNamespace(
        fleet_targets=Door([TARGET]),
        record=Door(SimpleNamespace(model_dump=lambda mode: {"fleet_fix_id": "f"})),
    )
    services = SimpleNamespace(
        remediation=SimpleNamespace(fleet_targets=stub.fleet_targets, record=stub.record),
        portfolio=SimpleNamespace(
            find_repository=lambda url: SimpleNamespace(id=REPO_ID) if str(url) == REPO else None
        ),
    )
    monkeypatch.setattr(Context, "services", lambda self: services)
    return stub


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "core.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def run(door: Any, home: Path, *argv: str) -> tuple[int, Any]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = door(["--config-home", str(home), *argv])
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


@pytest.mark.parametrize(
    ("argv", "scope"),
    [
        (("--cwe", "CWE-1104"), FleetScope(cwe="CWE-1104")),
        (("--package-id", str(PACKAGE_ID)), FleetScope(package_id=PACKAGE_ID)),
        (("--repo-url", REPO), FleetScope(repository_ids=(REPO_ID,))),
    ],
)
def test_targets_is_one_door_call_with_the_scope(
    doors: SimpleNamespace, home: Path, argv: tuple[str, ...], scope: FleetScope
) -> None:
    rc, out = run(remediation.fleet_targets, home, *argv)
    assert (rc, out) == (0, [TARGET.model_dump(mode="json")])
    assert doors.fleet_targets.calls == [(scope,)]


def test_targets_writes_out(doors: SimpleNamespace, home: Path, tmp_path: Path) -> None:
    out = tmp_path / "fleet.json"
    assert run(remediation.fleet_targets, home, "--cwe", "CWE-79", "-o", str(out)) == (0, "")
    assert json.loads(out.read_text())[0]["url"] == REPO


@pytest.mark.parametrize(
    "argv",
    [
        (),
        ("--cwe", "CWE-79", "--repo-url", REPO),
        ("--cwe", "XSS"),
    ],
)
def test_targets_needs_exactly_one_valid_scope(
    doors: SimpleNamespace, home: Path, argv: tuple[str, ...]
) -> None:
    with pytest.raises(SystemExit):
        run(remediation.fleet_targets, home, *argv)
    assert doors.fleet_targets.calls == []


def test_targets_refusals_are_exit_2(doors: SimpleNamespace, home: Path) -> None:
    rc, err = run(remediation.fleet_targets, home, "--repo-url", "https://github.com/x/unknown")
    assert rc == 2 and "not registered" in err
    doors.fleet_targets.result = NotFoundError("package not found")
    rc, err = run(remediation.fleet_targets, home, "--package-id", str(PACKAGE_ID))
    assert rc == 2 and "package not found" in err


def test_record_parses_a_yaml_spec(doors: SimpleNamespace, home: Path) -> None:
    rc, out = run(remediation.fleet_record, home, str(SPEC / "konflux-mutable-pipelineref.yaml"))
    assert (rc, out) == (0, {"fleet_fix_id": "f"})
    [(doc, _)] = doors.record.calls
    assert isinstance(doc, FleetFixArtifact) and doc.id == "konflux-mutable-pipelineref"


def test_record_refusals_are_exit_2(doors: SimpleNamespace, home: Path, tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("matcher: [unclosed")
    assert run(remediation.fleet_record, home, str(bad))[0] == 2
    bad.write_text("id: only-an-id\n")
    assert run(remediation.fleet_record, home, str(bad))[0] == 2
    assert doors.record.calls == []
    doors.record.result = ValidationError("golden test failed")
    rc, err = run(remediation.fleet_record, home, str(SPEC / "tls-verify-enable.yaml"))
    assert rc == 2 and "golden test failed" in err


# `fleet-apply`: one door call on a Context carrying the engine's applier; the run order the
# door checks (leased, for this repository) is the caller's. Kept apart from `doors` so the
# fleet-targets / fleet-record stubs above stay as they were.

FIX_ID, ORDER_ID, REF_ID, ASSESSMENT_ID = (uuid.uuid4() for _ in range(4))
PATCH = PatchResult(
    files_changed=(".tekton/push.yaml",),
    diff="--- a/.tekton/push.yaml\n+++ b/.tekton/push.yaml\n",
    fleet_fix_id=FIX_ID,
    repository_ref_id=REF_ID,
    assessment_id=ASSESSMENT_ID,
)
CONFIG = Path(__file__).parent / "fixtures" / "config"


@pytest.fixture
def applier(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> SimpleNamespace:
    stub = SimpleNamespace(apply=Door(PATCH), wired=[])

    def services(self: Context) -> SimpleNamespace:
        stub.wired.append(self.fleet_fix_applier is not None)
        return SimpleNamespace(
            remediation=SimpleNamespace(apply_fleet_fix=stub.apply),
            portfolio=SimpleNamespace(
                find_repository=lambda url: (
                    SimpleNamespace(id=REPO_ID) if str(url) == REPO else None
                )
            ),
        )

    monkeypatch.setattr(Context, "services", services)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    return stub


@pytest.fixture
def engine_home(tmp_path: Path) -> Path:
    config = tmp_path / "engine-config"
    shutil.copytree(CONFIG, config)
    (config / "core.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def apply(home: Path, *argv: str) -> tuple[int, Any]:
    return run(remediation.fleet_apply, home, str(FIX_ID), *argv)


def test_apply_is_one_door_call_through_the_engine_applier(
    applier: SimpleNamespace, engine_home: Path
) -> None:
    rc, out = apply(engine_home, "--repo-url", REPO, "--order", str(ORDER_ID))
    assert (rc, out) == (0, PATCH.model_dump(mode="json"))
    assert applier.apply.calls == [(FIX_ID, REPO_ID, ORDER_ID)]
    assert applier.wired and all(applier.wired)


def test_apply_writes_out(applier: SimpleNamespace, engine_home: Path, tmp_path: Path) -> None:
    out = tmp_path / "patch.json"
    argv = ("--repo-url", REPO, "--order", str(ORDER_ID), "-o", str(out))
    assert apply(engine_home, *argv) == (0, "")
    assert json.loads(out.read_text())["files_changed"] == [".tekton/push.yaml"]


@pytest.mark.parametrize(
    "argv",
    [
        ("--repo-url", REPO),
        ("--order", str(ORDER_ID)),
        ("--repo-url", REPO, "--order", "not-a-uuid"),
    ],
)
def test_apply_needs_a_repository_and_an_order(
    applier: SimpleNamespace, engine_home: Path, argv: tuple[str, ...]
) -> None:
    with pytest.raises(SystemExit):
        apply(engine_home, *argv)
    assert applier.apply.calls == []


def test_apply_unregistered_repository_is_exit_2(
    applier: SimpleNamespace, engine_home: Path
) -> None:
    rc, err = apply(
        engine_home, "--repo-url", "https://github.com/x/unknown", "--order", str(ORDER_ID)
    )
    assert rc == 2 and "not registered" in err
    assert applier.apply.calls == []


@pytest.mark.parametrize(
    "refusal",
    [
        ForbiddenError(f"run order {ORDER_ID} is not a leased order for repository {REPO_ID}"),
        IntegrityError("fleet fix konflux changed files outside its file_glob: ['README.md']"),
        ValidationError("guard: 9 files changed exceeds max_files_changed=5"),
        ServiceError("git clone failed"),
    ],
)
def test_apply_door_refusals_are_exit_2(
    applier: SimpleNamespace, engine_home: Path, refusal: Exception
) -> None:
    applier.apply.result = refusal
    rc, err = apply(engine_home, "--repo-url", REPO, "--order", str(ORDER_ID))
    assert rc == 2 and str(refusal) in err
