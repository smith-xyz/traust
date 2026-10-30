"""`traust portfolio liveness`: the CLI layer only. Every page of `liveness` becomes one
repo-liveness document keyed by URL, with the artifact's status words and their counts; a typed
error is exit 2 with its reason. What liveness reads is traust-core's tests."""

from __future__ import annotations

import contextlib
import io
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.common import Cursor, Page
from traust_core.v1.models.inventory import Liveness, RepositoryFilter

from traust.cli import portfolio_liveness

WHEN = datetime(2026, 10, 1, tzinfo=UTC)
ACTIVE = Liveness(
    repository_id=uuid.uuid4(),
    url="https://github.com/example-org/active",
    observed_at=WHEN,
    archived=False,
    pushed_at="2026-09-30T12:00:00Z",
    dormant=False,
)
ARCHIVED = Liveness(
    repository_id=uuid.uuid4(),
    url="https://github.com/example-org/archived",
    observed_at=WHEN,
    archived=True,
    pushed_at="2024-01-02T00:00:00Z",
    dormant=True,
)
NEVER = Liveness(
    repository_id=uuid.uuid4(),
    url="https://gitlab.com/example-org/never",
    unobserved="unsupported-host",
    reason="no forge observes this host",
)


@pytest.fixture
def doors(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    pages = [(ARCHIVED, NEVER), (ACTIVE,)]
    stub = SimpleNamespace(calls=[], result=None)

    def liveness(filter: Any, page: Any) -> Page[Liveness]:
        stub.calls.append((filter, page.cursor))
        if isinstance(stub.result, Exception):
            raise stub.result
        index = 0 if page.cursor is None else int(page.cursor)
        last = index == len(pages) - 1
        return Page(items=pages[index], next=None if last else Cursor(str(index + 1)))

    services = SimpleNamespace(portfolio=SimpleNamespace(liveness=liveness))
    monkeypatch.setattr(Context, "services", lambda self: services)
    return stub


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "traust.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def run(home: Path, *argv: str) -> tuple[int, Any]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = portfolio_liveness.main(["--config-home", str(home), *argv])
    text = out.getvalue().strip()
    return rc, json.loads(text) if text else err.getvalue()


def test_liveness_of_every_registered_repository_keyed_by_url(doors, home):
    rc, out = run(home)

    assert rc == 0
    assert out == {
        "counts": {"active": 1, "archived": 1, "unknown": 1},
        "repos": {
            ACTIVE.url: {
                "status": "active",
                "observed_at": WHEN.isoformat().replace("+00:00", "Z"),
                "archived": False,
                "pushed_at": "2026-09-30T12:00:00Z",
                "dormant": False,
            },
            ARCHIVED.url: {
                "status": "archived",
                "observed_at": WHEN.isoformat().replace("+00:00", "Z"),
                "archived": True,
                "pushed_at": "2024-01-02T00:00:00Z",
                "dormant": True,
            },
            NEVER.url: {
                "status": "unknown",
                "unobserved": "unsupported-host",
                "reason": "no forge observes this host",
            },
        },
    }
    assert doors.calls == [(RepositoryFilter(), None), (RepositoryFilter(), "1")]


def test_liveness_refusal_exits_2_with_the_reason(doors, home):
    doors.result = ConfigError("liveness reads observations through AssessmentService")

    rc, err = run(home)

    assert rc == 2
    assert "liveness reads observations through AssessmentService" in err
