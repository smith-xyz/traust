"""`traust pqc xcrypto`: the CLI layer only. The checkout and --callgraph become one
`PqcService.xcrypto_tracker` call on the registered commit; the rules are traust-core's tests."""

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
from traust_core.v1.errors import ConfigError
from traust_core.v1.models.common import ToolRequest
from traust_core.v1.models.pqc import XcryptoRow, XcryptoStatus, XcryptoTier, XcryptoTracker

from traust.cli import pqc

URL = "https://github.com/acme/widget"
SHA = "f1b29843254b34f95ee1b36f1accca0380070962"
REF = uuid.uuid4()
ROW = XcryptoRow(
    product_org="acme",
    repository=URL,
    package="golang.org/x/crypto/ssh",
    evidence_tier=XcryptoTier.FIRST_PARTY_IMPORT,
    status_suggested=XcryptoStatus.UNACCEPTABLE,
    evidence="cmd/app/main.go:7",
)
CSV = "product_org,repository\nacme,https://github.com/acme/widget\n"


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, ...]]:
    seen: list[tuple[Any, ...]] = []
    registered: list[tuple[Any, ...]] = []

    def tracker(ref_id: uuid.UUID, request: ToolRequest) -> XcryptoTracker:
        seen.append((ref_id, request))
        if request.params.get("callgraph") and not (Path(request.workspace) / "go.mod").exists():
            raise ConfigError("go-callgraph is not ready: callgraph not on PATH")
        return XcryptoTracker(rows=(ROW,), csv=CSV)

    services = SimpleNamespace(
        pqc=SimpleNamespace(xcrypto_tracker=tracker),
        portfolio=SimpleNamespace(
            register_repository=lambda url, public: (
                registered.append((str(url), public)) or SimpleNamespace(id=uuid.uuid4())
            ),
            register_ref=lambda *_: SimpleNamespace(id=REF),
        ),
    )
    monkeypatch.setattr(Context, "services", lambda self: services)
    seen.append(("registered", registered))
    return seen


@pytest.fixture
def home(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    (config / "core.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    return config


def run(home: Path, *argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = pqc.xcrypto(["--config-home", str(home), "--repo-url", URL, "--sha", SHA, *argv])
    return rc, out.getvalue(), err.getvalue()


def test_rows_of_the_registered_commit_static_by_default(
    calls: list[tuple[Any, ...]], home: Path, tmp_path: Path
) -> None:
    rc, out, _ = run(home, str(tmp_path), "--public")
    assert rc == 0, out
    assert json.loads(out) == [ROW.model_dump(mode="json")]
    (_, registered), (ref_id, request) = calls
    assert registered == [(URL, True)]
    assert (ref_id, request) == (REF, ToolRequest(workspace=tmp_path, params={"callgraph": False}))


def test_callgraph_registers_the_tool_and_csv_prints_the_workbook(
    calls: list[tuple[Any, ...]], home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registered: list[Context] = []
    monkeypatch.setattr(pqc, "register_go_callgraph", registered.append)
    (tmp_path / "go.mod").write_text("module m\n")
    rc, out, _ = run(home, str(tmp_path), "--callgraph", "--csv")
    assert (rc, out) == (0, CSV)
    assert calls[1][1].params == {"callgraph": True}
    assert len(registered) == 1 and isinstance(registered[0], Context)


def test_callgraph_without_the_tool_is_exit_2(
    calls: list[tuple[Any, ...]], home: Path, tmp_path: Path
) -> None:
    rc, out, err = run(home, str(tmp_path), "--callgraph")
    assert (rc, out) == (2, "")
    assert "go-callgraph is not ready" in err


def test_the_checkout_is_required(calls: list[tuple[Any, ...]], home: Path) -> None:
    with pytest.raises(SystemExit) as e:
        run(home)
    assert e.value.code == 2
    assert len(calls) == 1  # only the registration log, no door call
