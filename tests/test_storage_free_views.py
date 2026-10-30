"""The live spend view, `attribute-spend` and `registry products` read files only: on a fresh
install they never create the record store (`<core home>/traust.db`)."""

from __future__ import annotations

import contextlib
import io
import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from traust_core.v1.context import Context
from traust_core.v1.providers.transcripts import SessionTranscripts

from traust.cli.groups import metrics, registry

REGISTRY = Path(__file__).resolve().parents[1] / "config" / "model-registry.yaml"
PRODUCT_DEFINITIONS = Path(__file__).parent / "fixtures" / "registry" / "product-definitions"
WORKSPACE = Path("/w/workspace")
DAY = "2026-10-05"


@pytest.fixture
def config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    project = tmp_path / "projects" / "-w-workspace"
    project.mkdir(parents=True)
    usage = {"input_tokens": 1200, "output_tokens": 300}
    record = {
        "timestamp": f"{DAY}T08:00:00Z",
        "message": {"model": "claude-opus-5-5", "usage": usage},
    }
    (project / "s1.jsonl").write_text(json.dumps(record) + "\n")
    monkeypatch.setattr(Context, "session_transcripts", SessionTranscripts(tmp_path / "projects"))
    home = tmp_path / "config"
    home.mkdir()
    (home / "model-registry.yaml").write_text(REGISTRY.read_text())
    (home / "traust.yaml").write_text(f"home: {tmp_path / 'store'}\n")
    return home


def run(fn: Any, args: Any) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        rc = fn(args)
    return rc, out.getvalue()


def spend_args(config: Path, **kw: Any) -> Any:
    values = {"workspace": WORKSPACE, "date": DAY, "month": None, "json": False, "append": False}
    return SimpleNamespace(config_home=config, reconcile=False, **{**values, **kw})


@pytest.mark.parametrize(
    ("call", "kw"),
    [
        (metrics.call_collect_spend, {}),
        (metrics.call_attribute_spend, {}),
        (metrics.call_attribute_spend, {"json": True}),
    ],
)
def test_the_spend_views_never_create_the_record_store(
    config: Path, tmp_path: Path, call: Any, kw: dict[str, Any]
) -> None:
    rc, out = run(call, spend_args(config, **kw))
    assert rc == 0 and out
    assert not (tmp_path / "store" / "traust.db").exists()


def test_registry_products_never_creates_the_record_store(config: Path, tmp_path: Path) -> None:
    cache = shutil.copytree(PRODUCT_DEFINITIONS, tmp_path / "feeds")
    args = SimpleNamespace(
        config_home=config,
        package=["widget-core"],
        repo_url=[],
        product=[],
        all=False,
        map=None,
        cache_dir=Path(cache),
        json=True,
    )
    rc, out = run(registry.call_products, args)
    assert rc == 0 and json.loads(out)["results"]
    assert not (tmp_path / "store" / "traust.db").exists()


def test_appending_spend_does_record(config: Path, tmp_path: Path) -> None:
    rc, _ = run(metrics.call_collect_spend, spend_args(config, append=True))
    assert rc == 0
    assert (tmp_path / "store" / "traust.db").exists()
