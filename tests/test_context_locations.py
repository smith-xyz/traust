"""traust's location helpers read core's ``Config.locations`` and resolve every path the engine did.

``_before`` is the helper code as it was on ``traust_engine.locations``; each row loads one
``locations.yaml`` both ways and the paths must match.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from traust_contracts import DeploymentConfigMissing
from traust_engine import locations as engine_locations

from traust import context
from traust.context import load_core, load_engine
from traust.paths import HARNESS_ROOT

FIXTURE = Path(__file__).parent / "fixtures" / "config"
HELPERS = (
    "analysis_results_dir",
    "workspace_dir",
    "inputs_dir",
    "findings_db",
    "findings_tree_dir",
    "progress_tracker_dir",
    "rule_drafts_dir",
    "feeds_cache_dir",
)


def _before(engine, name: str) -> Path:
    loc, req = engine.ctx.locations, engine_locations.require
    match name:
        case "analysis_results_dir":
            return req(engine_locations.analysis_results_dir(loc), "analysis_results")
        case "workspace_dir":
            return engine_locations.workspace_dir(loc)
        case "inputs_dir":
            val = getattr(loc, "inputs", None) if loc is not None else None
            if val and (p := engine_locations.local_path(val)) is not None:
                return (
                    p if p.is_absolute() else (Path(os.environ["TRAUST_CONFIG_HOME"]) / p).resolve()
                )
            return engine_locations.workspace_dir(loc) / "inputs"
        case "findings_db":
            return req(engine_locations.findings_db(loc), "analysis_results")
        case "findings_tree_dir":
            return _before(engine, "analysis_results_dir") / "findings"
        case "progress_tracker_dir":
            return req(engine_locations.progress_tracker_dir(loc), "progress_tracker")
        case "rule_drafts_dir":
            return req(engine_locations.rule_drafts_dir(loc), "rule_drafts")
        case "feeds_cache_dir":
            if raw := os.environ.get("FEEDS_CACHE_DIR", "").strip():
                return Path(raw).expanduser().resolve()
            cache = engine_locations.feeds_cache_dir(loc)
            return cache or _before(engine, "progress_tracker_dir") / "feeds"
    raise AssertionError(name)


def _home(tmp_path: Path, locations: dict | None) -> Path:
    home = tmp_path / "cfg"
    home.mkdir()
    for f in FIXTURE.iterdir():
        if f.is_file():
            shutil.copy2(f, home / f.name)
    if locations is not None:
        (home / "locations.yaml").write_text(yaml.safe_dump(locations), encoding="utf-8")
    return home


ROWS = {
    "absolute": {"workspace": "/w", "analysis_results": "/ar", "progress_tracker": "/pt"},
    "relative": {"workspace": "./ws", "analysis_results": "../ar", "progress_tracker": "a/../pt"},
    "file uri": {"workspace": "file:///w", "analysis_results": "file:///ar"},
    "remote": {"workspace": "s3://b/w", "analysis_results": "gs://b/ar", "feeds_cache": "az://c"},
    "explicit": {
        "workspace": "/w",
        "analysis_results": "/ar",
        "progress_tracker": "/pt",
        "rule_drafts": "./drafts",
        "feeds_cache": "/fc",
    },
    "inputs relative": {"workspace": "/w", "inputs": "./inv"},
    "inputs absolute": {"workspace": "/w", "inputs": "/inv"},
    "inputs file uri": {"workspace": "/w", "inputs": "file:///inv"},
    "empty strings": {"workspace": "", "analysis_results": "", "progress_tracker": ""},
    "no file": None,
}


def _outcome(fn):
    try:
        return fn()
    except DeploymentConfigMissing:
        return DeploymentConfigMissing


@pytest.mark.parametrize("feeds_env", [None, "~/feeds"], ids=["config", "FEEDS_CACHE_DIR"])
@pytest.mark.parametrize("row", ROWS, ids=list(ROWS))
def test_core_locations_resolve_the_paths_the_engine_did(tmp_path, monkeypatch, row, feeds_env):
    home = _home(tmp_path, ROWS[row])
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(home))
    if feeds_env:
        monkeypatch.setenv("FEEDS_CACHE_DIR", feeds_env)
    else:
        monkeypatch.delenv("FEEDS_CACHE_DIR", raising=False)
    engine, core = load_engine(home), load_core(home)
    for name in HELPERS:
        helper = getattr(context, name)
        expected = _outcome(lambda name=name: _before(engine, name))
        assert _outcome(lambda helper=helper: helper(core)) == expected, name
        assert _outcome(lambda helper=helper: helper(engine)) == expected, name


def test_a_remote_inputs_location_is_refused(tmp_path, monkeypatch):
    """Behaviour change: the engine-era helper fell back to ``<workspace>/inputs``."""
    home = _home(tmp_path, {"workspace": "/w", "inputs": "s3://b/inv"})
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(home))
    with pytest.raises(DeploymentConfigMissing, match="inputs"):
        context.inputs_dir(load_core(home))


@pytest.mark.parametrize("key", ["workspace", "analysis_results", "findings"])
def test_traust_paths_sh_prints_the_configured_path(tmp_path, key):
    home = _home(tmp_path, {"workspace": "/w", "analysis_results": "./ar"})
    lib = HARNESS_ROOT / "harnessing" / "_lib" / "traust_paths.sh"
    out = subprocess.run(
        ["bash", "-c", f'source "{lib}" && _traust_path {key}'],
        env={**os.environ, "TRAUST_CONFIG_HOME": str(home)},
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    expected = {
        "workspace": "/w",
        "analysis_results": home / "ar",
        "findings": home / "ar" / "findings",
    }
    assert out == str(Path(expected[key]).resolve())
