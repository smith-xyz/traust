"""`traust registry models` (list, resolve, validate, stamp) on traust-core's ModelCatalog and
`traust registry products` on PortfolioService.resolve_products, against traust-engine's
`registry/models.py` and `registry/products.py` on the same registry and cache.

The engine side goes when lane (f) drops traust-engine; the parity it proves stays proven.
"""

from __future__ import annotations

import contextlib
import io
import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from traust_engine.registry import products

from traust.cli.groups import registry
from traust.cli.groups._registry import load_engine

PRODUCT_DEFINITIONS = Path(__file__).parent / "fixtures" / "registry" / "product-definitions"
PRODUCT_MAP = {
    "mappings": {
        "packages": {"gizmo-findings": "gizmo"},
        "repos": {"https://github.com/acme/mapped": "relic"},
    }
}
QUERIES = {
    "packages": ["widget-core", "gizmo-findings", "nope"],
    "repo_urls": ["https://github.com/acme/widget-api", "https://github.com/acme/mapped", "x"],
    "products": ["gizmo", "missing"],
}


def call(fn: Any, args: Any) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = fn(args)
    return rc, out.getvalue(), err.getvalue()


def models(cmd: str, **kw: Any) -> tuple[int, str, str]:
    return call(registry.call_models, SimpleNamespace(config_home=None, cmd=cmd, **kw))


def test_list_matches_the_engine() -> None:
    reg = load_engine().models.registry()
    expected = [
        f"{role:22s} floor={r.floor:13s} approved={','.join(r.approved)}"
        for role, r in sorted(reg.roles.items())
    ]
    assert models("list") == (0, "\n".join(expected) + "\n", "")


def test_validate_matches_the_engine() -> None:
    assert load_engine().models.validate() == []
    assert models("validate") == (0, "model registry: OK\n", "")


@pytest.mark.parametrize(
    ("role", "tier"),
    [
        ("fact-judge", None),
        ("fact-judge", "sonnet-class"),
        ("fact-judge", "mythos-class"),
        ("deep-audit", None),
    ],
)
def test_resolve_matches_the_engine(role: str, tier: str | None) -> None:
    expected = load_engine().models.resolve(role, tier)
    assert models("resolve", role=role, tier=tier) == (0, f"{expected}\n", "")


@pytest.mark.parametrize(
    ("role", "tier", "message"),
    [
        ("no-such-role", None, "unknown role 'no-such-role' — roles: ["),
        ("fact-judge", "nope-class", "unknown tier 'nope-class'"),
        ("deep-audit", "haiku-class", "tier-downs below the floor are never allowed"),
    ],
)
def test_an_unresolvable_role_exits_1_naming_why(role: str, tier: str | None, message: str) -> None:
    with pytest.raises((KeyError, ValueError)):
        load_engine().models.resolve(role, tier)
    rc, out, err = models("resolve", role=role, tier=tier)
    assert (rc, out) == (1, "") and message in err


@pytest.mark.parametrize("role", ["fact-judge", "no-such-role"])
def test_stamp_matches_the_engine(role: str) -> None:
    expected = load_engine().models.stamp(role, "claude-x")
    assert models("stamp", role=role, model="claude-x") == (0, json.dumps(expected) + "\n", "")


@pytest.fixture
def cache(tmp_path: Path) -> Path:
    return Path(shutil.copytree(PRODUCT_DEFINITIONS, tmp_path / "feeds"))


@pytest.fixture
def product_map(tmp_path: Path) -> Path:
    path = tmp_path / "product-definitions-map.yaml"
    path.write_text(yaml.safe_dump(PRODUCT_MAP))
    return path


def engine_products(**kw: Any) -> tuple[str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        products.resolve_queries(**kw)
    return out.getvalue(), err.getvalue()


def products_args(**kw: Any) -> Any:
    values = {"config_home": None, "package": [], "repo_url": [], "product": [], "all": False}
    return SimpleNamespace(**{**values, "map": None, "cache_dir": None, "json": False, **kw})


@pytest.mark.parametrize("json_only", [False, True])
def test_products_match_the_engine(cache: Path, product_map: Path, json_only: bool) -> None:
    out, err = engine_products(
        **QUERIES, map_path=product_map, cache_dir=cache, json_only=json_only
    )
    args = products_args(
        package=QUERIES["packages"],
        repo_url=QUERIES["repo_urls"],
        product=QUERIES["products"],
        map=product_map,
        cache_dir=cache,
        json=json_only,
    )
    assert call(registry.call_products, args) == (0, out, err)


def test_an_unavailable_cache_matches_the_engine(tmp_path: Path) -> None:
    out, err = engine_products(packages=["widget-core"], cache_dir=tmp_path, all_packages=True)
    args = products_args(package=["widget-core"], cache_dir=tmp_path, all=True)
    assert call(registry.call_products, args) == (0, out, err)
    assert json.loads(out)["source_status"] == "unavailable" and err == ""


def tracked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """A config home whose progress tracker is under tmp_path (the engine reads it the same way)."""
    tracker, home = tmp_path / "progress-tracker", tmp_path / "config"
    home.mkdir()
    (home / "locations.yaml").write_text(yaml.safe_dump({"progress_tracker": str(tracker)}))
    monkeypatch.setattr(products, "_default_packages_dir", lambda: tracker / "processed-results")
    return home, tracker / "processed-results"


def test_all_without_processed_results_warns_after_the_map_warnings(
    cache: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, _ = tracked(tmp_path, monkeypatch)
    broken = tmp_path / "broken-map.yaml"
    broken.write_text("mappings: [unclosed")
    out, err = engine_products(map_path=broken, cache_dir=cache, all_packages=True)
    args = products_args(config_home=home, map=broken, cache_dir=cache, all=True)
    assert call(registry.call_products, args) == (0, out, err)
    warnings = json.loads(out)["warnings"]
    assert "unparseable" in warnings[0] and "--all resolved no packages" in warnings[1]


def test_all_resolves_every_processed_results_package(
    cache: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, processed = tracked(tmp_path, monkeypatch)
    for name in ("widget-core-findings", "gizmo-findings", ".hidden"):
        (processed / name).mkdir(parents=True)
    out, err = engine_products(cache_dir=cache, all_packages=True, json_only=True)
    args = products_args(config_home=home, cache_dir=cache, all=True, json=True)
    assert call(registry.call_products, args) == (0, out, err)
    assert [r["query"]["value"] for r in json.loads(out)["results"]] == [
        "gizmo-findings",
        "widget-core-findings",
    ]
