"""Tests for traust.cli.fetch_feeds (product-definitions) + enrich_findings_cves.py (C8)."""

import dataclasses
import gzip
import json
import os
import shutil
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from traust_contracts import Locations
from traust_core.v1.context import Context
from traust_core.v1.models.inventory import Product, Repository, Team
from traust_core.v1.providers.base import Acquisition, Readiness, Result
from traust_engine.registry import feeds as pd_feeds

from traust.context import load_core
from traust.paths import skill_dir

_ROOT = Path(__file__).resolve().parents[1]


def _load(name):
    import importlib

    if name == "fetch_feeds":
        return importlib.import_module("traust.cli.fetch_feeds")
    path = skill_dir("secure-code-audit") / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


ff = _load("fetch_feeds")
en = _load("enrich_findings_cves")


@pytest.fixture(autouse=True)
def _product_definitions_configured(monkeypatch):
    """product-definitions is config-gated (locations.product_definitions) since it
    targets a deployment-specific registry. The suite exercises it as a configured
    estate would. Tests that want the open-source default (absent) override it."""
    monkeypatch.setattr(
        ff.locations,
        "configured_locations",
        lambda: Locations(product_definitions="https://feeds.test/product-definitions.json"),
    )


def test_product_definitions_absent_without_config(monkeypatch, tmp_path, capsys):
    """Open-source default: locations.product_definitions unset → the internal
    product registry is not registered at all; nothing is fetched, the run says so."""
    monkeypatch.setattr(ff.locations, "configured_locations", lambda: Locations())
    assert ff.main(["--cache-dir", str(tmp_path)]) == 1
    assert "not configured" in capsys.readouterr().out
    assert not (tmp_path / "product_definitions.json").exists()


URL = "https://feeds.test/product-definitions.json"


def _mk_cache(tmp_path, retrieved_at="2026-07-18T00:00:00Z"):
    cache = tmp_path / "feeds"
    cache.mkdir()
    (cache / "product_definitions.json").write_text(
        json.dumps({"ps_products": {"a": {}}, "ps_modules": {}, "ps_update_streams": {}})
    )
    (cache / "feeds-meta.json").write_text(
        json.dumps({"product-definitions": {"retrieved_at": retrieved_at}})
    )
    return cache


# ---------------- fetch_feeds (product-definitions) ----------------


def test_offline_uses_stale_copy(tmp_path):
    cache = _mk_cache(tmp_path, retrieved_at="2026-01-01T00:00:00Z")
    usable, status = ff.fetch(URL, cache, 24, offline=True)
    assert usable and "STALE" in status


def test_offline_without_copy_fails(tmp_path):
    usable, _status = ff.fetch(URL, tmp_path / "empty", 24, offline=True)
    assert not usable


def test_fresh_copy_skips_download(tmp_path, monkeypatch):
    cache = _mk_cache(tmp_path, retrieved_at=ff._iso(ff._now()))
    monkeypatch.setattr(
        ff.urllib.request,
        "urlopen",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("network touched")),
    )
    usable, status = ff.fetch(URL, cache, 24)
    assert usable and status.startswith("fresh")


def test_failed_refresh_falls_back(tmp_path, monkeypatch):
    cache = _mk_cache(tmp_path, retrieved_at="2026-01-01T00:00:00Z")
    import urllib.error

    monkeypatch.setattr(
        ff.urllib.request,
        "urlopen",
        lambda *a, **k: (_ for _ in ()).throw(urllib.error.URLError("no vpn")),
    )
    usable, status = ff.fetch(URL, cache, 24)
    assert usable and "STALE" in status and "refresh failed" in status


def test_a_refresh_writes_the_registry_and_its_counts(tmp_path, monkeypatch):
    body = json.dumps({"ps_products": {"a": {}, "b": {}}, "ps_modules": {}}).encode()

    class _Resp:
        def read(self):
            return body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(ff.urllib.request, "urlopen", lambda *a, **k: _Resp())
    cache = tmp_path / "feeds"
    assert ff.main(["--cache-dir", str(cache)]) == 0
    assert (cache / "product_definitions.json").read_bytes() == body
    meta = json.loads((cache / "feeds-meta.json").read_text())["product-definitions"]
    assert meta["counts"] == {"ps_modules": 0, "ps_products": 2} and meta["url"] == URL


EPSS_CSV = (
    "#model_version:v2026.06.15,score_date:2026-07-18\n"
    "cve,epss,percentile\n"
    "CVE-2026-1111,0.72000,0.99120\n"
    "CVE-2026-2222,0.00042,0.05000\n"
)
KEV_JSON = {
    "catalogVersion": "2026.07.16",
    "count": 1,
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-3333",
            "dateAdded": "2026-07-01",
            "knownRansomwareCampaignUse": "Known",
            "vulnerabilityName": "Demo RCE",
        }
    ],
}


class _Feed:
    def __init__(self, name, filename, data):
        self.name, self.filename, self.data = name, filename, data
        self.max_age = timedelta(hours=24)

    def check(self):
        return Readiness(ready=True)

    def fetch(self, previous=lambda: None):
        return Result(self.data, Acquisition(provider=self.name, acquired_at=datetime.now(UTC)))


@pytest.fixture
def core_feeds(tmp_path, monkeypatch):
    """A config home whose core store holds EPSS and KEV snapshots (what `traust feeds fetch`
    leaves behind)."""
    home = tmp_path / "config-home"
    shutil.copytree(os.environ["TRAUST_CONFIG_HOME"], home)
    (home / "core.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(home))
    core = load_core(home)
    feeds = (
        _Feed("epss", "epss_scores-current.csv.gz", gzip.compress(EPSS_CSV.encode())),
        _Feed("kev", "known_exploited_vulnerabilities.json", json.dumps(KEV_JSON).encode()),
    )
    for feed in feeds:
        core.feeds.register(feed.name, lambda feed=feed: feed)
    assert all(s.last_error is None for s in core.services().exposure.refresh_feeds())
    return home


# ---------------- enrich_findings_cves ----------------


def test_enrich_items_join(tmp_path):
    epss = {
        "CVE-2026-1111": {"epss": 0.72, "percentile": 0.9912},
        "CVE-2026-2222": {"epss": 0.00042, "percentile": 0.05},
    }
    kev = {"CVE-2026-3333": {"date_added": "2026-07-01", "ransomware": True}}
    items = [
        {"id": "F-1", "description": "fixes CVE-2026-1111 in dep"},
        {"id": "F-2", "title": "ransomware CVE-2026-3333"},
        {"id": "F-3", "title": "no cve here"},
    ]
    out = en.enrich_items(items, epss, kev)
    assert [i["id"] for i in out] == ["F-1", "F-2"]
    assert out[0]["max_epss"] == 0.72 and not out[0]["kev_any"]
    assert out[1]["kev_any"] and out[1]["cves"][0]["kev_ransomware"]


def test_repo_label():
    assert (
        en.repo_label({"metadata": {"repository": "https://github.com/stolostron/foo.git"}})
        == "stolostron/foo"
    )
    assert en.repo_label({"metadata": {"repository": "/tmp/x"}}) is None


@pytest.fixture
def registered(monkeypatch):
    """org/app registered in traust-core, shipped by ACM and owned by example-team."""
    app = Repository(id=uuid.uuid4(), url="https://github.com/org/app", public=True)
    portfolio = SimpleNamespace(
        find_repository=lambda url: app if str(url) == app.url else None,
        list_products_of=lambda repository_id: [Product(id=uuid.uuid4(), slug="acm", name="ACM")],
        list_owners=lambda repository_id: [Team(id=uuid.uuid4(), name="example-team")],
    )
    services = Context.services
    monkeypatch.setattr(
        Context, "services", lambda self: dataclasses.replace(services(self), portfolio=portfolio)
    )


def test_main_end_to_end(tmp_path, monkeypatch, core_feeds, registered):
    artifact = tmp_path / "x-osv-scanner.json"
    artifact.write_text(
        json.dumps(
            {
                "metadata": {"repository": "https://github.com/org/app"},
                "candidates": [{"osv_id": "GHSA-x", "aliases": ["CVE-2026-3333"]}],
            }
        )
    )
    workloads = tmp_path / "workloads.json"
    workloads.write_text(json.dumps(["org/app"]))
    out = tmp_path / "enrich.json"
    rc = en.main(
        [
            "--in",
            str(artifact),
            "--workloads",
            str(workloads),
            "--out",
            str(out),
        ]
    )
    assert rc == 0
    doc = json.loads(out.read_text())
    src = doc["sources"][0]
    assert src["items"][0]["kev_any"] is True
    reach = src["repository_reach"]
    assert reach["products_shipping"] == ["ACM"]
    assert reach["registered"] is True
    assert reach["owner_teams"] == ["example-team"]
    assert reach["deployed"] is True
    assert doc["summary"] == {"items_with_cves": 1, "kev_hits": 1}


def test_main_without_workloads_is_unknown(tmp_path, core_feeds):
    artifact = tmp_path / "y.json"
    artifact.write_text(
        json.dumps(
            {
                "metadata": {"repository": "https://github.com/org/app"},
                "findings": [{"id": "F-9", "title": "CVE-2026-2222 dep"}],
            }
        )
    )
    out = tmp_path / "e2.json"
    rc = en.main(
        [
            "--in",
            str(artifact),
            "--out",
            str(out),
        ]
    )
    assert rc == 0
    doc = json.loads(out.read_text())
    reach = doc["sources"][0]["repository_reach"]
    assert reach["deployed"] == "unknown"
    assert reach["registered"] is False and reach["owner_teams"] == []


# ---------------- product-definitions loader shape guard ----------------


def _write_pd(cache, doc):
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "product_definitions.json").write_text(json.dumps(doc))


def test_load_product_definitions_happy(tmp_path):
    cache = tmp_path / "feeds"
    _write_pd(cache, {"ps_products": {"a": {}}, "ps_modules": {"a-1": {}}, "ps_update_streams": {}})
    doc = pd_feeds.load_product_definitions(cache)
    assert doc["ps_products"] == {"a": {}}


def test_load_product_definitions_raises_on_missing_key(tmp_path):
    """A silent upstream shape change must not read as 'no contacts'."""
    cache = tmp_path / "feeds"
    _write_pd(cache, {"ps_products": {}, "ps_update_streams": {}})
    try:
        pd_feeds.load_product_definitions(cache)
    except ValueError as e:
        assert "ps_modules" in str(e)
    else:
        raise AssertionError("missing ps_modules must raise")


def test_load_product_definitions_raises_on_wrong_type(tmp_path):
    cache = tmp_path / "feeds"
    _write_pd(cache, {"ps_products": {}, "ps_modules": [], "ps_update_streams": {}})
    try:
        pd_feeds.load_product_definitions(cache)
    except ValueError as e:
        assert "ps_modules" in str(e)
    else:
        raise AssertionError("a list where a map belongs must raise")
