"""`traust check drift`: rule-pack, ADR and framework pins vs upstream, policy review dates.
The rest of drift-watch is traust-core's freshness view (core's tests)."""

import json
from pathlib import Path

import pytest

from traust.cli import check_drift as pc


def _remote(monkeypatch, head: str) -> None:
    monkeypatch.setattr(
        pc.subprocess, "run", lambda *a, **k: type("R", (), {"stdout": f"{head}\tHEAD\n"})()
    )


def _unreachable(*a, **k):
    raise OSError("no network")


@pytest.fixture
def home(tmp_path, monkeypatch):
    """An empty config home of the test's own."""
    path = tmp_path / "config-home"
    path.mkdir()
    monkeypatch.setenv("TRAUST_CONFIG_HOME", str(path))
    return path


def test_adr_registry_pending_then_checked(home, monkeypatch):
    assert pc.check_adr_registry()[0]["status"] == "pending"
    (home / "adr-registry.yaml").write_text(
        "registers:\n  - {name: arch, repo: https://x/y.git, pin: aaaa1111}\n"
        "  - {name: local, repo: file:///etc, pin: aaaa}\n"
    )
    _remote(monkeypatch, "bbbb2222")
    rows = {r["item"]: r for r in pc.check_adr_registry()}
    assert rows["adr-registry:arch"]["status"] == "stale"
    assert "superseded" in rows["adr-registry:arch"]["detail"]
    assert rows["adr-registry:local"]["status"] == "unavailable"
    _remote(monkeypatch, "aaaa1111ffff")
    assert pc.check_adr_registry()[0]["status"] == "fresh"
    monkeypatch.setattr(pc.subprocess, "run", _unreachable)
    assert pc.check_adr_registry()[0]["status"] == "unavailable"


def test_adr_registry_without_registers_is_unavailable(home):
    (home / "adr-registry.yaml").write_text("registers: []\n")
    assert pc.check_adr_registry() == [
        pc.item("adr-registry", "unavailable", "registry has no registers")
    ]


def test_provenance_review_due(home, tmp_path):
    (home / "sla-policy.yaml").write_text("source: {retrieved: '2020-01-01'}\n")
    (home / "org-parameters.yaml").write_text(f"declared_on: '{pc._now():%Y-%m-%d}'\n")
    items = {i["item"]: i for i in pc.check_policy_provenance(tmp_path / "none")}
    assert items["provenance:sla-policy"]["status"] == "review_due"
    assert "re-verify" in items["provenance:sla-policy"]["refresh"]
    assert items["provenance:org-parameters"]["status"] == "fresh"
    assert items["provenance:compliance-spine"]["status"] == "pending"


def test_catalog_reviewed_dates_covered(home, tmp_path):
    comp = tmp_path / "compliance-data"
    comp.mkdir()
    (comp / "catalog-pci-dss-v4.yaml").write_text("reviewed: '2020-01-01'\nframework: pci-dss-v4\n")
    (comp / "catalog-gdpr-technical.yaml").write_text("framework: gdpr\n")
    (comp / "provenance.json").write_text("{not json")
    items = {i["item"]: i for i in pc.check_policy_provenance(comp)}
    assert items["provenance:catalog-pci-dss"]["status"] == "review_due"
    assert items["provenance:catalog-soc2-tsc"]["status"] == "pending"
    assert items["provenance:catalog-gdpr"]["status"] == "unavailable"
    assert items["provenance:compliance-spine"]["status"] == "unavailable"
    assert items["provenance:sla-policy"]["status"] == "pending"


def test_framework_upstream_pin_check(tmp_path, monkeypatch):
    assert pc.check_framework_upstream(tmp_path)[0]["status"] == "pending"
    (tmp_path / "provenance.json").write_text(json.dumps({"upstream": "https://x/y"}))
    assert pc.check_framework_upstream(tmp_path)[0]["status"] == "unavailable"
    (tmp_path / "provenance.json").write_text(
        json.dumps({"upstream": "https://x/y", "upstream_head": "aaaa1111"})
    )
    _remote(monkeypatch, "bbbb2222")
    res = pc.check_framework_upstream(tmp_path)[0]
    assert res["status"] == "stale" and "re-deriv" in res["refresh"]
    _remote(monkeypatch, "aaaa1111ff")
    assert pc.check_framework_upstream(tmp_path)[0]["status"] == "fresh"
    monkeypatch.setattr(pc.subprocess, "run", _unreachable)
    assert pc.check_framework_upstream(tmp_path)[0]["status"] == "unavailable"


@pytest.mark.parametrize("check", [pc.check_yara_rules_pin, pc.check_argus_rules_pin])
def test_rule_pack_pins_parse_from_the_engine_adapters(check, monkeypatch):
    """The rows read the pins out of the adapters by regex; a renamed constant degrades the row
    to `unavailable`, never to fresh."""
    _remote(monkeypatch, "f" * 40)
    row = check()[0]
    assert row["status"] == "stale", row["detail"]
    assert "never auto-advanced" in row["refresh"]


def test_a_rule_pack_pin_that_cannot_be_parsed_is_unavailable(monkeypatch):
    monkeypatch.setattr(pc, "_module_text", lambda module: "nothing pinned here")
    assert pc.check_yara_rules_pin()[0]["status"] == "unavailable"
    monkeypatch.setattr(pc, "_module_text", lambda module: None)
    assert pc.check_argus_rules_pin()[0]["status"] == "pending"


def test_argus_pack_is_not_the_default_rules_source():
    """~500 rules uncalibrated against our triage-ledger ground truth must stay opt-in."""
    import traust_engine.adapters.opengrep as _og

    src = Path(_og.__file__).read_text(encoding="utf-8")
    assert "ARGUS_RULES_REPO" in src
    default = src.split("Default (no --rules):", 1)[1][:200]
    assert "traust-authored" in default, default


def test_main_prints_every_row(home, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(pc, "compliance_data_dir", lambda: tmp_path)
    monkeypatch.setattr(pc, "load", lambda: None)
    monkeypatch.setattr(pc, "inputs_dir", lambda core: tmp_path / "inputs")
    monkeypatch.setattr(pc.subprocess, "run", _unreachable)
    assert pc.main([]) == 0
    rows = {r["item"] for r in json.loads(capsys.readouterr().out)["items"]}
    assert {"framework-spine:upstream", "provenance:sla-policy", "adr-registry"} <= rows
    assert {"yara-rules-pin", "argus-rules-pin", "docs-product-map"} <= rows
