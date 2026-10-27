"""`traust.context.load` is the one loader: every command gets a Context on which
`Context.services()` sees every registered provider."""

from __future__ import annotations

import shutil
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from traust_core.v1.context import Context

from traust import context
from traust.context import load

ROOT = Path(__file__).resolve().parents[1]
TOOLS = {"checkov", "gitleaks", "gitleaks-history", "govulncheck", "grype", "joern"}
TOOLS |= {"opengrep", "osv", "osv_sbom", "yara"}


@pytest.fixture(scope="module")
def core(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Context]:
    tmp = tmp_path_factory.mktemp("load")
    home = tmp / "config"
    shutil.copytree(ROOT / "tests" / "fixtures" / "config", home)
    (home / "core.yaml").write_text(yaml.safe_dump({"home": str(tmp / "store")}))
    shutil.copy(ROOT / "config" / "sla-policy.example.yaml", home / "sla-policy.yaml")
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("XDG_CACHE_HOME", str(tmp / "cache"))
        yield load(home)


PROVIDERS: dict[str, Callable[[Context], Any]] = {
    "rule packs": lambda c: c.services().detection_quality.rule_packs(),
    "tools": lambda c: {b.capability.name for b in c.services().catalog.readiness(None)} >= TOOLS,
    "tool floors": lambda c: c.tools.get("gitleaks") and c.tool_floors.get("gitleaks"),
    "canaries": lambda c: c.canaries.check().detail,
    "adr source": lambda c: c.adr_source,
    "docs source": lambda c: c.doc_source,
    "fleet-fix applier": lambda c: c.fleet_fix_applier,
    "fleet-fix goldens": lambda c: c.fleet_fix_goldens,
    "sla policy": lambda c: c.sla_policy,
    "attack catalog": lambda c: c.attack_catalog,
}


@pytest.mark.parametrize("provider", PROVIDERS)
def test_the_context_sees_every_registered_provider(core: Context, provider: str) -> None:
    assert PROVIDERS[provider](core)


def test_the_context_is_the_only_loader() -> None:
    loaders = {n for n in vars(context) if n.startswith("load")}
    # NEED(engine facade): load_engine stays for the grouped ops; load_caller is identity;
    # load_spend_core is load() that requires the model registry (exit 2 without it).
    assert loaders == {"load", "load_engine", "load_caller", "load_spend_core"}
