"""Compliance test paths.

The control-to-check mapping ships with traust-engine; the org parameters are
deployment config, read from the config home (the suite's home carries a
labeled-fiction copy).
"""

from __future__ import annotations

from pathlib import Path

from traust_contracts import config_path
from traust_engine.assets import compliance_data_dir

from traust.paths import HARNESS_ROOT

REGISTRY = "compliance-mapping.yaml"


def compliance_registry() -> Path:
    """The shipped control-to-check mapping."""
    return compliance_data_dir() / REGISTRY


def org_parameters() -> Path:
    """org-parameters.yaml from the config home (the suite's fixture copy)."""
    return config_path("org-parameters.yaml")


def org_parameters_template() -> Path:
    return HARNESS_ROOT / "config" / "org-parameters.example.yaml"
