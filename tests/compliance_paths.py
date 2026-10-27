"""Compliance test paths.

The control-to-check mapping ships with the security pack; the org parameters are
deployment config, read from the config home (the suite's home carries a
labeled-fiction copy).
"""

from __future__ import annotations

from pathlib import Path

from traust.paths import HARNESS_ROOT, SECURITY_PACK_DIR, config_path

REGISTRY = "compliance-mapping.yaml"


def compliance_registry() -> Path:
    """The shipped control-to-check mapping."""
    return SECURITY_PACK_DIR / "compliance" / REGISTRY


def org_parameters() -> Path:
    """org-parameters.yaml from the config home (the suite's fixture copy)."""
    return config_path("org-parameters.yaml")


def org_parameters_template() -> Path:
    return HARNESS_ROOT / "config" / "org-parameters.example.yaml"
