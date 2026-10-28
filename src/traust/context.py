"""The app's single composition root: traust-core's Context with every provider registered.

Every entry point builds it here, once (:func:`load`), and threads it into its workers. Nothing
else in the app calls ``Context``.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from importlib.metadata import version
from pathlib import Path
from typing import TypeVar

from traust_core.v1.context import (
    TRAUST_CONFIG_HOME_DEFAULT,
    Config,
    Context,
    Locations,
    resolve_config_home,
)
from traust_core.v1.errors import AuthenticationError, ConfigError, DeploymentConfigMissing
from traust_core.v1.models.identity import Credential, Principal

from traust.paths import GITLEAKS_CONFIG, HARNESSING_DIR, OPENGREP_RULES_DIR

T = TypeVar("T")

CORE_CONFIG = "core.yaml"
SLA_POLICY = "sla-policy.yaml"
MODEL_REGISTRY = "model-registry.yaml"
EXTERNAL_TOOLS = "external-tools.yaml"
SAFE_EXEC_PROFILES = "safe-exec-profiles.yaml"
# Security-pack content (home: traust-pack-security): the pinned ATT&CK release and its mapping.
_ATTACK = HARNESSING_DIR / "attack-coverage" / "tables"
ATTACK_TABLES = (_ATTACK / "attack-techniques.json", _ATTACK / "attack-mapping.json")
ATLAS_TABLE = _ATTACK / "atlas-techniques.json"  # the pinned MITRE ATLAS release

# ---------------------------------------------------------------------------
# Sanctioned environment overrides — read ONLY in this module, never in consumers.
#
# ``locations.yaml`` owns estate/campaign paths. These env vars are deliberate
# escape hatches for layouts that must not live in checked-in config, plus one
# secret that must never sit in a file or on argv.
# ---------------------------------------------------------------------------
#
# TRAUST_CONFIG_HOME
#   The config home, when no --config-home is given. Consumed by core's
#   ``resolve_config_home``.
#
# XDG_CACHE_HOME
#   Where the recall benchmark commits its canary repositories
#   (``<cache>/recall-bench/<canaries>``). Consumed by :func:`load`.
#
# AUDIT_RESULTS_ROOT
#   Point a one-off run or CI matrix job at an analysis-results tree without
#   editing ``locations.yaml``. Used when the job checks out results elsewhere
#   or shares a prebuilt tree across steps. Consumed by :func:`resolve_results_root`
#   (after an explicit ``--results-root`` CLI flag).
#
# FEEDS_CACHE_DIR
#   Pin the EPSS/KEV/product-definitions pull-through cache to a shared volume,
#   temp dir, or orchestrator-managed path. Feed mirrors are third-party licensed
#   data — intentionally kept out of ``analysis-results/`` (different provenance
#   and retention). Consumed by :func:`feeds_cache_dir`.
#
# TRAUST_OIDC_CLIENT_SECRET
#   A service account's client secret for ``traust auth service-account`` when no
#   ``--client-secret-file`` is given. Consumed by :func:`oidc_client_secret`.
#


def _audit_results_root_from_env() -> Path | None:
    raw = os.environ.get("AUDIT_RESULTS_ROOT")
    if not raw or not str(raw).strip():
        return None
    return Path(str(raw).strip()).expanduser().resolve()


def _feeds_cache_dir_from_env() -> Path | None:
    raw = os.environ.get("FEEDS_CACHE_DIR")
    if not raw or not str(raw).strip():
        return None
    return Path(str(raw).strip()).expanduser().resolve()


def _guarded(what: str, step: Callable[[], T]) -> T:
    try:
        return step()
    except ConfigError as e:
        print(f"{what} not resolvable: {e}", file=sys.stderr)
        raise SystemExit(2) from e


def load(
    config_home: Path | None = None,
    *,
    sla_policy: Path | None = None,
    invoices: Path | None = None,
    canaries: str = "canaries",
    rule_pack: Path | None = None,
    rule_drafts: Path | None = None,
) -> Context:
    """traust-core's Context from ``<config home>/core.yaml`` with every provider registered once,
    or exit 2 when the config is invalid.

    No ``core.yaml``: core's defaults (SQLite and artifacts under ``~/.traust``), the zero-setup
    laptop install, with the home's ``locations.yaml``. The ATT&CK coverage view is built on the
    pack's pinned tables; the SLA view on ``sla_policy``, else on ``<config home>/sla-policy.yaml``
    when there is one (template: config/sla-policy.example.yaml); the spend view on the home's
    model registry when there is one, reconciled against ``invoices``. The tools read the home's
    ``external-tools.yaml`` and ``safe-exec-profiles.yaml`` on first use; detection quality scores
    the rule pack (``rule_pack``, else :func:`_rule_pack`) against canaries from
    ``recall-benchmark/<canaries>`` and stages rule drafts in ``rule_drafts``, else
    ``locations.rule_drafts`` when one resolves.
    """
    home = resolve_config_home(config_home)
    path = home / CORE_CONFIG if home is not None else None
    sla = sla_policy or (home / SLA_POLICY if home is not None else None)
    core = _guarded(
        "core config",
        lambda: Context(
            _with_bundled_rules(
                Config.from_file(path)
                if path is not None and path.is_file()
                else Config(locations=Locations.from_home(home) if home else Locations())
            )
        ),
    )
    _guarded("ATT&CK catalog", lambda: core.register_attack_catalog(*ATTACK_TABLES))
    _guarded("ATLAS catalog", lambda: core.register_atlas_catalog(ATLAS_TABLE))
    if sla is not None and (sla_policy is not None or sla.is_file()):
        _guarded("SLA policy", lambda: core.register_sla_policy(sla))
    if home is not None and (home / MODEL_REGISTRY).is_file():
        _register_spend(core, home / MODEL_REGISTRY, invoices)
    elif invoices is not None:
        print(f"invoices need the spend view: no {MODEL_REGISTRY} in {home}", file=sys.stderr)
        raise SystemExit(2)
    # No home: the default home's paths, so the first tool use names the file it needs.
    files = home or TRAUST_CONFIG_HOME_DEFAULT
    core.register_toolchain(files / EXTERNAL_TOOLS, files / SAFE_EXEC_PROFILES)
    pack, pack_version = (
        (rule_pack, f"local:{rule_pack}") if rule_pack else _rule_pack(core.config.locations)
    )
    core.register_rule_pack(pack)
    cache = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    core.register_detection_quality(
        pack_version, files / "recall-benchmark" / canaries, cache / "recall-bench" / canaries
    )
    if drafts := rule_drafts or core.config.locations.rule_drafts_dir():
        core.register_rule_drafts(drafts)
    core.register_fleet_fix()
    core.register_compliance_sources()
    return core


def _with_bundled_rules(config: Config) -> Config:
    """``config`` with the pack's gitleaks config when ``locations.gitleaks_config`` is unset."""
    if config.locations.gitleaks_config:
        return config
    locations = config.locations.model_copy(update={"gitleaks_config": str(GITLEAKS_CONFIG)})
    return config.model_copy(update={"locations": locations})


def _rule_pack(locations: Locations) -> tuple[Path, str]:
    """The opengrep rule pack and its version: ``locations.opengrep_rules``, else the pack's."""
    if raw := locations.opengrep_rules:
        pack = Path(raw.removeprefix("file://"))
        return pack, f"local:{pack}"
    return OPENGREP_RULES_DIR, version("traust")


def load_spend_core(config_home: Path | None = None) -> Context:
    """``load_core`` pricing spend on ``<config home>/model-registry.yaml`` (template:
    config/model-registry.yaml); exit 2 when it is missing or invalid."""
    core = load(config_home)
    if core.model_catalog is None:
        home = resolve_config_home(config_home)
        _register_spend(core, (home or Path()) / MODEL_REGISTRY, None)
    return core


def _register_spend(core: Context, registry: Path, invoices: Path | None) -> None:
    try:
        core.register_model_catalog(registry)
        if invoices is not None:
            core.register_invoices(invoices)
    except ConfigError as e:
        print(f"spend not resolvable: {e}", file=sys.stderr)
        raise SystemExit(2) from e


def load_caller(core: Context) -> Principal:
    """Who is calling: the stored login (``traust auth``), verified by core's identity service."""
    if core.identity is None:
        raise ConfigError(
            "no identity: section in core.yaml; a solo install adds `identity: {trust_local: true}`"
            " to accept its own `traust auth local` tokens"
        )
    login = core.credentials.load()
    if login is None:
        raise AuthenticationError("not logged in: run `traust auth login` or `traust auth local`")
    return core.identity.authenticate(Credential(token=login.grant.access_token))


def oidc_client_secret() -> str | None:
    raw = os.environ.get("TRAUST_OIDC_CLIENT_SECRET", "").strip()
    return raw or None


def add_config_home_arg(parser) -> None:
    """Standard --config-home flag so every CLI resolves config the same way."""
    parser.add_argument(
        "--config-home",
        type=Path,
        default=None,
        help="TRAUST config home (default: $TRAUST_CONFIG_HOME)",
    )


def locations(src: Context) -> Locations:
    return src.config.locations


def _required(value: Callable[[], Path | None], name: str) -> Path:
    """A location from core, or :class:`DeploymentConfigMissing` naming it (what callers catch)."""
    try:
        return Locations.require(value(), name)
    except ConfigError as e:
        raise DeploymentConfigMissing(str(e)) from e


def analysis_results_dir(src: Context) -> Path:
    """Configured local analysis-results root (fail-loud when unset)."""
    return _required(locations(src).analysis_results_dir, "analysis_results")


def workspace_dir(src: Context) -> Path:
    """Configured workspace root (fail-loud when unset)."""
    return _required(locations(src).workspace_dir, "workspace")


def inputs_dir(src: Context) -> Path:
    """The repository-inventory tree: ``locations.inputs``, else ``<workspace>/inputs``."""
    return _required(locations(src).inputs_dir, "inputs")


def _optional_config(name: str) -> dict:
    """``$TRAUST_CONFIG_HOME/<name>`` as a dict, or {} when the file is absent.

    For the small per-flow settings files (``remediation.yaml``,
    ``campaign.yaml``) that ship as ``config/*.example.yaml`` templates. Read
    directly rather than through the contracts manifest, which lists the
    schema-gated files; a schema for these is a contracts follow-up.
    """
    home = resolve_config_home()
    if home is None:
        return {}
    path = home / name
    if not path.is_file():
        return {}
    import yaml  # local import: only these two settings files need it here

    data = yaml.safe_load(path.read_text()) or {}
    return data if isinstance(data, dict) else {}


def _normalise_host(value: str) -> str:
    """``https://gitlab.example.com/group/`` → ``gitlab.example.com``."""
    h = str(value).strip().lower()
    h = h.split("://", 1)[-1]
    h = h.split("/", 1)[0]
    return h.strip(". ")


def _private_forge_hosts(cfg: dict) -> tuple[str, ...]:
    raw = os.environ.get("HARNESS_PRIVATE_FORGE_HOSTS")
    if raw and raw.strip():
        values: list = raw.split(",")
    else:
        values = cfg.get("private_forge_hosts") or []
        if isinstance(values, str):
            values = values.split(",")
        elif not isinstance(values, list):
            values = []
    return tuple(dict.fromkeys(h for h in (_normalise_host(v) for v in values) if h))


def remediation_settings() -> dict:
    """remediate-finding's deployment settings — ``fork_org``,
    ``naming_prefix`` and ``private_forge_hosts`` — from ``remediation.yaml``
    in the config home, each overridable by ``HARNESS_FORK_ORG`` /
    ``REMEDIATION_PREFIX`` / ``HARNESS_PRIVATE_FORGE_HOSTS`` in the
    environment. ``fork_org`` has no shipped default: the private mirror
    organisation is the adopter's (decision D5, 2026-09-07); callers fail loud
    when it is unset. ``naming_prefix`` defaults to ``traust``.
    ``private_forge_hosts`` defaults to empty — naming an organisation's
    internal forge is deployment config, never a shipped constant.
    """
    cfg = _optional_config("remediation.yaml")
    fork_org = os.environ.get("HARNESS_FORK_ORG") or str(cfg.get("fork_org") or "").strip()
    prefix = (
        os.environ.get("REMEDIATION_PREFIX") or str(cfg.get("naming_prefix") or "traust").strip()
    )
    if fork_org in ("", "example-org"):
        fork_org = ""
    return {
        "fork_org": fork_org,
        "naming_prefix": prefix,
        "private_forge_hosts": _private_forge_hosts(cfg),
    }


def private_forge_hosts() -> tuple[str, ...]:
    """Hosts of self-hosted forges whose repositories ARE their own downstream
    fork — remediation lands in place rather than in a mirror. Empty unless the
    deployment lists them in ``remediation.yaml``; see
    ``config/remediation.example.yaml``.
    """
    return remediation_settings()["private_forge_hosts"]


def require_fork_org() -> str:
    org = remediation_settings()["fork_org"]
    if not org:
        raise SystemExit(
            "remediate-finding: no private mirror organisation configured — set "
            "fork_org in $TRAUST_CONFIG_HOME/remediation.yaml (template: "
            "config/remediation.example.yaml) or HARNESS_FORK_ORG in the environment"
        )
    return org


def campaign_settings() -> dict:
    """``campaign.yaml`` in the config home: ``tracking_reference`` (the
    issue-tracker key dashboards cite) and ``display_name``. Both optional;
    dashboards omit the line when unset."""
    cfg = _optional_config("campaign.yaml")
    return {
        "tracking_reference": str(cfg.get("tracking_reference") or "").strip(),
        "display_name": str(cfg.get("display_name") or "").strip(),
    }


def findings_db(src: Context) -> Path:
    """``<analysis-results>/graph/findings.db`` (fail-loud when unset)."""
    return _required(locations(src).findings_db, "analysis_results")


def progress_tracker_dir(src: Context) -> Path:
    """Configured progress-tracker root (fail-loud when unset)."""
    return _required(locations(src).progress_tracker_dir, "progress_tracker")


def rule_drafts_dir(src: Context) -> Path:
    """Configured rule-drafts root (fail-loud when unset)."""
    return _required(locations(src).rule_drafts_dir, "rule_drafts")


def feeds_cache_dir(src: Context) -> Path:
    """Feeds pull-through cache: ``FEEDS_CACHE_DIR`` > config > ``progress_tracker/feeds``."""
    override = _feeds_cache_dir_from_env()
    if override is not None:
        return override
    return locations(src).feeds_cache_dir() or progress_tracker_dir(src) / "feeds"


def findings_tree_dir(src: Context) -> Path:
    """``<analysis-results>/findings`` (fail-loud when analysis_results unset)."""
    return analysis_results_dir(src) / "findings"


def resolve_results_root(args=None, *, config_home: Path | None = None) -> Path:
    """``--results-root`` > ``$AUDIT_RESULTS_ROOT`` > ``locations.analysis_results``.

    Exits 2 when ``analysis_results`` is unset. Pass ``args`` from argparse after
    :func:`add_config_home_arg`.
    """
    if args is not None and getattr(args, "results_root", None):
        return Path(args.results_root).expanduser().resolve()
    if args is not None and config_home is None and getattr(args, "config_home", None):
        config_home = args.config_home
    override = _audit_results_root_from_env()
    if override is not None:
        return override
    try:
        return analysis_results_dir(load(config_home)).resolve()
    except DeploymentConfigMissing as e:
        print(f"config not resolvable: {e}", file=sys.stderr)
        raise SystemExit(2) from e
