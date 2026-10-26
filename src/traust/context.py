"""The app's single composition root: traust-core's Context with every provider registered.

Every entry point builds it here, once (:func:`load`), and threads it into its workers. Nothing
else in the app calls ``Context`` or ``HarnessEngine.load()``.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

from traust_contracts import DeploymentConfigMissing
from traust_contracts.config import TRAUST_CONFIG_HOME_DEFAULT, TRAUST_CONFIG_HOME_ENV
from traust_core.v1.context import Config, Context, Locations
from traust_core.v1.errors import AuthenticationError, ConfigError
from traust_core.v1.models.identity import Credential, Principal
from traust_engine import HarnessEngine

from traust._tools import register_providers
from traust.paths import HARNESSING_DIR

T = TypeVar("T")
# NEED(engine facade): an engine until the last load_engine caller moves to load.
LocationSource = Context | HarnessEngine

CORE_CONFIG = "core.yaml"
SLA_POLICY = "sla-policy.yaml"
# Security-pack content (home: traust-pack-security): the pinned ATT&CK release and its mapping.
_ATTACK = HARNESSING_DIR / "attack-coverage" / "tables"
ATTACK_TABLES = (_ATTACK / "attack-techniques.json", _ATTACK / "attack-mapping.json")

# ---------------------------------------------------------------------------
# Sanctioned environment overrides — read ONLY in this module, never in consumers.
#
# ``locations.yaml`` owns estate/campaign paths. These env vars are deliberate
# escape hatches for layouts that must not live in checked-in config, plus one
# secret that must never sit in a file or on argv.
# ---------------------------------------------------------------------------
#
# TRAUST_CONFIG_HOME
#   The config home, when no --config-home is given. Consumed by
#   :func:`resolve_config_home`.
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


def resolve_config_home(config_home: Path | None = None) -> Path | None:
    """``config_home``, else ``$TRAUST_CONFIG_HOME``, else ``~/.traust/config`` when it exists.

    PENDING(core Bindings loader): the same rule as contracts, until core's loader owns it.
    """
    if config_home is not None:
        return config_home
    if raw := os.environ.get(TRAUST_CONFIG_HOME_ENV):
        return Path(raw).expanduser()
    return TRAUST_CONFIG_HOME_DEFAULT if TRAUST_CONFIG_HOME_DEFAULT.is_dir() else None


def load_engine(config_home: Path | None = None) -> HarnessEngine:
    """Resolve the engine facade, or exit 2 with a one-line message (no traceback).

    NEED(engine facade): only the grouped ``traust <group> <op>`` ops still on ``HarnessEngine``
    namespaces (adapters, metrics, portfolio, registry, reporting, sweep, util) and the callers
    listed in the plan's step-1 table; everything else goes through :func:`load`.
    """
    try:
        return HarnessEngine.load(config_home=config_home)
    except DeploymentConfigMissing as e:
        print(f"config not resolvable: {e}", file=sys.stderr)
        raise SystemExit(2) from e


def _guarded(what: str, step: Callable[[], T]) -> T:
    try:
        return step()
    except ConfigError as e:
        print(f"{what} not resolvable: {e}", file=sys.stderr)
        raise SystemExit(2) from e


def load(
    config_home: Path | None = None, *, sla_policy: Path | None = None, canaries: str = "canaries"
) -> Context:
    """traust-core's Context from ``<config home>/core.yaml`` with every provider registered once,
    or exit 2 when the config is invalid.

    No ``core.yaml``: core's defaults (SQLite and artifacts under ``~/.traust``), the zero-setup
    laptop install, with the home's ``locations.yaml``. The ATT&CK coverage view is built on the
    pack's pinned tables; the SLA view on ``sla_policy``, else on ``<config home>/sla-policy.yaml``
    when there is one (template: config/sla-policy.example.yaml). The engine's providers
    (``recall-benchmark/<canaries>`` for the canary source) load the engine on first use.
    """
    home = resolve_config_home(config_home)
    path = home / CORE_CONFIG if home is not None else None
    sla = sla_policy or (home / SLA_POLICY if home is not None else None)
    core = _guarded(
        "core config",
        lambda: (
            Context.from_file(path)
            if path is not None and path.is_file()
            else Context(Config(locations=Locations.from_home(home) if home else Locations()))
        ),
    )
    _guarded("ATT&CK catalog", lambda: core.register_attack_catalog(*ATTACK_TABLES))
    if sla is not None and (sla_policy is not None or sla.is_file()):
        _guarded("SLA policy", lambda: core.register_sla_policy(sla))
    # NEED(engine Policy): the tools' config still comes from the engine facade, loaded lazily.
    register_providers(core, lambda: HarnessEngine.load(config_home=home), canaries=canaries)
    return core


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


def locations(src: LocationSource) -> Locations:
    """core's ``Config.locations``. An engine (callers still on ``load_engine``) gets the same
    ``locations.yaml`` read by core, so both resolve every path the same way."""
    return (
        src.config.locations
        if isinstance(src, Context)
        else Locations.from_home(src.ctx.config_home)
    )


def _required(value: Callable[[], Path | None], name: str) -> Path:
    """A location from core, or :class:`DeploymentConfigMissing` naming it (what callers catch)."""
    try:
        return Locations.require(value(), name)
    except ConfigError as e:
        raise DeploymentConfigMissing(str(e)) from e


def analysis_results_dir(src: LocationSource) -> Path:
    """Configured local analysis-results root (fail-loud when unset)."""
    return _required(locations(src).analysis_results_dir, "analysis_results")


def workspace_dir(src: LocationSource) -> Path:
    """Configured workspace root (fail-loud when unset)."""
    return _required(locations(src).workspace_dir, "workspace")


def inputs_dir(src: LocationSource) -> Path:
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


def findings_db(src: LocationSource) -> Path:
    """``<analysis-results>/graph/findings.db`` (fail-loud when unset)."""
    return _required(locations(src).findings_db, "analysis_results")


def progress_tracker_dir(src: LocationSource) -> Path:
    """Configured progress-tracker root (fail-loud when unset)."""
    return _required(locations(src).progress_tracker_dir, "progress_tracker")


def rule_drafts_dir(src: LocationSource) -> Path:
    """Configured rule-drafts root (fail-loud when unset)."""
    return _required(locations(src).rule_drafts_dir, "rule_drafts")


def feeds_cache_dir(src: LocationSource) -> Path:
    """Feeds pull-through cache: ``FEEDS_CACHE_DIR`` > config > ``progress_tracker/feeds``."""
    override = _feeds_cache_dir_from_env()
    if override is not None:
        return override
    return locations(src).feeds_cache_dir() or progress_tracker_dir(src) / "feeds"


def findings_tree_dir(src: LocationSource) -> Path:
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
