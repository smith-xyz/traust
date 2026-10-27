"""``traust registry …`` — model registry and product catalog."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.operations import ModelName

from traust.cli.groups._registry import OpSpec, load_engine
from traust.context import load, load_spend_core
from traust.paths import optional_config_path

PRODUCT_MAP = "product-definitions-map.yaml"


def add_models_args(ap) -> None:
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("validate")
    sub.add_parser("list")
    p = sub.add_parser("resolve")
    p.add_argument("role")
    p.add_argument("--tier", default=None)
    p = sub.add_parser("stamp")
    p.add_argument("role")
    p.add_argument("model")
    p = sub.add_parser("spend")
    p.add_argument("--skill", required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--tokens-in", type=int, default=0, help="best-effort; omit when unknown")
    p.add_argument("--tokens-out", type=int, default=0, help="best-effort; omit when unknown")
    p.add_argument("--cache-read", type=int, default=0)
    p.add_argument("--cache-creation", type=int, default=0)
    p.add_argument("--batch", default=None)
    p.add_argument("--repo", default=None, help="repo slug this spend audited (calibration tuple)")
    p.add_argument("--loc", type=int, default=None, help="target size in LoC/bytes at audit time")
    p.add_argument("--note", default=None)


def call_models(args) -> int:
    if args.cmd == "spend":
        return _declare_spend(args)
    catalog = load_spend_core(args.config_home).model_catalog
    if args.cmd == "validate":
        errors = catalog.validate()
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        print(f"model registry: {'OK' if not errors else f'{len(errors)} error(s)'}")
        return 1 if errors else 0
    if args.cmd == "list":
        for r in catalog.list_roles():
            print(f"{r.name:22s} floor={r.floor:13s} approved={','.join(r.approved)}")
        return 0
    if args.cmd == "resolve":
        try:
            print(catalog.resolve_role(args.role, args.tier))
            return 0
        except (NotFoundError, ValidationError) as e:
            print(str(e), file=sys.stderr)
            return 1
    if args.cmd == "stamp":
        routing = catalog.stamp(args.role, ModelName(args.model))
        print(json.dumps(routing.model_dump(mode="json", exclude_none=True)))
        return 0
    return 2


def _declare_spend(args) -> int:
    # wave 2 lane (c): PENDING(decision: metrics journal — retire or port to OpsService timeline)
    engine = load_engine(args.config_home)
    try:
        engine.metrics._progress_tracker()
    except FileNotFoundError:  # contracts' DeploymentConfigMissing
        msg = (
            "spend: progress-tracker not configured — declaration skipped; "
            "the embedding platform records usage itself"
        )
        if os.environ.get("HARNESS_REQUIRE_SPEND_LEDGER") == "1":
            print(msg + " (HARNESS_REQUIRE_SPEND_LEDGER=1: failing)", file=sys.stderr)
            return 1
        print(msg, file=sys.stderr)
        return 0
    row = engine.models.spend_row(
        args.model,
        args.tokens_in,
        args.tokens_out,
        args.cache_read,
        args.cache_creation,
        repo=args.repo,
        loc=args.loc,
    )
    if args.batch:
        row["batch"] = args.batch
    engine.metrics.append(f"model-spend:{args.skill}", row, note=args.note or "")
    return 0


MODELS = OpSpec(
    add_args=add_models_args,
    call=call_models,
    help="Model registry validate, list, resolve, stamp, spend",
)


def add_products_args(ap) -> None:
    ap.add_argument(
        "--package",
        action="append",
        default=[],
        help="findings package name (-findings suffix optional)",
    )
    ap.add_argument("--repo-url", action="append", default=[])
    ap.add_argument("--product", action="append", default=[], help="ps_product id")
    ap.add_argument(
        "--all",
        action="store_true",
        help="propose a match for every package under processed-results/",
    )
    ap.add_argument("--map", type=Path, default=optional_config_path(PRODUCT_MAP))
    ap.add_argument("--cache-dir", type=Path, default=None)
    ap.add_argument("--json", action="store_true", help="JSON only, no human-readable summary")


def call_products(args) -> int:
    core = load(args.config_home)
    snapshot = core.product_definitions(args.cache_dir).read()
    mappings = core.product_mappings(args.map)
    packages, unresolved = list(args.package), None
    if args.all and snapshot.document is not None:
        tracker = core.config.locations.progress_tracker_dir()
        packages_dir = tracker / "processed-results" if tracker else None
        if packages_dir and packages_dir.is_dir():
            packages += sorted(
                p.name for p in packages_dir.iterdir() if p.is_dir() and not p.name.startswith(".")
            )
        else:
            unresolved = f"{packages_dir} not found — --all resolved no packages"
    resolution = core.product_lookup.resolve_products(
        snapshot, mappings, packages, args.repo_url, args.product
    )
    out = resolution.model_dump(mode="json", exclude_unset=True)
    if unresolved:
        out.setdefault("warnings", []).insert(len(mappings.warnings), unresolved)
    print(json.dumps(out, indent=2))
    if snapshot.document is not None and not args.json:
        _summarise(out)
    return 0


def _summarise(out: dict) -> None:
    lines = ["", f"# source_status={out['source_status']}"]
    for r in out["results"]:
        q = r["query"]
        lines.append(
            f"{q['kind']}={q['value']}  tier={r['match_tier']}  "
            f"lifecycle={r['lifecycle']['state']}  "
            f"embargo_cc={r['embargo_cc']}"
        )
        for c in r["contacts"]:
            flag = " [embargo-cleared]" if c["embargo_cleared"] else ""
            lines.append(f"    {c['kerberos_id']:14} tier{c['tier']} {c['field']}{flag}")
        if r["match_tier"] == "slug":
            lines.append("    (advisory slug match — confirm into the map)")
    for w in out.get("warnings") or []:
        lines.append(f"! {w}")
    print("\n".join(lines), file=sys.stderr)


PRODUCTS = OpSpec(
    add_args=add_products_args,
    call=call_products,
    help="Resolve ownership context from the product registry",
)
