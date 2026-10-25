"""``traust adapters route-guards|config-matrix|sanitizers|fork-lag|priv-profile``: the
deterministic pre-scans on traust-core's code facts. Each reads a checkout and records nothing;
every result is a candidate worklist the audit judges, never a finding.

route-guards    the route x guard matrix (go-http, django-drf, flask), asymmetry groups first
config-matrix   effective deployed defaults as (key, default, sink) triples
sanitizers      sanitizer-shaped Python functions (discovery only; probing executes target code
                and is `probe_sanitizers.py --run`)
fork-lag        fork / vendored-upstream signals, then the advisories whose range holds each
                tracked upstream version (unless --offline)
priv-profile    an operator's privilege profile (tiers 1-2): the operator-priv-profile document
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from traust_core.v1.models.code_facts import CodeFactKind
from traust_core.v1.models.common import ToolRequest

from traust.cli._doors import parser, run
from traust.context import load_core, load_services
from traust.registry.feeds_config import registry_path


def _parser(op: str, about: str) -> argparse.ArgumentParser:
    ap = parser("adapters", op, about)
    ap.add_argument("checkout", type=Path, help="the checkout to read (read-only)")
    ap.add_argument("--out", type=Path, help="write the JSON here (default: stdout)")
    return ap


def _emit(doc: dict, out: Path | None) -> dict:
    if out is None:
        return doc
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    counts = {k: len(v) for k, v in doc.items() if isinstance(v, list)}
    return {"wrote": str(out), **counts}


def route_guards(argv: list[str] | None = None) -> int:
    ap = _parser("route-guards", "A checkout's route x guard matrix.")
    ap.add_argument(
        "--resolve-handlers",
        action="store_true",
        help="place each handler at its definition through the symbol index",
    )
    args = ap.parse_args(argv)

    def call() -> dict:
        matrix = load_services(args.config_home).code_facts.route_guards(
            ToolRequest(workspace=args.checkout), resolve_handlers=args.resolve_handlers
        )
        return _emit(matrix.model_dump(mode="json"), args.out)

    return run(call)


def config_matrix(argv: list[str] | None = None) -> int:
    args = _parser("config-matrix", "A checkout's effective deployed defaults.").parse_args(argv)

    def call() -> dict:
        [matrix] = load_services(args.config_home).code_facts.enumerate(
            CodeFactKind.CONFIG, ToolRequest(workspace=args.checkout)
        )
        return _emit(matrix.model_dump(mode="json", by_alias=True), args.out)

    return run(call)


def sanitizers(argv: list[str] | None = None) -> int:
    args = _parser("sanitizers", "A checkout's sanitizer-shaped functions.").parse_args(argv)

    def call() -> dict:
        found = load_services(args.config_home).code_facts.enumerate(
            CodeFactKind.SANITIZER, ToolRequest(workspace=args.checkout)
        )
        return _emit({"candidates": [c.model_dump(mode="json") for c in found]}, args.out)

    return run(call)


def fork_lag(argv: list[str] | None = None) -> int:
    ap = _parser("fork-lag", "A checkout's fork signals and its upstreams' in-range advisories.")
    ap.add_argument("--offline", action="store_true", help="fork detection only, no advisory read")
    args = ap.parse_args(argv)

    def call() -> dict:
        core = load_core(args.config_home)
        core.register_feeds(registry_path())  # advisories come from the registry's osv source
        fork = core.services().code_facts.fork_lag(
            ToolRequest(workspace=args.checkout), offline=args.offline
        )
        return _emit(fork.model_dump(mode="json"), args.out)

    return run(call)


def priv_profile(argv: list[str] | None = None) -> int:
    ap = _parser("priv-profile", "A checkout's operator privilege profile (tiers 1-2).")
    ap.add_argument("--name", required=True, help="the repository name the profile carries")
    args = ap.parse_args(argv)

    def call() -> dict:
        doc = load_services(args.config_home).code_facts.priv_profile(
            ToolRequest(workspace=args.checkout), args.name
        )
        return _emit(json.loads(doc.payload), args.out)

    return run(call)
