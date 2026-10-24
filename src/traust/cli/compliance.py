"""``traust compliance declare|scopes|resolve``: compliance-check's boundary doors on traust-core.

declare  record one boundary declaration (a compliance-scope document); signed only when you, the
         verified caller, are its declarant, otherwise DRAFT; an existing boundary needs --replace
scopes   the current declaration of each boundary, newest first
resolve  a boundary's repositories now, under its current declaration
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import yaml
from traust_core.v1.context import Services
from traust_core.v1.errors import NotFoundError
from traust_core.v1.models.artifacts import ComplianceScopeArtifact
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.compliance import ComplianceScope, ScopeFilter

from traust.cli._doors import parser, run
from traust.context import load_caller, load_core, load_services


def declare(argv: list[str] | None = None) -> int:
    ap = parser("compliance", "declare", "Record one compliance boundary declaration.")
    ap.add_argument("scope", type=Path, help="a compliance-scope document (YAML) of one boundary")
    ap.add_argument("--replace", action="store_true", help="supersede the boundary's declaration")
    args = ap.parse_args(argv)

    def call() -> str:
        core = load_core(args.config_home)
        doc = ComplianceScopeArtifact.from_document(yaml.safe_load(args.scope.read_text()))
        scope = core.services().compliance.set_scope(doc, load_caller(core), replace=args.replace)
        return scope.model_dump_json(indent=2)

    return run(call)


def scopes(argv: list[str] | None = None) -> int:
    ap = parser("compliance", "scopes", "The current declaration of each boundary.")
    ap.add_argument("--framework", help="only boundaries declaring this framework")
    ap.add_argument("--product", help="only boundaries of this product")
    drafts = ap.add_mutually_exclusive_group()
    drafts.add_argument("--draft", action="store_true", help="only unsigned declarations")
    drafts.add_argument("--signed", action="store_true", help="only signed declarations")
    ap.add_argument("--limit", type=int, default=100)
    ap.add_argument("--cursor", help="the previous page's `next`")
    args = ap.parse_args(argv)
    draft = True if args.draft else False if args.signed else None

    def call() -> str:
        page = load_services(args.config_home).compliance.scopes(
            ScopeFilter(framework=args.framework, product=args.product, draft=draft),
            PageRequest(limit=args.limit, cursor=args.cursor),
        )
        return page.model_dump_json(indent=2)

    return run(call)


def current(services: Services, boundary: str) -> ComplianceScope:
    """A boundary's current declaration, by scope id or by boundary name."""
    try:
        return services.compliance.get_scope(UUID(boundary))
    except ValueError:
        pass
    page, cursor = None, None
    while page is None or cursor:
        page = services.compliance.scopes(ScopeFilter(), PageRequest(limit=500, cursor=cursor))
        if found := next((s for s in page.items if s.boundary == boundary), None):
            return found
        cursor = page.next
    raise NotFoundError(f"no compliance boundary {boundary!r} is declared")


def resolve(argv: list[str] | None = None) -> int:
    ap = parser("compliance", "resolve", "A boundary's repositories under its current declaration.")
    ap.add_argument("boundary", help="the boundary name or its scope id")
    args = ap.parse_args(argv)

    def call() -> str:
        services = load_services(args.config_home)
        scope = current(services, args.boundary)
        assert scope.scope_id is not None
        return services.compliance.resolve(scope.scope_id).model_dump_json(indent=2)

    return run(call)
