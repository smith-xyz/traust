"""``traust products list|add|update``: corpus-intake's doors on traust-core.

list    every product with its corpus ownership and business unit
add     register a product (name = slug, label = display name) with its ownership
update  change a registered product's label, ownership or business unit
"""

from __future__ import annotations

from typing import Any

from traust_core.v1.errors import NotFoundError, ValidationError
from traust_core.v1.models.artifacts import CorpusRegistryArtifact
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.corpus import CorpusRegistry, CorpusSubject
from traust_core.v1.models.inventory import Product
from traust_core.v1.models.values import ProductSlug
from traust_core.v1.models.vocabulary import OwnershipClass

from traust.cli._doors import parser, run
from traust.context import load_services

OWNERSHIP = [o.value for o in OwnershipClass]


def _registry(doc: CorpusRegistryArtifact | None) -> CorpusRegistry:
    return CorpusRegistry() if doc is None else CorpusRegistry.of(doc)


def _subject(doc: CorpusRegistryArtifact | None, product: Product) -> CorpusSubject | None:
    return _registry(doc).subject(str(product.id))


def _row(product: Product, subject: CorpusSubject | None) -> dict[str, Any]:
    return {
        "name": product.slug,
        "label": product.name,
        "ownership": None if subject is None else subject.ownership,
        "business_unit": None if subject is None else subject.business_unit,
        "product_id": product.id,
    }


def list_(argv: list[str] | None = None) -> int:
    args = parser("products", "list", "Every product with its corpus ownership.").parse_args(argv)

    def call() -> list[dict[str, Any]]:
        portfolio = load_services(args.config_home).portfolio
        registry = _registry(portfolio.corpus_registry())
        out, page = [], PageRequest()
        while True:
            got = portfolio.list_products(page)
            out += [_row(p, registry.subject(str(p.id))) for p in got.items]
            if got.next is None:
                return out
            page = PageRequest(cursor=got.next)

    return run(call)


def add(argv: list[str] | None = None) -> int:
    ap = parser("products", "add", "Register a product with its corpus ownership.")
    ap.add_argument("name", help="the product slug: letters, digits, . _ - only")
    ap.add_argument("--label", required=True, help="the display name")
    ap.add_argument("--ownership", required=True, choices=OWNERSHIP)
    ap.add_argument("--business-unit", required=True)
    args = ap.parse_args(argv)

    def call() -> dict[str, Any]:
        portfolio = load_services(args.config_home).portfolio
        product = portfolio.register_product(ProductSlug.parse(args.name), args.label)
        if (subject := _subject(portfolio.corpus_registry(), product)) is not None:
            return _row(product, subject)  # registered already: unchanged, changes go by update
        owned = OwnershipClass(args.ownership)
        doc = portfolio.set_corpus_ownership(product.id, owned, args.business_unit)
        return _row(product, _subject(doc, product))

    return run(call)


def update(argv: list[str] | None = None) -> int:
    ap = parser("products", "update", "Change a registered product's label or ownership.")
    ap.add_argument("name")
    ap.add_argument("--label")
    ap.add_argument("--ownership", choices=OWNERSHIP)
    ap.add_argument("--business-unit")
    args = ap.parse_args(argv)

    def call() -> dict[str, Any]:
        portfolio = load_services(args.config_home).portfolio
        product = portfolio.find_product(ProductSlug.parse(args.name))
        if product is None:
            raise NotFoundError(f"no product named {args.name!r}")
        if args.label is not None:
            product = portfolio.update_product(product.id, args.label)
        subject = _subject(portfolio.corpus_registry(), product)
        if args.ownership is None and args.business_unit is None:
            return _row(product, subject)
        if subject is None and None in (args.ownership, args.business_unit):
            raise ValidationError(f"{args.name!r} has no ownership yet: give both fields")
        ownership = OwnershipClass(args.ownership or subject.ownership)
        business_unit = args.business_unit or subject.business_unit
        doc = portfolio.set_corpus_ownership(product.id, ownership, business_unit)
        return _row(product, _subject(doc, product))

    return run(call)
