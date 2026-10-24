"""``traust inventory …``: add-inputs' and inventory-repositories' doors on traust-core."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

INVENTORY: dict[str, object] = {
    "plan": passthrough_op("inventory", "What onboard would register, writing nothing.", "plan"),
    "onboard": passthrough_op("inventory", "Register a product's repositories.", "onboard"),
    "owner-hints": passthrough_op("inventory", "Who may own a repository.", "owner_hints"),
    "import-owners": passthrough_op(
        "inventory", "Mirror the declared ownership source.", "import_owners"
    ),
}
