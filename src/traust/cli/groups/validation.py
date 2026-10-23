"""Machine-validation recording doors on traust-core."""

from traust.cli.groups._registry import passthrough_op

VALIDATION: dict[str, object] = {
    "record": passthrough_op(
        "validation", "Record validation evidence with explicit source bindings.", "record"
    ),
}
