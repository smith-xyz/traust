"""``traust session …`` — skill sessions started headless for continuous-ops orders."""

from __future__ import annotations

from traust.cli.groups._registry import passthrough_op

SESSION: dict[str, object] = {
    "run": passthrough_op("session", "Start a skill session headless for a pack order.", "run"),
}
