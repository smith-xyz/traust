"""`traust registry models` (list, resolve, validate, stamp) on traust-core's ModelCatalog, against
traust-engine's `registry/models.py` on the same registry. (The products parity went with the
engine's `registry/products.py`, deleted in traust-engine#113; core's product-definition tests
own that behaviour.)

The engine side goes when lane (f) drops traust-engine; the parity it proves stays proven.
"""

from __future__ import annotations

import contextlib
import io
import json
from types import SimpleNamespace
from typing import Any

import pytest

# delete with the engine (final-drop follow-up)
from traust.cli.groups import registry
from traust.cli.groups._registry import load_engine


def call(fn: Any, args: Any) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = fn(args)
    return rc, out.getvalue(), err.getvalue()


def models(cmd: str, **kw: Any) -> tuple[int, str, str]:
    return call(registry.call_models, SimpleNamespace(config_home=None, cmd=cmd, **kw))


def test_list_matches_the_engine() -> None:
    reg = load_engine().models.registry()
    expected = [
        f"{role:22s} floor={r.floor:13s} approved={','.join(r.approved)}"
        for role, r in sorted(reg.roles.items())
    ]
    assert models("list") == (0, "\n".join(expected) + "\n", "")


def test_validate_matches_the_engine() -> None:
    assert load_engine().models.validate() == []
    assert models("validate") == (0, "model registry: OK\n", "")


@pytest.mark.parametrize(
    ("role", "tier"),
    [
        ("fact-judge", None),
        ("fact-judge", "sonnet-class"),
        ("fact-judge", "mythos-class"),
        ("deep-audit", None),
    ],
)
def test_resolve_matches_the_engine(role: str, tier: str | None) -> None:
    expected = load_engine().models.resolve(role, tier)
    assert models("resolve", role=role, tier=tier) == (0, f"{expected}\n", "")


@pytest.mark.parametrize(
    ("role", "tier", "message"),
    [
        ("no-such-role", None, "unknown role 'no-such-role' — roles: ["),
        ("fact-judge", "nope-class", "unknown tier 'nope-class'"),
        ("deep-audit", "haiku-class", "tier-downs below the floor are never allowed"),
    ],
)
def test_an_unresolvable_role_exits_1_naming_why(role: str, tier: str | None, message: str) -> None:
    with pytest.raises((KeyError, ValueError)):
        load_engine().models.resolve(role, tier)
    rc, out, err = models("resolve", role=role, tier=tier)
    assert (rc, out) == (1, "") and message in err


@pytest.mark.parametrize("role", ["fact-judge", "no-such-role"])
def test_stamp_matches_the_engine(role: str) -> None:
    expected = load_engine().models.stamp(role, "claude-x")
    assert models("stamp", role=role, model="claude-x") == (0, json.dumps(expected) + "\n", "")
