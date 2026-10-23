"""Registration contract for ``traust <group> <op>`` handlers."""

from __future__ import annotations

import argparse
import importlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from traust_engine import HarnessEngine


class OpHandler(Protocol):
    help: str

    def add_args(self, ap) -> None: ...

    def call(self, engine: HarnessEngine, args) -> int: ...


@dataclass(frozen=True)
class OpSpec:
    add_args: Callable
    call: Callable[[HarnessEngine, object], int]
    help: str = ""
    passthrough_argv: bool = False


def passthrough_op(module: str, help: str, entry: str = "main") -> OpSpec:
    """Forward argv to ``traust.cli.<module>.<entry>(argv)``; prepend ``--config-home`` when set."""

    def add_args(ap) -> None:
        ap.add_argument("argv", nargs=argparse.REMAINDER, default=[])

    def call(_engine, args) -> int:
        mod = importlib.import_module(f"traust.cli.{module}")
        argv: list[str] = []
        if getattr(args, "config_home", None):
            argv.extend(["--config-home", str(args.config_home)])
        argv.extend(args.argv or [])
        return getattr(mod, entry)(argv)

    return OpSpec(add_args=add_args, call=call, help=help, passthrough_argv=True)
