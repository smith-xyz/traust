"""Registration contract for ``traust <group> <op>`` handlers.

An op's ``call(args)`` gets the parsed arguments (``args.config_home`` included) and returns the
exit code; an op that needs traust-core builds its Context with ``traust.context.load``.
"""

from __future__ import annotations

import argparse
import importlib
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


class OpHandler(Protocol):
    help: str

    def add_args(self, ap) -> None: ...

    def call(self, args: argparse.Namespace) -> int: ...


@dataclass(frozen=True)
class OpSpec:
    add_args: Callable
    call: Callable[[argparse.Namespace], int]
    help: str = ""
    passthrough_argv: bool = False


def passthrough_op(module: str, help: str, entry: str = "main") -> OpSpec:
    """Forward argv to ``traust.cli.<module>.<entry>(argv)``; prepend ``--config-home`` when set."""

    def add_args(ap) -> None:
        ap.add_argument("argv", nargs=argparse.REMAINDER, default=[])

    def call(args) -> int:
        mod = importlib.import_module(f"traust.cli.{module}")
        argv: list[str] = []
        if getattr(args, "config_home", None):
            argv.extend(["--config-home", str(args.config_home)])
        argv.extend(args.argv or [])
        return getattr(mod, entry)(argv)

    return OpSpec(add_args=add_args, call=call, help=help, passthrough_argv=True)


# wave 2: removed by lane (f) once lanes (b)-(e) land
def load_engine(config_home: Path | None = None) -> Any:
    """The engine facade (``HarnessEngine``) for the ops still on it, or exit 2 with a one-line
    message."""
    from traust_engine import HarnessEngine

    try:
        return HarnessEngine.load(config_home=config_home)
    except FileNotFoundError as e:  # contracts' DeploymentConfigMissing
        print(f"config not resolvable: {e}", file=sys.stderr)
        raise SystemExit(2) from e
