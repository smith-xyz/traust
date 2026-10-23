"""What every ``traust <group> <op>`` door on traust-core shares: its parser and how it answers."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable

from pydantic import ValidationError as ModelValidationError
from traust_core.v1.errors import TraustError

from traust.context import add_config_home_arg


def parser(group: str, op: str, about: str) -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog=f"traust {group} {op}", description=about)
    add_config_home_arg(ap)
    return ap


def run(call: Callable[[], object], *, redact: bool = False) -> int:
    """Print the result; optionally keep submitted content out of refusal messages."""
    try:
        out = call()
    except (OSError, TraustError, ModelValidationError) as e:
        detail = type(e).__name__ if redact else str(e)
        print(f"ERROR: {detail}", file=sys.stderr)
        return 2
    if out is not None:
        print(out if isinstance(out, str) else json.dumps(out, indent=2, default=str))
    return 0
