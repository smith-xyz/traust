"""What every ``traust <group> <op>`` door on traust-core shares: its parser and how it answers."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable

from traust_core.v1.errors import TraustError
from traust_core.v1.models.operations import JobResult, Outcome

from traust.context import add_config_home_arg


def parser(group: str, op: str, about: str) -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog=f"traust {group} {op}", description=about)
    add_config_home_arg(ap)
    return ap


def run(call: Callable[[], object]) -> int:
    """Print the result (JSON unless it's text); a refused input is exit 2 with its reason."""
    try:
        out = call()
    except (OSError, TraustError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    if out is not None:
        print(out if isinstance(out, str) else json.dumps(out, indent=2, default=str))
    return 0


EXIT_CODES = {Outcome.SUCCEEDED: 0, Outcome.FAILED: 1, Outcome.DEGRADED: 4, Outcome.REFUSED: 5}


def answer(result: JobResult) -> int:
    """A materializer's door: print the JobResult; the exit code is its outcome."""
    print(result.model_dump_json())
    return EXIT_CODES[result.outcome]
