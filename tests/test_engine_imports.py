"""traust reaches traust-engine only through `src/traust/_tools.py` (until traust-tools exists).

Every other `traust_engine` import under src/ and harnessing/ is counted per file against
BASELINE, which only shrinks: a new file, a higher count or a stale entry fails.
"""

from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS_MODULE = "src/traust/_tools.py"
BASELINE = {
    "harnessing/3-audit/pqc-readiness/scripts/pqc_facts.py": 1,
    "harnessing/financial-tracking/scripts/build_financial_report.py": 7,
    "src/traust/cli/build_rescan_worklist.py": 1,
    "src/traust/cli/check_drift.py": 1,
    "src/traust/cli/fetch_feeds.py": 1,
    "src/traust/cli/groups/_registry.py": 1,
    "src/traust/cli/groups/adapters.py": 15,
    "src/traust/cli/groups/metrics.py": 2,
    "src/traust/cli/groups/portfolio.py": 2,
    "src/traust/cli/groups/registry.py": 1,
    "src/traust/cli/groups/reporting.py": 4,
    "src/traust/cli/groups/sweep.py": 4,
    "src/traust/cli/groups/util.py": 2,
    "src/traust/cli/toolchain.py": 1,
    "src/traust/context.py": 1,  # NEED(engine Policy): the lazy engine factory
    "src/traust/lib/__init__.py": 1,
}


def _engine_imports(source: str) -> int:
    count = 0
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module]
        else:
            continue
        count += sum(n == "traust_engine" or n.startswith("traust_engine.") for n in names)
    return count


def _hits() -> Counter[str]:
    return Counter(
        {
            rel: n
            for root in ("src", "harnessing")
            for path in (ROOT / root).rglob("*.py")
            if (rel := path.relative_to(ROOT).as_posix()) != TOOLS_MODULE
            and (n := _engine_imports(path.read_text(encoding="utf-8")))
        }
    )


def test_engine_imports_never_grow_past_the_baseline() -> None:
    grown = {f: n for f, n in _hits().items() if n > BASELINE.get(f, 0)}
    assert not grown, f"import traust_engine through {TOOLS_MODULE} instead: {grown}"


def test_the_baseline_only_shrinks() -> None:
    hits = _hits()
    stale = {f: (n, hits[f]) for f, n in BASELINE.items() if hits[f] < n}
    assert not stale, f"lower BASELINE to what remains (baseline, now): {stale}"


def test_counted_imports_include_adapters_and_nested_ones() -> None:
    source = (
        "import traust_engine\n"
        "from traust_engine.adapters import grype\n"
        "def f():\n"
        "    from traust_engine import HarnessEngine\n"
        "from traust_enginex import y\n"
        "from . import traust_engine\n"
    )
    assert _engine_imports(source) == 3
