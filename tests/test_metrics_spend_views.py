"""`traust metrics collect-spend` (live view) and `attribute-spend` (table, `--json`) on traust-core's
`SpendService.usage_summary`, against traust-engine's `collect_spend.collect` and
`attribute_spend.collect_attributed` + `render` on the same transcripts.

The engine side goes when lane (f) drops traust-engine; the parity it proves stays proven.
"""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from traust_contracts.config import load_section
from traust_core.v1.context import Context
from traust_core.v1.providers.transcripts import SessionTranscripts
from traust_engine.metrics import attribute_spend, collect_spend
from traust_engine.registry.models import long_prompt_thresholds

from traust.cli.groups import metrics

REGISTRY = Path(__file__).resolve().parents[1] / "config" / "model-registry.yaml"
WORKSPACE = Path("/w/workspace")
DAY1, DAY2 = "2026-10-05", "2026-10-06"


def request(ts: str, model: str, tokens_in: int, tokens_out: int, **usage: int) -> dict[str, Any]:
    tokens = {"input_tokens": tokens_in, "output_tokens": tokens_out, **usage}
    return {"timestamp": f"{ts}Z", "message": {"model": model, "usage": tokens}}


def signal(ts: str, content: Any) -> dict[str, Any]:
    return {"timestamp": f"{ts}Z", "message": {"content": content}}


def skill_call(ts: str, name: str) -> dict[str, Any]:
    return signal(ts, [{"type": "tool_use", "name": "Skill", "input": {"skill": name}}])


SESSIONS = {
    "s1": [
        request(f"{DAY1}T08:00:00", "claude-opus-5-5", 1200, 300),
        skill_call(f"{DAY1}T08:01:00", "triage"),
        request(f"{DAY1}T08:02:00", "claude-opus-5-5", 800, 90, cache_read_input_tokens=40_000),
        # a prompt over claude-haiku-5-5's 100k long-prompt threshold
        request(f"{DAY1}T08:03:00", "claude-haiku-5-5", 95_000, 700, cache_read_input_tokens=9_000),
        request(f"{DAY1}T08:04:00", "<synthetic>", 5, 5),
        request(
            f"{DAY2}T09:00:00", "claude-sonnet-5-5", 2000, 400, cache_creation_input_tokens=3000
        ),
    ],
    "s2": [
        signal(f"{DAY1}T10:00:00", "<command-name>/secure-code-audit</command-name>"),
        request(f"{DAY1}T10:01:00", "claude-opus-5-5", 600, 1100),
        request(f"{DAY1}T10:02:00", "claude-not-in-the-registry", 100, 70),
        signal(f"{DAY1}T10:03:00", "read harnessing/5-validate/validate-findings/SKILL.md"),
        request(f"{DAY1}T10:04:00", "claude-haiku-5-5", 3000, 45),
    ],
}


@pytest.fixture
def projects(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    project = tmp_path / "projects" / "-w-workspace"
    project.mkdir(parents=True)
    for name, records in SESSIONS.items():
        lines = [json.dumps(r) for r in records]
        (project / f"{name}.jsonl").write_text("\n".join([*lines, '{"usage": torn']) + "\n")
    monkeypatch.setattr(Context, "session_transcripts", SessionTranscripts(tmp_path / "projects"))
    return project


@pytest.fixture
def config(tmp_path: Path) -> Path:
    home = tmp_path / "config"
    home.mkdir()
    (home / "model-registry.yaml").write_text(REGISTRY.read_text())
    (home / "core.yaml").write_text(f"home: {tmp_path / 'store'}\n")
    return home


def registry(config: Path) -> Any:
    return load_section("model-registry.yaml", config_home=config)


def args(config: Path, **kw: Any) -> Any:
    values = {"workspace": WORKSPACE, "date": None, "month": None, "json": False}
    return SimpleNamespace(config_home=config, append=False, reconcile=False, **{**values, **kw})


def stdout(fn: Any, *a: Any) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = fn(*a)
    return rc, out.getvalue()


@pytest.mark.parametrize("day", [DAY1, DAY2, "2026-10-07"])
def test_the_live_view_matches_the_engine_collector(projects: Path, config: Path, day: str) -> None:
    agg = collect_spend.collect([projects], day, long_prompt_thresholds(registry(config)))
    rows = [collect_spend._row(model, a) for model, a in sorted(agg.get(day, {}).items())]
    expected = [f"session spend — {day} (final) across 1 project dir(s)"] + (
        [
            f"  {r['model']}: out={r['tokens_out']:,} in={r['tokens_in']:,} "
            f"cache_read={r['cache_read']:,} cache_new={r['cache_creation']:,} "
            f"({r['messages']} msgs, {r['sessions']} sessions)"
            for r in rows
        ]
        or ["  no usage recorded"]
    )
    assert stdout(metrics.call_collect_spend, args(config, date=day)) == (
        0,
        "\n".join(expected) + "\n",
    )


@pytest.mark.parametrize(("date", "month"), [(None, "2026-10"), (DAY1, None), (None, "2026-09")])
def test_the_attribution_table_matches_the_engine_render(
    projects: Path, config: Path, date: str | None, month: str | None
) -> None:
    reg = registry(config)
    agg = attribute_spend.collect_attributed(
        [projects], date, month, None, long_prompt_thresholds(reg)
    )
    expected = attribute_spend.render(agg, date or month, reg=reg)
    rc, out = stdout(metrics.call_attribute_spend, args(config, date=date, month=month))
    assert (rc, out) == (0, "\n".join(expected) + "\n")


def test_the_attribution_json_matches_the_engine_buckets(projects: Path, config: Path) -> None:
    agg = attribute_spend.collect_attributed(
        [projects], None, "2026-10", None, long_prompt_thresholds(registry(config))
    )
    expected = {
        d: {
            s: {m: {**a, "sessions": len(a["sessions"])} for m, a in models.items()}
            for s, models in skills.items()
        }
        for d, skills in agg.items()
    }
    rc, out = stdout(metrics.call_attribute_spend, args(config, month="2026-10", json=True))
    assert rc == 0 and json.loads(out) == expected
    assert "long_prompt" in json.loads(out)[DAY1]["unattributed"]["claude-haiku-5-5"]


def test_without_transcripts_the_live_view_exits_1_and_attribution_3(
    projects: Path, config: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    elsewhere = Path("/elsewhere")
    assert metrics.call_collect_spend(args(config, workspace=elsewhere)) == 1
    assert metrics.call_attribute_spend(args(config, workspace=elsewhere)) == 3
    err = capsys.readouterr().err
    assert f"under {projects.parent} for /elsewhere" in err
