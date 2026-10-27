"""``traust metrics …`` — metrics journal, spend."""

from __future__ import annotations

import datetime
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

from traust_core.v1.models.common import TimeWindow
from traust_core.v1.models.operations import (
    ModelName,
    ModelUsage,
    ProviderName,
    SkillName,
    SpendDimension,
    SpendFilter,
    SpendSource,
)

from traust.cli.groups._registry import OpSpec, load_engine
from traust.context import load_spend_core
from traust.paths import HARNESSING_DIR

# Claude Code transcripts record Anthropic API requests.
_TRANSCRIPT_PROVIDER = ProviderName("anthropic")


def _transcript_readers() -> tuple[ModuleType, ModuleType]:
    """traust-engine's ``attribute_spend`` and ``collect_spend`` (wave 2 lane (c))."""
    from traust_engine.metrics import attribute_spend, collect_spend

    return attribute_spend, collect_spend


def add_history_args(ap) -> None:
    ap.add_argument("cmd", choices=["append", "latest", "verify", "render-exec"])
    ap.add_argument("--source", help="Dashboard slug (append/latest)")
    ap.add_argument("--metrics-json", help="Path to a JSON object of metrics, or '-' for stdin")
    ap.add_argument("--note", default="")


def call_history(args) -> int:
    metrics = load_engine(args.config_home).metrics  # wave 2 lane (c)
    if args.cmd == "verify":
        ok, issues = metrics.verify()
        for i in issues:
            print(f"✗ {i}")
        print("✓ chain verified" if ok else f"✗ {len(issues)} issue(s)")
        return 0 if ok else 1

    if args.cmd == "latest":
        if not args.source:
            print("error: --source required", file=sys.stderr)
            return 2
        row = metrics.previous(args.source)
        print(json.dumps(row, indent=2) if row else "null")
        return 0

    if args.cmd == "append":
        if not args.source or not args.metrics_json:
            print("error: --source and --metrics-json required", file=sys.stderr)
            return 2
        raw = (
            sys.stdin.read()
            if args.metrics_json == "-"
            else Path(args.metrics_json).read_text(encoding="utf-8")
        )
        row = metrics.append(args.source, json.loads(raw), note=args.note)
        print(f"appended {row['source']} @ {row['snapshot_at']} (row_sha {row['row_sha'][:12]}…)")
        return 0

    if args.cmd == "render-exec":
        mdp, htmlp = metrics.render()
        print(f"wrote {mdp}\nwrote {htmlp}")
        return 0
    return 2


HISTORY = OpSpec(
    add_args=add_history_args,
    call=call_history,
    help="Append-only metrics history ledger (append, latest, verify, render-exec)",
)


def add_spend_args(ap) -> None:
    ap.add_argument("--out-dir", type=Path, default=None)
    ap.add_argument(
        "--budget",
        type=Path,
        default=None,
        help="budget-policy.yaml carrying monthly_budget",
    )


def call_spend(args) -> int:
    engine = load_engine(args.config_home)  # wave 2 lane (c)
    print(
        "note: session actuals and skill attribution are recorded in traust-core now "
        "(`metrics collect-spend --append`); this dashboard reads only the metrics ledger "
        "rows written before that. Current spend: `traust dashboard view spend`.",
        file=sys.stderr,
    )
    out = engine.metrics.build_spend_dashboard(
        out_dir=args.out_dir,
        budget_path=args.budget,
        budget_section=engine.ctx.budget_policy,
    )
    print(f"wrote {out}")
    return 0


SPEND = OpSpec(
    add_args=add_spend_args,
    call=call_spend,
    help="Rebuild the model-spend dashboard from ledger rows",
)


def add_collect_spend_args(ap) -> None:
    ap.add_argument("--workspace", type=Path, default=None)
    ap.add_argument("--date", default=None, help="YYYY-MM-DD (default: today for live view)")
    ap.add_argument(
        "--append",
        action="store_true",
        help="record completed days in traust-core as spend per day, model and skill (idempotent)",
    )


def call_collect_spend(args) -> int:
    attr, css = _transcript_readers()
    metrics = load_engine(args.config_home).metrics  # wave 2 lane (c)
    ws = args.workspace or metrics.workspace()
    dirs = metrics.session_project_dirs(ws)
    if not dirs:
        print(
            f"no Claude Code project transcripts under {css.PROJECTS} for {ws}",
            file=sys.stderr,
        )
        return 1

    today = datetime.date.today().isoformat()

    if args.append:
        usages = tuple(session_usages(dirs, attr.known_skills(HARNESSING_DIR)))
        if not usages:
            print("recorded 0 day×model×skill spend event(s)")
            return 0
        start = min(u.occurred_at for u in usages).astimezone(datetime.UTC)
        window = TimeWindow(
            start=start.replace(hour=0, minute=0, second=0, microsecond=0),
            end=datetime.datetime.now(datetime.UTC),
        )
        spend = load_spend_core(args.config_home).services().spend
        recorded = spend.collect(SpendSource(name=f"sessions:{ws}", usages=usages), window)
        print(f"recorded {recorded} day×model×skill spend event(s)")
        return 0

    day = args.date or today
    agg = metrics.collect_session_spend(dirs, day)
    rows = agg.get(day, {})
    print(
        f"session spend — {day} ({'live' if day == today else 'final'}) "
        f"across {len(dirs)} project dir(s)"
    )
    if not rows:
        print("  no usage recorded")
        return 0
    for model, a in sorted(rows.items()):
        r = css._row(model, a)
        print(
            f"  {model}: out={r['tokens_out']:,} in={r['tokens_in']:,} "
            f"cache_read={r['cache_read']:,} cache_new={r['cache_creation']:,} "
            f"({r['messages']} msgs, {r['sessions']} sessions)"
        )
    return 0


COLLECT_SPEND = OpSpec(
    add_args=add_collect_spend_args,
    call=call_collect_spend,
    help="Collect session spend from Claude Code transcripts",
)


def add_attribute_spend_args(ap) -> None:
    ap.add_argument("--workspace", type=Path, default=None)
    ap.add_argument("--date", default=None, help="one day, YYYY-MM-DD")
    ap.add_argument("--month", default=None, help="one month, YYYY-MM")
    ap.add_argument(
        "--reconcile",
        action="store_true",
        help="prove traust-core's recorded spend splits by skill losslessly; exit 1 if not",
    )
    ap.add_argument("--json", action="store_true")


def call_attribute_spend(args) -> int:
    month = args.month
    if not month and not args.date:
        month = datetime.date.today().strftime("%Y-%m")

    if args.reconcile:
        return _reconcile(args, month)

    _, css = _transcript_readers()
    metrics = load_engine(args.config_home).metrics  # wave 2 lane (c)
    ws = args.workspace or metrics.workspace()
    dirs = css.workspace_slugs(ws)
    if not dirs:
        print(f"no session transcripts under {css.PROJECTS} for {ws}", file=sys.stderr)
        return 3

    agg = metrics.collect_attributed(dirs, args.date, month)
    if args.json:
        out = {
            d: {
                s: {
                    m: {k: v for k, v in a.items() if k != "sessions"}
                    | {"sessions": len(a["sessions"])}
                    for m, a in models.items()
                }
                for s, models in skills.items()
            }
            for d, skills in agg.items()
        }
        print(json.dumps(out, indent=1, sort_keys=True))
        return 0
    print("\n".join(metrics.render_attribution(agg, args.date or month or "all")))
    return 0


def session_usages(dirs: list[Path], skills: set[str]) -> Iterator[ModelUsage]:
    """Each transcript request's usage with the skill running then (traust-engine's skill
    signals, walked in session order); usage before any signal has no skill."""
    attr, _ = _transcript_readers()
    for d in dirs:
        for f in sorted(d.glob("*.jsonl")):
            skill = None
            with f.open(encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if not any(tok in line for tok in attr._INTERESTING):
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue  # a torn line in a live transcript
                    skill = attr.detect_skill(rec, skills) or skill
                    msg = rec.get("message") or {}
                    usage, model = msg.get("usage"), msg.get("model")
                    if not usage or not model or model.startswith("<") or not rec.get("timestamp"):
                        continue
                    yield ModelUsage(
                        provider=_TRANSCRIPT_PROVIDER,
                        model=ModelName(model),
                        occurred_at=datetime.datetime.fromisoformat(rec["timestamp"]),
                        tokens_in=usage.get("input_tokens") or 0,
                        tokens_out=usage.get("output_tokens") or 0,
                        cache_read=usage.get("cache_read_input_tokens") or 0,
                        cache_creation=usage.get("cache_creation_input_tokens") or 0,
                        skill=None if skill is None else SkillName(skill),
                    )


def _reconcile(args, month: str | None) -> int:
    start = datetime.datetime.fromisoformat(args.date or f"{month}-01").replace(tzinfo=datetime.UTC)
    window = (
        TimeWindow(start=start, end=start + datetime.timedelta(days=1))
        if args.date
        else TimeWindow.month_of(start)
    )
    split = (
        load_spend_core(args.config_home)
        .services()
        .spend.attribute_by(SpendFilter(window=window), SpendDimension.SKILL)
    )
    if args.json:
        print(json.dumps(split.model_dump(mode="json") | {"lossless": split.lossless}, indent=1))
    else:
        t = split.total
        print(
            f"recorded spend by skill, {window.start.date()} to {window.end.date()}:"
            f"\n  total: {t.events} events, {t.tokens_out:,} output tokens, ${t.cost_usd:,.2f}"
            f"\n  unattributed: ${split.unattributed.cost_usd:,.2f}\n  lossless: {split.lossless}"
        )
    return 0 if split.lossless else 1


ATTRIBUTE_SPEND = OpSpec(
    add_args=add_attribute_spend_args,
    call=call_attribute_spend,
    help="Attribute session spend to harness lanes from transcripts",
)
