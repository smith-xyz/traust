"""``traust sweep …`` — class-generalization sweep, benchmark, rule-mining lane."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import yaml
from traust_core.v1.errors import (
    DeploymentConfigMissing,
    NotFoundError,
    ServiceError,
    ValidationError,
)
from traust_core.v1.models.detection_quality import RegressionPair, RegressionPairFilter

from traust.cli._doors import run
from traust.cli.groups._registry import OpSpec, load_engine, passthrough_op
from traust.context import load, rule_drafts_dir


def _add_common_sweep_args(ap) -> None:
    ap.add_argument(
        "--sweeps-root",
        type=Path,
        default=None,
        help="default <analysis-results>/scan-testing/sweeps",
    )
    ap.add_argument("--analysis-results", default=None)
    ap.add_argument(
        "--pack",
        type=Path,
        default=None,
        help="rule pack dir (default: locations.opengrep_rules, env, bundled)",
    )
    ap.add_argument(
        "--drafts-dir",
        type=Path,
        default=None,
        help=(
            "rule drafts dir (default: locations.rule_drafts or"
            " <progress_tracker>/metrics/rule-mining/rule-drafts)"
        ),
    )


def _analysis_results(engine, arg: str | None) -> Path:
    if arg:
        return Path(arg)
    return engine.sweep._analysis_results()


def _sweeps_root(engine, args) -> Path:
    # PENDING(decision: sweep stages — retire or port)
    from traust_engine.locations import SWEEPS_REL

    if args.sweeps_root is not None:
        return args.sweeps_root
    return _analysis_results(engine, args.analysis_results) / SWEEPS_REL


def _resolve_pack(args, pack: Path | None) -> Path:
    """``pack``, else the one rule pack every default run loads (``load().rule_pack``)."""
    if pack is not None:
        return pack
    path = load(args.config_home).rule_pack
    if not path.is_dir():
        print(
            "opengrep rule pack required (rule_pack, locations.opengrep_rules, or bundled default)",
            file=sys.stderr,
        )
        raise SystemExit(2)
    return path


def _resolve_drafts_dir(args) -> Path:
    if args.drafts_dir is not None:
        return args.drafts_dir
    try:
        return rule_drafts_dir(load(args.config_home))
    except DeploymentConfigMissing as e:
        print(str(e), file=sys.stderr)
        raise SystemExit(2) from e


def add_collect_args(ap) -> None:
    _add_common_sweep_args(ap)
    ap.add_argument(
        "--results-root",
        type=Path,
        default=None,
        help="findings tree (default <analysis-results>/findings)",
    )
    ap.add_argument(
        "--phase0-root",
        type=Path,
        default=None,
        help="Phase-0 artifacts (default <analysis-results>/scan-testing/phase-0)",
    )
    ap.add_argument("--force", action="store_true")


def call_collect(args) -> int:
    engine = load_engine(args.config_home)  # PENDING(decision: sweep stages — retire or port)
    ops = engine.sweep
    sweeps_root = _sweeps_root(engine, args)
    res = ops.collect(
        results_root=args.results_root,
        phase0_root=args.phase0_root,
        sweeps_root=sweeps_root,
        force=args.force,
    )
    if res["skipped"]:
        print(f"collect: state exists, skipping ({res['state']}) — use --force to re-collect")
    else:
        print(
            f"collect: {res['confirmed_findings']} confirmed "
            f"finding(s) ({res['by_source']}); "
            f"{res['rule_expressible']} rule-expressible across "
            f"{res['classes']} class(es); "
            f"{res['not_expressible']} not expressible (reasons "
            f"recorded) -> {res['state']}"
        )
    return 0


def add_draft_args(ap) -> None:
    _add_common_sweep_args(ap)


def call_draft(args) -> int:
    engine = load_engine(args.config_home)  # PENDING(decision: sweep stages — retire or port)
    ops = engine.sweep
    pack = _resolve_pack(args, args.pack)
    drafts_dir = _resolve_drafts_dir(args)
    sweeps_root = _sweeps_root(engine, args)
    res = ops.draft(pack, drafts_dir, sweeps_root=sweeps_root)
    print(
        f"draft: {len(res['emitted'])} draft(s) staged "
        f"({', '.join(res['emitted']) or 'none'}); "
        f"{len(res['skipped'])} class(es) skipped — author "
        "patterns, calibrate via mine-ledger, then `sweep` runs "
        "by default"
    )
    return 0


def add_sweep_args(ap) -> None:
    # PENDING(decision: sweep stages — retire or port)
    from traust_engine.sweep.engine import DEFAULT_SWEEP_LIMIT

    _add_common_sweep_args(ap)
    ap.add_argument("--rule", required=True, help="rule id, yaml path, or draft dir/name")
    ap.add_argument("--limit", type=int, default=DEFAULT_SWEEP_LIMIT)
    ap.add_argument(
        "--repos",
        type=Path,
        default=None,
        help="JSON [{slug,url}] override for the corpus resolver (url may be a local dir)",
    )
    ap.add_argument(
        "--work-dir",
        type=Path,
        default=None,
        help="clone root (default: fresh temp dir, removed after the run)",
    )
    ap.add_argument("--opengrep", default="opengrep")
    ap.add_argument("--timeout", type=int, default=600, help="per-repo scan timeout seconds")


def call_sweep(args) -> int:
    engine = load_engine(args.config_home)  # PENDING(decision: sweep stages — retire or port)
    ops = engine.sweep
    pack = _resolve_pack(args, args.pack)
    drafts_dir = _resolve_drafts_dir(args)
    sweeps_root = _sweeps_root(engine, args)
    res = ops.sweep(
        args.rule,
        pack,
        drafts_dir,
        sweeps_root=sweeps_root,
        repos=args.repos,
        limit=args.limit,
        work_dir=args.work_dir,
        opengrep=args.opengrep,
        timeout=args.timeout,
    )
    print(
        f"sweep [{res['rule_id']}]: {res['swept']} repo(s) swept, "
        f"{res['skipped']} resumed/skipped, "
        f"{res['repo_errors']} errored, {res['hits']} raw hit(s) "
        f"-> {res['repo_results']}"
    )
    return 0


def add_emit_args(ap) -> None:
    _add_common_sweep_args(ap)
    ap.add_argument("--rule", required=True)
    ap.add_argument("--force", action="store_true")


def call_emit(args) -> int:
    engine = load_engine(args.config_home)  # PENDING(decision: sweep stages — retire or port)
    ops = engine.sweep
    pack = _resolve_pack(args, args.pack)
    drafts_dir = _resolve_drafts_dir(args)
    sweeps_root = _sweeps_root(engine, args)
    res = ops.emit(args.rule, pack, drafts_dir, sweeps_root=sweeps_root, force=args.force)
    if res["skipped"]:
        print(f"emit: candidates exist, skipping ({res['out']}) — use --force to re-emit")
    else:
        print(
            f"emit: {res['candidates']} candidate(s) from "
            f"{res['repos_swept']} repo(s) "
            f"({res['repos_with_hits']} with hits) -> {res['out']} "
            "(+ sweep-summary.md). Results enter the triage workflow."
        )
    return 0


def add_benchmark_args(ap) -> None:
    ap.add_argument(
        "--benchmark-dir",
        type=Path,
        default=None,
        help="validate-findings benchmark dir "
        "(default: locations.analysis_results/.../validation-benchmark)",
    )
    sub = ap.add_subparsers(dest="benchmark_cmd", required=True)
    sub.add_parser("plan", help="emit benchmark worklist and deploy commands")
    p = sub.add_parser("check-trigger", help="exit 10 if validation-lane paths changed since ref")
    p.add_argument("--since", required=True, help="git ref of the last benchmarked release")
    p.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="git repo to diff (default: BENCHMARK_REPO_ROOT or locations.workspace/traust)",
    )
    p = sub.add_parser("score", help="score one lane run against expectations")
    p.add_argument("--report", required=True)
    p.add_argument("--variant", required=True, choices=["vuln", "safe"])
    sub.add_parser("scorecard", help="print the current scorecard state")


def _benchmark_results_dir(args) -> Path:
    if args.benchmark_dir:
        return args.benchmark_dir
    # PENDING(decision: sweep stages — retire or port)
    return load_engine(args.config_home).sweep._benchmark_dir()


def call_benchmark(args) -> int:
    # PENDING(decision: sweep stages — retire or port)
    from traust_engine.sweep import benchmark as bench

    if args.benchmark_cmd == "check-trigger":
        return bench.cmd_check_trigger(args)
    results_dir = _benchmark_results_dir(args)
    return {
        "plan": bench.cmd_plan,
        "score": bench.cmd_score,
        "scorecard": bench.cmd_scorecard,
    }[args.benchmark_cmd](args, results_dir=results_dir)


def add_rule_lane_args(ap) -> None:
    ap.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help="campaign workspace holding analysis-results/ and metrics output",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="rule-mining output dir (default: <progress-tracker>/metrics/rule-mining)",
    )
    ap.add_argument(
        "--draft-limit",
        type=int,
        default=6,
        help="max regression drafts staged per run (0 skips the stage; default 6)",
    )
    ap.add_argument(
        "--skip-sweep", action="store_true", help="skip the sweep-engine collect/draft stages"
    )
    ap.add_argument(
        "--emit-drafts-script",
        type=Path,
        default=None,
        help="optional emit_rule_drafts.py path (env: EMIT_RULE_DRAFTS_SCRIPT)",
    )


def call_rule_lane(args) -> int:
    # PENDING(decision: sweep stages — retire or port)
    from traust_engine.sweep import rule_lane as lane

    engine = load_engine(args.config_home)  # PENDING(decision: sweep stages — retire or port)

    return lane.execute_rule_lane(
        workspace=args.workspace,
        out=args.out,
        draft_limit=args.draft_limit,
        skip_sweep=args.skip_sweep,
        emit_drafts_script=args.emit_drafts_script,
        engine=engine,
    )


COLLECT = OpSpec(
    add_args=add_collect_args,
    call=call_collect,
    help="gather and classify confirmed findings for class-generalization",
)
DRAFT = OpSpec(
    add_args=add_draft_args,
    call=call_draft,
    help="stage candidate rules for uncovered expressible classes",
)
SWEEP = OpSpec(
    add_args=add_sweep_args,
    call=call_sweep,
    help="run one rule corpus-wide (bounded, resumable per repo)",
)
EMIT = OpSpec(
    add_args=add_emit_args,
    call=call_emit,
    help="aggregate sweep hits into triage-ready candidates",
)
BENCHMARK = OpSpec(
    add_args=add_benchmark_args,
    call=call_benchmark,
    help="validation-lane benchmark (plan, check-trigger, score, scorecard)",
)
RULE_LANE = OpSpec(
    add_args=add_rule_lane_args,
    call=call_rule_lane,
    help="rule-mining lane: mine → sweep collect/draft → delta",
)


def add_mine_args(ap) -> None:
    ap.add_argument(
        "--pack",
        default="traust",
        help="rule pack name (default: traust, from locations.opengrep_rules or bundled; an "
        "enabled rule-pack-allowlist supplement by its name)",
    )
    ap.add_argument("--out", type=Path, default=None, help="also write the result here (JSON)")


def call_mine(args) -> int:
    """The confirmed TPs in traust-core against a rule pack from core's RulePackSource."""

    def call() -> dict:
        quality = load(args.config_home).services().detection_quality
        packs = {p.name: p for p in quality.rule_packs()}
        if args.pack not in packs:
            raise NotFoundError(f"no rule pack {args.pack!r}; have {sorted(packs)}")
        mining = quality.mine_rules(packs[args.pack])
        if args.out is not None:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(mining.model_dump_json(indent=2) + "\n", encoding="utf-8")
        return {
            "pack": f"{mining.pack.name} {mining.pack.version}",
            "pack_rules": len(mining.pack.rules),
            "confirmed_tps": len(mining.corpus),
            "ruleable_tps": mining.ruleable,
            **mining.model_dump(mode="json", exclude={"pack", "corpus"}),
        }

    return run(call)


MINE = OpSpec(
    add_args=add_mine_args,
    call=call_mine,
    help="Mine ledger-confirmed TPs for opengrep rule authoring",
)

BENCHMARK_TARGETS = passthrough_op(
    "recall", "Record the recall benchmark's answer key (benchmark-targets).", "targets"
)
BUILD_CANARIES = passthrough_op(
    "recall", "Materialise canaries (or --seeded fixtures) as answer-key targets.", "canaries"
)
CARDS = passthrough_op(
    "precedent_cards", "Validate semantic precedent cards; sweep them over a checkout.", "main"
)
SCORE_BENCHMARK = passthrough_op(
    "recall", "Score recall-benchmark runs (a runs dir, or the recorded audits).", "score"
)
SCREEN_INJECTION = passthrough_op(
    "recall", "Screen recorded audit reports for prompt injection (report-only).", "screen"
)


def add_regression_drafts_args(ap) -> None:
    ap.add_argument(
        "--drafts-dir",
        type=Path,
        default=None,
        help="rule drafts dir (default: locations.rule_drafts or"
        " <progress_tracker>/metrics/rule-mining/rule-drafts)",
    )
    ap.add_argument("--cwe", default=None, help="only fixes of this CWE (e.g. CWE-78)")
    ap.add_argument("--limit", type=int, default=6, help="max drafts staged (default 6)")
    ap.add_argument(
        "--skip-existing",
        action="store_true",
        help="never re-stage a draft dir that already exists (protects authored-but-unpromoted "
        "patterns; the rule-mining lane's mode)",
    )


def call_regression_drafts(args) -> int:
    """Stage one draft dir per confirmed fix from `DetectionQualityService.regression_pairs`."""
    drafts_dir = _resolve_drafts_dir(args)

    def call() -> dict:
        quality = load(args.config_home).services().detection_quality
        staged = {d.name for d in drafts_dir.glob("*/")} if args.skip_existing else set()
        found = quality.regression_pairs(
            RegressionPairFilter(cwe=args.cwe, limit=args.limit, staged=frozenset(staged))
        )
        for pair in found.pairs:
            _stage(drafts_dir / pair.id, pair)
        return {
            "drafts_dir": str(drafts_dir),
            "drafted": [
                {"draft": p.id, "language": p.language, "cwe": p.cwes[0], "files": len(p.files)}
                for p in found.pairs
            ],
            "skipped_by_reason": found.skipped_by_reason,
            "skipped": found.model_dump(mode="json")["skipped"],
        }

    return run(call)


def _stage(draft: Path, pair: RegressionPair) -> None:
    if draft.exists():
        shutil.rmtree(draft)
    for side in ("before", "after"):
        (draft / side).mkdir(parents=True)
    for f in pair.files:
        for side, text in (("before", f.before), ("after", f.after)):
            if text is not None:
                target = draft / side / f.path  # a RepoPath: relative, no `..`
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding="utf-8")
    rule = {
        "id": pair.rule_id,
        "languages": [pair.language],
        "severity": pair.rule_severity,
        "message": f"TODO: one sentence on the vulnerable shape and the fix. {pair.cwes[0]}.",
        "metadata": {
            "cwe": list(pair.cwes),
            "category": "regression",
            "confidence": "HIGH",
            "regression_of": {
                "fingerprint": pair.fingerprint,
                "source_finding": str(pair.finding_id),
                "repo": pair.repository_url,
                "fix_commit": pair.fix_sha,
            },
        },
        "patterns": [{"pattern": "TODO: author from before/ (must fire) vs after/ (must not)"}],
    }
    (draft / "rule.skeleton.yaml").write_text(
        yaml.safe_dump({"rules": [rule]}, sort_keys=False, width=100), encoding="utf-8"
    )
    excerpt = " ".join((pair.rationale or "").split())[:500]
    (draft / "DRAFT.md").write_text(
        f"""# Rule draft: {pair.rule_id}

**Regression guard for:** {pair.title or "(untitled finding)"}
**CWE:** {", ".join(pair.cwes)} · **severity:** {pair.severity}
**Repo:** {pair.repository_url}
**Pre-fix commit:** `{pair.pre_fix_sha}` · **fix commit:** `{pair.fix_sha}`
**Fingerprint:** `{pair.fingerprint}` · **finding:** `{pair.finding_id}`

**Fix rationale (verification evidence):**

> {excerpt}

**Authoring contract:** write `patterns:` in `rule.skeleton.yaml` so that
`traust sweep verify-draft {draft}` fires on every file in `before/` and on
nothing in `after/`. Then move the rule into the pack category file in
the security pack (`packs/security/opengrep-rules/`; not a `regression.yaml`
dump, match the pack's category layout) with `ruleid:`-annotated fixture
lines, and delete this draft dir.
""",
        encoding="utf-8",
    )


def add_verify_draft_args(ap) -> None:
    ap.add_argument("draft", type=Path, help="draft dir (holds before/ and after/)")
    ap.add_argument(
        "--rule",
        type=Path,
        default=None,
        help="candidate rule (default: <draft>/rule.skeleton.yaml)",
    )


def call_verify_draft(args) -> int:
    """The calibration gate: the candidate rule fires on before/ and is silent on after/."""
    # NEED(core: an opengrep door that scans with one given rule file)
    from traust_engine.adapters import opengrep

    rule = args.rule or args.draft / "rule.skeleton.yaml"
    counts = {}
    for side in ("before", "after"):
        target = args.draft / side
        try:
            if not rule.is_file():
                raise ValidationError(f"no rule file at {rule}")
            counts[side] = len(opengrep.scan(target, rules=[str(rule)]).findings)
        except (ValueError, OSError, RuntimeError, ServiceError) as e:
            print(f"ERROR: opengrep over {target}: {e}", file=sys.stderr)
            return 2
    ok = counts["before"] > 0 and counts["after"] == 0
    print(
        f"{args.draft.name}: before={counts['before']} (need >0), "
        f"after={counts['after']} (need 0) -> {'PASS' if ok else 'FAIL'}"
    )
    return 0 if ok else 1


REGRESSION_DRAFTS = OpSpec(
    add_args=add_regression_drafts_args,
    call=call_regression_drafts,
    help="stage regression-rule drafts (pre/post-fix fixtures) from confirmed fixes",
)
VERIFY_DRAFT = OpSpec(
    add_args=add_verify_draft_args,
    call=call_verify_draft,
    help="check a draft rule fires on before/ and not on after/ (opengrep)",
)
