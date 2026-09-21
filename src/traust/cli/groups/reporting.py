"""``traust reporting …`` — report validation."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from traust_engine.reporting import validate

from traust.cli.groups._registry import OpSpec
from traust.lib import threat_model_artifact


def add_validate_args(ap) -> None:
    ap.add_argument("path", help="Path to a .json file or directory containing .json files")
    ap.add_argument(
        "--strict",
        action="store_true",
        help="Enable strict mode (additional warnings)",
    )
    ap.add_argument(
        "--schema",
        default=None,
        help="Schema file to validate against (default: filename-based auto-detection)",
    )
    ap.add_argument(
        "--signing-pubkey",
        default=None,
        help="cosign public key path for optional merkle_root_signature verification",
    )


def call_validate(engine, args) -> int:
    signing_pubkey = args.signing_pubkey
    if signing_pubkey is None:
        key = engine.reporting.signing_pubkey()
        signing_pubkey = str(key) if key is not None else None

    files = validate.collect_report_files(args.path)
    if not files:
        target = Path(args.path)
        if target.is_dir():
            print(f"No .json files found in {target}")
        else:
            print(f"Path not found: {target}")
        return 1

    explicit_schema = None
    if args.schema is not None:
        schema_path = Path(args.schema)
        if not schema_path.is_absolute() and not schema_path.exists():
            schema_path = validate.SCHEMA_DIR / schema_path.name
        explicit_schema = schema_path

    print(f"\nValidating {len(files)} report(s)...\n")

    results = engine.reporting.validate(
        args.path,
        strict=args.strict,
        schema=explicit_schema,
        signing_pubkey=signing_pubkey,
    )
    total_errors = 0
    total_warnings = 0
    for r in results:
        r.print_report()
        total_errors += len(r.errors)
        total_warnings += len(r.warnings)
        print()

    print("=" * 60)
    print(f"Total: {len(files)} file(s), {total_errors} error(s), {total_warnings} warning(s)")
    failed = sum(1 for r in results if not r.passed)
    if failed:
        print(f"Result: {failed} FAILED")
    else:
        print("Result: ALL PASSED")
    return 0 if not failed else 1


VALIDATE = OpSpec(
    add_args=add_validate_args,
    call=call_validate,
    help="Validate security report JSON files against contracts schemas",
)


def add_lint_args(ap) -> None:
    ap.add_argument(
        "paths",
        nargs="+",
        help="THREAT_MODEL.md files or directories (searched recursively)",
    )
    ap.add_argument(
        "--strict",
        action="store_true",
        help="Promote optional gaps to warnings in the summary",
    )


def call_lint(engine, args) -> int:
    from traust_engine.reporting import lint

    files = lint.collect(args.paths)
    if not files:
        print("no THREAT_MODEL.md files found", file=sys.stderr)
        return 1
    total_errors = 0
    total_warnings = 0
    failed = 0
    for f in files:
        errors, warnings = engine.reporting.lint(f, strict=args.strict)
        if errors or warnings:
            print(f"\n{f}:")
            for e in errors:
                print(f"  ERROR: {e}")
            for w in warnings:
                print(f"  WARN:  {w}")
        total_errors += len(errors)
        total_warnings += len(warnings)
        if errors:
            failed += 1
    print(f"\n{len(files)} file(s), {total_errors} error(s), {total_warnings} warning(s)")
    if failed:
        print(f"Result: {failed} FAILED")
        return 1
    print("Result: ALL PASSED")
    return 0


LINT = OpSpec(
    add_args=add_lint_args,
    call=call_lint,
    help="Lint THREAT_MODEL.md artifacts against schema contract",
)


def add_render_args(ap) -> None:
    ap.add_argument("report", type=Path, help="Path to a security report JSON file")
    ap.add_argument(
        "-o",
        "--out",
        type=Path,
        help="Write markdown to file (default: stdout)",
    )


def call_render(engine, args) -> int:
    md = engine.reporting.render(args.report)
    if args.out:
        args.out.write_text(md, encoding="utf-8")
        print(f"render: wrote {args.out}")
    else:
        print(md, end="")
    return 0


RENDER = OpSpec(
    add_args=add_render_args,
    call=call_render,
    help="Render a validated security report JSON to Markdown",
)


def add_sarif_args(ap) -> None:
    ap.add_argument(
        "reports",
        nargs="*",
        type=Path,
        help="report(s): *-security-audit.json, *-container-audit.json, "
        "*-cloud-config-audit.json, or *-findings-current.json",
    )
    ap.add_argument(
        "-o",
        "--out",
        type=Path,
        help="output path (single input only; default: <input stem>.sarif alongside input)",
    )
    ap.add_argument(
        "--results-root",
        type=Path,
        help="batch sweep: walk this tree for exportable reports; requires --out-dir",
    )
    ap.add_argument(
        "--out-dir",
        type=Path,
        help="sweep output tree — .sarif files mirror reports' relative paths",
    )
    ap.add_argument("--compact", action="store_true", help="minified JSON")


def call_sarif(_engine, args) -> int:
    from traust_engine.reporting import sarif

    if bool(args.results_root) == bool(args.reports):
        print("ERROR: pass report paths OR --results-root, not both/neither", file=sys.stderr)
        return 2
    if args.results_root and not args.out_dir:
        print("ERROR: --results-root requires --out-dir", file=sys.stderr)
        return 2
    if args.out and (len(args.reports) > 1 or args.results_root):
        print("ERROR: -o/--out requires exactly one input report", file=sys.stderr)
        return 2

    sweep_root = None
    report_paths = list(args.reports)
    if args.results_root:
        sweep_root = args.results_root.resolve()
        report_paths = sarif._sweep(sweep_root)
        if not report_paths:
            print(f"no exportable reports under {sweep_root}")
            return 0

    rc = 0
    for report_path in report_paths:
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"ERROR: cannot read {report_path}: {e}", file=sys.stderr)
            rc = 1
            continue
        if not isinstance(report, dict) or "findings" not in report:
            print(f"ERROR: {report_path}: not a harness report (no findings key)", file=sys.stderr)
            rc = 1
            continue
        sarif_doc = sarif.export(report)
        sarif_name = (
            report_path.name[: -len(".json")] + ".sarif"
            if report_path.name.endswith(".json")
            else report_path.name + ".sarif"
        )
        if sweep_root is not None:
            rel = report_path.resolve().parent.relative_to(sweep_root)
            out = args.out_dir / rel / sarif_name
            out.parent.mkdir(parents=True, exist_ok=True)
        else:
            out = args.out or report_path.with_name(sarif_name)
        indent = None if args.compact else 2
        out.write_text(
            json.dumps(sarif_doc, indent=indent, sort_keys=False) + "\n",
            encoding="utf-8",
        )
        n = len(sarif_doc["runs"][0]["results"])
        print(f"wrote {out} ({n} result{'s' if n != 1 else ''})")
    return rc


SARIF = OpSpec(
    add_args=add_sarif_args,
    call=call_sarif,
    help="Export harness reports to SARIF 2.1.0",
)


def add_threat_model_json_args(ap) -> None:
    ap.add_argument(
        "model",
        type=Path,
        nargs="+",
        help="Path to one or more <repo>-threat-model.md files",
    )
    ap.add_argument(
        "--root",
        type=Path,
        default=None,
        help=(
            "Tree the model's product/slug identity is relative to "
            "(default: the model's grandparent, i.e. <product>/<repo>/)"
        ),
    )
    ap.add_argument(
        "--check",
        action="store_true",
        help="Report conformance without writing the artifact",
    )


def call_threat_model_json(engine, args) -> int:
    """Emit the contract artifact beside an authored threat model.

    /threat-model calls this in the same step that writes the Markdown,
    the way an audit emits .json and .md together. The backfill in
    traust.migrations.emit_threat_model_json runs the SAME derivation
    over a whole tree -- one implementation, so the two cannot drift.
    """
    failed = 0
    for model in args.model:
        if not model.is_file():
            print(f"no such model: {model}", file=sys.stderr)
            failed += 1
            continue
        root = args.root or model.parent.parent.parent
        try:
            target, reasons = threat_model_artifact.emit(
                model, root, write=not args.check
            )
        except ValueError as error:  # model outside --root
            print(f"{model}: {error}", file=sys.stderr)
            failed += 1
            continue
        if reasons:
            failed += 1
            print(f"NOT CONFORMANT  {model}", file=sys.stderr)
            for reason in reasons[:10]:
                print(f"    {reason}", file=sys.stderr)
            print(
                "  fix the Markdown — the schema is the authority, and an "
                "artifact written in a degraded form is one the ingest "
                "refuses anyway.",
                file=sys.stderr,
            )
            continue
        print(f"{'would write' if args.check else 'wrote'} {target}")
    return 1 if failed else 0


THREAT_MODEL_JSON = OpSpec(
    add_args=add_threat_model_json_args,
    call=call_threat_model_json,
    help="Emit the contract JSON artifact beside an authored threat model",
)
