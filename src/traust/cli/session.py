"""``traust session run``: a skill session for a pack order, started headless. The model is the
role's (`traust registry models resolve`); the session's last line is the JobResult, whose
outcome is the exit code.

Repo-config isolation (check-skill-security S9): the agent's working directory is this harness,
never a checkout. A checkout the session reviews is a separate temporary directory passed as an
argument; its own agent config (`.claude/`, `CLAUDE.md`, hooks) is data under audit, never loaded
as configuration.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

from traust_core.v1.errors import ServiceError, ValidationError
from traust_core.v1.models.operations import JobResult, OrderReason

from traust.cli._doors import answer, parser
from traust.paths import HARNESS_ROOT, skill_dir

# PENDING(agents): Claude Code is the agent sessions start in; Crush is the other implementation.
AGENT = ("claude", "-p", "--output-format", "text")
_GIT_ENV = {"GIT_ALLOW_PROTOCOL": "https", "GIT_TERMINAL_PROMPT": "0"}


def resolve_model(role: str) -> str:
    """The role's model, from the model registry through its one door."""
    done = subprocess.run(
        [sys.executable, "-m", "traust.cli", "registry", "models", "resolve", role],
        capture_output=True,
        text=True,
        check=False,
    )
    model = done.stdout.strip().splitlines()[-1:] if done.returncode == 0 else []
    if not model:
        raise ValidationError(f"role {role!r}: no model in the registry ({done.stderr.strip()})")
    return model[0]


def checkout(url: str, dest: Path) -> Path:
    """The repository's default-branch head, https only, outside this harness. Full history: a
    diff scan anchors at its baseline audit's commit, which a shallow clone doesn't hold."""
    if not url.startswith("https://"):
        raise ValidationError(f"{url}: only https repositories are checked out")
    try:
        subprocess.run(
            ["git", "clone", "-q", "--", url, str(dest)],
            env={**os.environ, **_GIT_ENV},
            check=True,
            capture_output=True,
            timeout=600,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        detail = (getattr(e, "stderr", b"") or b"").decode()[-200:]
        raise ServiceError(f"cannot check out {url}: {detail}") from e
    return dest


def prompt(skill: str, args: list[str]) -> str:
    return " ".join([f"/{skill}", *args])


def run(argv: list[str] | None = None) -> int:
    ap = parser(
        "session",
        "run",
        "Start a skill session headless for a pack order, e.g. "
        "`--skill vuln-scan --role vuln-scan --repo <url> --checkout -- --diff`.",
    )
    ap.add_argument("--skill", required=True, help="the skill the session runs")
    ap.add_argument("--role", required=True, help="its model-registry role")
    ap.add_argument("--repo", help="the repository the order is for")
    ap.add_argument(
        "--checkout", action="store_true", help="pass a checkout of --repo's head, not its URL"
    )
    ap.add_argument(
        "--mode", help="the skill's mode token, before the repository (e.g. threat-model review)"
    )
    ap.add_argument("--run-id", default="manual", help="the run order this session is for")
    argv = sys.argv[1:] if argv is None else argv
    split = argv.index("--") if "--" in argv else len(argv)
    args, extra = ap.parse_args(argv[:split]), argv[split + 1 :]
    if args.checkout and not args.repo:
        ap.error("--checkout needs --repo")
    try:
        skill_dir(args.skill)
        model = resolve_model(args.role)
    except (ValidationError, FileNotFoundError, KeyError) as e:
        print(f"run {args.run_id}: {OrderReason.BAD_REQUEST}: {e}", file=sys.stderr)
        return answer(JobResult.failed(OrderReason.BAD_REQUEST))
    mode = [args.mode] if args.mode else []
    with tempfile.TemporaryDirectory(prefix="traust-session-") as tmp:
        target: list[str] = []
        if args.repo:
            try:
                target = (
                    [str(checkout(args.repo, Path(tmp) / "checkout"))]
                    if args.checkout
                    else [args.repo]
                )
            except (ValidationError, ServiceError) as e:
                print(f"run {args.run_id}: {OrderReason.NOT_FOUND}: {e}", file=sys.stderr)
                return answer(JobResult.refused(OrderReason.NOT_FOUND))
        command = [*AGENT, "--model", model, prompt(args.skill, [*mode, *target, *extra])]
        try:
            done = subprocess.run(command, cwd=HARNESS_ROOT, check=False)
        except OSError as e:
            print(f"run {args.run_id}: {OrderReason.RUNNER_CRASHED}: {e}", file=sys.stderr)
            return answer(JobResult.failed(OrderReason.RUNNER_CRASHED))
    if done.returncode != 0:
        print(f"run {args.run_id}: session exited {done.returncode}", file=sys.stderr)
        return answer(JobResult.failed(OrderReason.RUNNER_CRASHED))
    return answer(JobResult.succeeded())
