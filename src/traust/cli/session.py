"""``traust session run``: a skill session for a pack order, started headless. The model is the
role's (the model registry's `resolve_role`); the session's last line is the JobResult, whose
outcome is the exit code.

A diff scan whose order carries the router's threat-model PR stamp (`--rule`) then runs
`/threat-model pr` on the same checkout, at the anchor `traust assessments prepare --diff`
resolves; report-only.

Repo-config isolation (check-skill-security S9): the agent's working directory is this harness,
never a checkout. A checkout the session reviews is a separate temporary directory passed as an
argument; its own agent config (`.claude/`, `CLAUDE.md`, hooks) is data under audit, never loaded
as configuration.

Spend: the agent answers Claude Code's JSON result; its reply text is printed, and its measured
usage per model rides on the JobResult, which `traust-engine claim` settles as the order's spend.
The session runs with its own Claude config dir (`<config home>/claude-runner`, as
`CLAUDE_CONFIG_DIR`; log in there once, or set `ANTHROPIC_API_KEY`), so its transcripts never
land in `~/.claude/projects`, where `traust metrics collect-spend` reads workstation sessions:
nothing is counted twice.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

import pydantic
from pydantic import Field
from traust_core.v1.errors import NotFoundError, ServiceError, ValidationError
from traust_core.v1.models.assessment import DiffRefused
from traust_core.v1.models.base import Dto
from traust_core.v1.models.operations import (
    JobResult,
    ModelName,
    ModelUsage,
    OrderReason,
    ProviderName,
    SkillName,
)

from traust.cli._doors import answer, parser
from traust.cli.assessments import REFUSED
from traust.context import MODEL_REGISTRY, TRAUST_CONFIG_HOME_DEFAULT, load, resolve_config_home
from traust.ops.router import THREAT_MODEL_PR
from traust.paths import HARNESS_ROOT, skill_dir

# PENDING(agents): Claude Code is the agent sessions start in; Crush is the other implementation.
AGENT = ("claude", "-p", "--output-format", "json")
# Claude Code bills Anthropic API requests.
PROVIDER = ProviderName("anthropic")
# PENDING(roles): the pack's threat-model role, as on its threat_model_quarterly asset.
THREAT_MODEL_ROLE = "threat-model"
_GIT_ENV = {"GIT_ALLOW_PROTOCOL": "https", "GIT_TERMINAL_PROMPT": "0"}


class _Tokens(Dto):
    tokens_in: int = Field(alias="inputTokens")
    tokens_out: int = Field(alias="outputTokens")
    cache_read: int = Field(0, alias="cacheReadInputTokens")
    cache_creation: int = Field(0, alias="cacheCreationInputTokens")


class AgentResult(Dto):
    """Claude Code's `--output-format json` result: the reply, and the session's usage per model."""

    result: str = ""
    is_error: bool = False
    session_id: str
    model_usage: dict[str, _Tokens] = Field(alias="modelUsage")

    def usage(self, skill: str, at: datetime) -> tuple[ModelUsage, ...]:
        return tuple(
            ModelUsage(
                provider=PROVIDER,
                model=ModelName(model),
                occurred_at=at,
                skill=SkillName(skill),
                session=self.session_id,
                **tokens.model_dump(),
            )
            for model, tokens in sorted(self.model_usage.items())
        )


def claude_dir(config_home: Path | None) -> Path:
    """The Claude config dir runner sessions use, apart from the workstation's `~/.claude`."""
    return (resolve_config_home(config_home) or TRAUST_CONFIG_HOME_DEFAULT) / "claude-runner"


def session(
    command: list[str], skill: str, env: Mapping[str, str]
) -> tuple[subprocess.CompletedProcess[str], tuple[ModelUsage, ...]]:
    """Run one agent session in the harness: its reply text goes to stdout, its measured usage
    comes back; an error result fails the session."""
    done = subprocess.run(
        command, cwd=HARNESS_ROOT, env=dict(env), stdout=subprocess.PIPE, text=True, check=False
    )
    try:
        reply = AgentResult.model_validate_json(done.stdout or "")
    except pydantic.ValidationError as e:
        raise ServiceError(f"/{skill}: not Claude Code's JSON result: {e}") from e
    print(reply.result)
    if reply.is_error and done.returncode == 0:
        done.returncode = 1
    return done, reply.usage(skill, datetime.now(UTC))


def _traust(*argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "traust.cli", *argv], capture_output=True, text=True, check=False
    )


def resolve_model(role: str) -> str:
    """The role's model, from the model registry."""
    catalog = load().model_catalog
    if catalog is None:
        raise ValidationError(f"role {role!r}: no model registry ({MODEL_REGISTRY})")
    return catalog.resolve_role(role)


def diff_anchor(url: str, clone: Path) -> str:
    """The commit the diff scan's diff starts from, resolved by the same door the scan asks."""
    head = subprocess.run(
        ["git", "-C", str(clone), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    done = _traust(
        *("assessments", "prepare", "--kind", "vuln-scan"),
        *("--repo-url", url, "--sha", head, "--diff", str(clone)),
    )
    if done.returncode == REFUSED:
        raise DiffRefused(json.loads(done.stdout)["reason"])
    if done.returncode != 0:
        raise ServiceError(f"assessments prepare exited {done.returncode}: {done.stderr.strip()}")
    return str(json.loads(done.stdout)["diff"]["anchor"])


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
        "`--skill vuln-scan --role vuln-scan --repo <url> --checkout -- --diff`. Its measured "
        "usage rides on the JobResult and settles as the order's spend; it runs with its own "
        "Claude config dir (<config home>/claude-runner: log in there once, or set "
        "ANTHROPIC_API_KEY), so `traust metrics collect-spend` never counts it again.",
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
    ap.add_argument("--rule", help="the router rule that routed the order")
    argv = sys.argv[1:] if argv is None else argv
    split = argv.index("--") if "--" in argv else len(argv)
    args, extra = ap.parse_args(argv[:split]), argv[split + 1 :]
    if args.checkout and not args.repo:
        ap.error("--checkout needs --repo")
    stamped = bool(args.rule) and args.rule.endswith(THREAT_MODEL_PR)
    if stamped and not args.checkout:
        ap.error(f"{THREAT_MODEL_PR} needs --checkout")
    try:
        skill_dir(args.skill)
        model = resolve_model(args.role)
        pr_model = resolve_model(THREAT_MODEL_ROLE) if stamped else None
    except (ValidationError, NotFoundError, FileNotFoundError, KeyError) as e:
        print(f"run {args.run_id}: {OrderReason.BAD_REQUEST}: {e}", file=sys.stderr)
        return answer(JobResult.failed(OrderReason.BAD_REQUEST))
    mode = [args.mode] if args.mode else []
    env = {**os.environ, "CLAUDE_CONFIG_DIR": str(claude_dir(args.config_home))}
    usage: tuple[ModelUsage, ...] = ()
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
            done, usage = session(command, args.skill, env)
            if done.returncode == 0 and pr_model:
                pr = threat_model_pr(args.run_id, args.repo, Path(target[0]), pr_model, env)
                if pr is not None:
                    done, usage = pr[0], usage + pr[1]
        except (OSError, ServiceError, subprocess.CalledProcessError) as e:
            print(f"run {args.run_id}: {OrderReason.RUNNER_CRASHED}: {e}", file=sys.stderr)
            return answer(_spent(JobResult.failed(OrderReason.RUNNER_CRASHED), usage))
    if done.returncode != 0:
        print(f"run {args.run_id}: session exited {done.returncode}", file=sys.stderr)
        return answer(_spent(JobResult.failed(OrderReason.RUNNER_CRASHED), usage))
    return answer(_spent(JobResult.succeeded(), usage))


def _spent(result: JobResult, usage: tuple[ModelUsage, ...]) -> JobResult:
    return result.model_copy(update={"usage": usage})


def threat_model_pr(
    run_id: str, url: str, clone: Path, model: str, env: Mapping[str, str]
) -> tuple[subprocess.CompletedProcess[str], tuple[ModelUsage, ...]] | None:
    """The stamp's report-only `/threat-model pr` session on the scan's checkout; None when the
    diff is refused, said on stderr."""
    try:
        anchor = diff_anchor(url, clone)
    except DiffRefused as e:
        print(f"run {run_id}: {THREAT_MODEL_PR} skipped: diff refused: {e}", file=sys.stderr)
        return None
    pr = prompt("threat-model", ["pr", str(clone), "--base", anchor])
    return session([*AGENT, "--model", model, pr], "threat-model", env)
