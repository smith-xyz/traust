"""``traust portfolio plan|onboard|owner-hints|import-owners|import-release``: add-inputs' and
inventory-repositories' doors on traust-core (onboarding and portfolio sync).

plan           what onboard would register and order, writing nothing (the dry run)
onboard        register the product (when --label names a new one), the repositories and an
               organisation's non-archived, non-fork repositories; re-runs are no-ops
owner-hints    OWNERS / CODEOWNERS approvers, then top contributors: hints, never stored
import-owners  mirror the declared ownership source onto every registered repository
import-release a product version and the commits it ships (a payload's commit URLs)
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any

import pydantic
import yaml
from traust_core.v1.context import Context
from traust_core.v1.errors import ValidationError
from traust_core.v1.models.base import Dto, Model
from traust_core.v1.models.inventory import (
    OrgName,
    OwnerAssignment,
    OwnershipSource,
    RefName,
    ReleaseCommit,
    TeamName,
    VersionLabel,
)
from traust_core.v1.models.onboarding import OnboardingRequest, RepositorySpec
from traust_core.v1.models.values import GitSha, HttpsRepoUrl, ProductSlug

from traust.cli import _doors
from traust.cli._doors import parser, run
from traust.context import load_caller, load_core


def _json(value: Any) -> Any:
    """A model as JSON values, repository URLs as their https string."""
    if isinstance(value, HttpsRepoUrl):
        return str(value)
    if isinstance(value, pydantic.BaseModel):
        return {name: _json(getattr(value, name)) for name in type(value).model_fields}
    if isinstance(value, tuple | list):
        return [_json(v) for v in value]
    return value


def _request_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--product", required=True, help="the product slug the repositories join")
    ap.add_argument("--label", help="the display name, to register a product not registered yet")
    ap.add_argument(
        "--repo", action="append", default=[], help="an https repository URL (repeatable)"
    )
    ap.add_argument("--org", help="a GitHub organisation or GitLab group to list")
    ap.add_argument("--host", default="github.com", help="the forge host --org lists on")


def _url(core: Context, raw: str) -> HttpsRepoUrl:
    return HttpsRepoUrl.parse(raw, core.config.forge_hosts)


def _request(core: Context, args: argparse.Namespace) -> OnboardingRequest:
    if not (args.repo or args.org):
        raise ValidationError("name something to add: --repo or --org")
    return OnboardingRequest(
        product=ProductSlug.parse(args.product),
        label=args.label,
        repositories=tuple(RepositorySpec(url=_url(core, r)) for r in args.repo),
        org=None if args.org is None else OrgName(args.org),
        host=args.host,
    )


def plan(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "plan", "What onboard would register, writing nothing.")
    _request_args(ap)
    args = ap.parse_args(argv)

    def call() -> Any:
        core = load_core(args.config_home)
        return _json(core.services().onboarding.plan(_request(core, args)))

    return run(call)


def onboard(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "onboard", "Register a product's repositories in the inventory.")
    _request_args(ap)
    args = ap.parse_args(argv)

    def call() -> Any:
        core = load_core(args.config_home)
        request = _request(core, args)
        return _json(core.services().onboarding.onboard(request, load_caller(core)))

    return run(call)


def owner_hints(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "owner-hints", "Who may own a repository, from its forge.")
    ap.add_argument("--repo", required=True, help="an https repository URL")
    args = ap.parse_args(argv)

    def call() -> Any:
        core = load_core(args.config_home)
        return [_json(h) for h in core.services().sync.owner_hints(_url(core, args.repo))]

    return run(call)


class _Assignment(Model):
    repo: str
    teams: tuple[str, ...]


class _SourceFile(Dto):
    """Other keys are ignored, so the inventory descriptor's `org_teams:` serves as a source."""

    assignments: tuple[_Assignment, ...] = ()
    org_teams: dict[str, str] = pydantic.Field(default_factory=dict)


def _source(core: Context, path: Path) -> OwnershipSource:
    try:
        doc = _SourceFile.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
    except (yaml.YAMLError, pydantic.ValidationError) as e:
        raise ValidationError(f"{path}: not an ownership source: {e}") from e
    return OwnershipSource(
        assignments=tuple(
            OwnerAssignment(repo=_url(core, a.repo), teams=tuple(TeamName(t) for t in a.teams))
            for a in doc.assignments
        ),
        org_teams={OrgName(o): TeamName(t) for o, t in doc.org_teams.items()},
    )


def import_owners(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "import-owners", "Mirror the declared ownership source.")
    ap.add_argument(
        "--source",
        type=Path,
        required=True,
        help="YAML with assignments: [{repo, teams}] and/or org_teams: {org: team}",
    )
    args = ap.parse_args(argv)

    def call() -> Any:
        core = load_core(args.config_home)
        return _json(core.services().sync.import_owners(_source(core, args.source)))

    return run(call)


_COMMIT_URL = re.compile(r"(?P<repo>https://\S+?)(?:/-)?/commit/(?P<sha>[0-9a-f]{40})/?")


def _commits(core: Context, path: Path, branch: str | None) -> list[ReleaseCommit]:
    """One commit per non-blank line whose last field is a commit URL (`oc adm release info
    --commit-urls`: `<image> <commit URL>`)."""
    commits = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        found = _COMMIT_URL.fullmatch(line.split()[-1])
        if found is None:
            raise ValidationError(f"{path}:{n}: not a commit URL: {line.strip()!r}")
        commits.append(
            ReleaseCommit(
                url=_url(core, found["repo"]),
                sha=GitSha.parse(found["sha"]),
                branch=None if branch is None else RefName(branch),
            )
        )
    return commits


def import_release(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "import-release", "Record a product version and its commits.")
    ap.add_argument("--product", required=True, help="the product slug")
    ap.add_argument("--version", required=True, help="the release version, e.g. 4.21.3")
    ap.add_argument("--commits", type=Path, required=True, help="lines of `<image> <commit URL>`")
    ap.add_argument("--branch", help="the branch every commit was built from (release-4.21)")
    args = ap.parse_args(argv)

    def call() -> Any:
        core = load_core(args.config_home)
        services = core.services()
        commits = _commits(core, args.commits, args.branch)
        [product] = _doors.products(services, [args.product])
        release = services.portfolio.import_release(product.id, VersionLabel(args.version), commits)
        return release.model_dump(mode="json")

    return run(call)
