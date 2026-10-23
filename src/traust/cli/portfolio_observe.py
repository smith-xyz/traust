"""``traust portfolio observe --repo URL``: the `repo_state` asset's materializer, by hand or from
a runner. Prints the JobResult; the exit code is its outcome."""

from __future__ import annotations

from traust_core.v1.models.operations import AssetRequest, Outcome

from traust.cli._doors import parser
from traust.context import load_core
from traust.ops.materializers import RepoStateMaterializer

EXIT_CODES = {Outcome.SUCCEEDED: 0, Outcome.FAILED: 1, Outcome.DEGRADED: 4, Outcome.REFUSED: 5}


def main(argv: list[str] | None = None) -> int:
    ap = parser("portfolio", "observe", "Observe a repository at its forge; keep what it answered.")
    ap.add_argument("--repo", required=True, help="https URL of an inventory repository")
    ap.add_argument("--run-id", default="manual", help="the run order this observation is for")
    args = ap.parse_args(argv)
    core = load_core(args.config_home)
    materializer = RepoStateMaterializer(core.services(), core.config.forge_hosts)
    result = materializer.materialize(
        AssetRequest(asset=materializer.asset, run_id=args.run_id, partition=args.repo)
    )
    print(result.model_dump_json())
    return EXIT_CODES[result.outcome]
