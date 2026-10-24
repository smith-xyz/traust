"""operator-priv-profile: the profile build_priv_profile.py writes is the contract's
operator-priv-profile document, so `traust reporting record --kind priv_profile` files it."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import yaml
from traust_core.v1.context import Context
from traust_core.v1.models.assessment import AssessmentKind
from traust_core.v1.models.values import GitSha, HttpsRepoUrl

from tests.test_assessment_record import SHA, URL, run
from traust.paths import skill_dir

_SPEC = importlib.util.spec_from_file_location(
    "build_priv_profile", skill_dir("operator-priv-profile") / "scripts" / "build_priv_profile.py"
)
assert _SPEC is not None and _SPEC.loader is not None
bpp = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(bpp)

ROLE = {
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "kind": "ClusterRole",
    "metadata": {"name": "widget"},
    "rules": [
        {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]},
        {
            "apiGroups": ["security.openshift.io"],
            "resources": ["securitycontextconstraints"],
            "resourceNames": ["privileged"],
            "verbs": ["use"],
        },
    ],
}
DEPLOYMENT = {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {"name": "widget", "namespace": "widget-system"},
    "spec": {
        "template": {
            "spec": {
                "containers": [
                    {"name": "manager", "image": "x", "securityContext": {"privileged": True}}
                ]
            }
        }
    },
}


def test_a_built_profile_records_as_a_priv_profile(tmp_path: Path) -> None:
    tree = tmp_path / "widget"
    (tree / "config").mkdir(parents=True)
    (tree / "config" / "role.yaml").write_text(yaml.safe_dump(ROLE))
    (tree / "config" / "manager.yaml").write_text(yaml.safe_dump(DEPLOYMENT))
    profile = tmp_path / "widget-priv-profile.json"
    profile.write_text(json.dumps(bpp.profile_repo(tree, "widget"), indent=1))
    home = tmp_path / "config"
    home.mkdir()
    (home / "core.yaml").write_text(yaml.safe_dump({"home": str(tmp_path / "store")}))

    rc, out = run(home, str(profile), "--kind", "priv_profile", "--repo-url", URL, "--sha", SHA)

    assert rc == 0, out
    core = Context.from_file(home / "core.yaml")
    services = core.services()
    repo = services.portfolio.find_repository(HttpsRepoUrl.parse(URL, core.config.forge_hosts))
    assert repo is not None
    ref = services.portfolio.register_ref(repo.id, GitSha.parse(SHA), None, None)
    latest = services.assessment.latest(ref.id, AssessmentKind.PRIV_PROFILE)
    assert latest is not None and str(latest.id) == out["id"]
