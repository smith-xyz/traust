"""attack-coverage's `modeled` leg: every repository, then `AssessmentService.threats`; techniques
not live in the pinned table are dropped and counted. The threats read is core's test."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import attack_refs
import build_attack_coverage as bac
import pytest
from traust_core.v1.models.common import Page

REPOS = [SimpleNamespace(id=uuid.uuid4()), SimpleNamespace(id=uuid.uuid4())]
MODEL_A, MODEL_B = uuid.uuid4(), uuid.uuid4()


def threat(model: uuid.UUID, *ids: str) -> SimpleNamespace:
    return SimpleNamespace(assessment_id=model, techniques=[SimpleNamespace(id=i) for i in ids])


def services(repos: list, threats: list, filters: list) -> SimpleNamespace:
    def list_threats(f, _page):
        filters.append(f)
        return Page(items=tuple(threats))

    return SimpleNamespace(
        portfolio=SimpleNamespace(list_repositories=lambda _f, _p: Page(items=tuple(repos))),
        assessments=SimpleNamespace(threats=list_threats),
    )


@pytest.fixture(autouse=True)
def table(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bac, "TECH", attack_refs.load_techniques(), raising=False)


def test_threats_of_every_repository_count_each_live_technique_once_per_threat() -> None:
    filters: list = []
    rows = [
        threat(MODEL_A, "T1078", "T1078", "T9999"),
        threat(MODEL_A, "T1190"),
        threat(MODEL_B),
        threat(MODEL_B, "T9999"),
    ]
    counts, models, with_refs, dropped = bac.scan_threat_models(services(REPOS, rows, filters))
    assert [f.repository_ids for f in filters] == [tuple(r.id for r in REPOS)]
    assert counts == {"T1078": 1, "T1190": 1}
    assert (models, with_refs) == (2, 2)
    assert dropped == {"T9999": 2}


def test_no_repositories_reads_no_threats() -> None:
    filters: list = []
    counts, models, with_refs, dropped = bac.scan_threat_models(services([], [], filters))
    assert filters == [] and not counts and not dropped and (models, with_refs) == (0, 0)
