#!/usr/bin/env python3
"""
Tests for the /cloud-config-audit skill's corpus tagging. The runner and the report gate moved to
traust-core and traust-engine (tests/test_cloud_config_doors.py drives them).
"""


def test_corpus_resolver_tags_cloud_config_kind(tmp_path):
    """The shared corpus resolver discovers *-cloud-config-audit.json
    and tags it report_kind='cloud-config' so no consumer can blend
    the units by accident."""
    from traust_engine.corpus import resolver as corpus

    ar = tmp_path / "analysis-results"
    d = ar / "cloud-config" / "t1"
    d.mkdir(parents=True)
    (d / "t1-cloud-config-audit.json").write_text("{}", encoding="utf-8")
    f = ar / "findings" / "prod" / "r1"
    f.mkdir(parents=True)
    (f / "r1-security-audit.json").write_text("{}", encoding="utf-8")
    from traust_contracts import CorpusConfig

    cfg = CorpusConfig.model_validate(
        {
            "version": 1,
            "trees": {
                "cloud-config": {"label": "cc", "ownership": "owned", "business_unit": "HP"},
                "findings": {"label": "hp", "ownership": "owned", "business_unit": "HP"},
            },
        }
    )
    res = corpus.resolve(ar, cfg)
    kinds = {r.base: r.report_kind for r in res.records}
    assert kinds == {"t1": "cloud-config", "r1": "code-audit"}
