"""The per-technology review checks: every check cites a CWE and its standard requirement, and
both audit skills wire the reference."""

import re

from traust.paths import HARNESS_ROOT

CHECKS = HARNESS_ROOT / "harnessing" / "3-audit" / "secure-code-audit" / "framework-checks.md"
ROW = re.compile(
    r"^\| (?P<id>[A-Z]{2}\.\d+) \| (?P<check>.+?) \| (?P<cwe>[^|]+) \| (?P<req>[^|]+) \|"
)
CWE = re.compile(r"CWE-\d+( / CWE-\d+)*")
ASVS = re.compile(r"ASVS V\d+\.\d+( / ASVS V\d+\.\d+)*")
K_ID = re.compile(r"K(0[1-9]|10)( / K(0[1-9]|10))*")


def _rows() -> list[re.Match[str]]:
    return [m for ln in CHECKS.read_text(encoding="utf-8").splitlines() if (m := ROW.match(ln))]


def test_both_sections_are_present_and_ids_unique():
    rows = _rows()
    ids = [m["id"] for m in rows]
    assert len(ids) == len(set(ids))
    assert {i.split(".")[0] for i in ids} == {"OP", "GR"}
    assert (
        sum(i.startswith("OP.") for i in ids) >= 10 and sum(i.startswith("GR.") for i in ids) >= 8
    )


def test_every_check_names_a_cwe_and_its_standard_requirement():
    for m in _rows():
        assert CWE.fullmatch(m["cwe"].strip()), (m["id"], m["cwe"])
        asvs, _, k = (p.strip() for p in m["req"].partition(";"))
        assert ASVS.fullmatch(asvs), (m["id"], m["req"])
        assert asvs.count("/") == m["cwe"].count("/"), m["id"]  # one section per CWE
        if k:
            assert m["id"].startswith("OP.") and K_ID.fullmatch(k), (m["id"], k)


def test_both_skills_wire_the_reference():
    for skill in ("secure-code-audit", "vuln-scan"):
        text = (HARNESS_ROOT / "harnessing" / "3-audit" / skill / "SKILL.md").read_text()
        assert "framework-checks.md" in text, skill
        assert '"framework-checks": "ran: <sections>"' in text, skill
