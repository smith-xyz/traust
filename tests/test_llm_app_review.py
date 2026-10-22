"""LLM application review: the `adapters llm-app` command and the checklist's shape."""

import json
import re
from types import SimpleNamespace

from traust.cli.groups import adapters
from traust.paths import HARNESS_ROOT

CHECKLIST = (
    HARNESS_ROOT / "harnessing" / "3-audit" / "secure-code-audit" / "llm-application-review.md"
)


def test_the_command_writes_the_detection(tmp_path, capsys):
    repo = tmp_path / "svc"
    (repo / "server").mkdir(parents=True)
    (repo / "server" / "tools.py").write_text("from mcp.server.fastmcp import FastMCP\n")
    out = tmp_path / "o.json"
    assert adapters.call_llm_app(None, SimpleNamespace(repo=repo, out=out)) == 0
    doc = json.loads(out.read_text())
    assert doc["metadata"]["artifact"] == "llm-app-detection"
    assert doc["llm_application"] is True
    assert doc["kinds"] == ["mcp-server"]
    assert doc["files"] == {"server/tools.py": ["mcp-server"]}
    assert "LLM application (mcp-server)" in capsys.readouterr().out


def test_a_plain_repo_is_reported_as_none(tmp_path, capsys):
    (tmp_path / "a.py").write_text("import os\n")
    out = tmp_path / "o.json"
    assert adapters.call_llm_app(None, SimpleNamespace(repo=tmp_path, out=out)) == 0
    assert json.loads(out.read_text())["llm_application"] is False
    assert "no LLM" in capsys.readouterr().out


def test_not_a_directory(tmp_path):
    assert adapters.call_llm_app(None, SimpleNamespace(repo=tmp_path / "x", out=None)) == 2


def test_the_checklist_covers_every_owasp_category():
    text = CHECKLIST.read_text(encoding="utf-8")
    headings = re.findall(r"^## (LLM\d\d) — ", text, re.M)
    assert headings == [f"LLM{n:02d}" for n in range(1, 11)]


def test_every_check_names_a_cwe_or_is_a_threat_model_item():
    rows = [
        ln
        for ln in CHECKLIST.read_text(encoding="utf-8").splitlines()
        if re.match(r"^\| \d\d\.\d+ \|", ln)
    ]
    assert len(rows) >= 30
    for row in rows:
        cells = [c.strip() for c in row.strip("|").split("|")]
        number, check, cwe = cells[0], cells[1], cells[2]
        if check.startswith("*Threat model:*"):
            assert cwe == "—", number
        else:
            assert re.fullmatch(r"CWE-\d+( / CWE-\d+)*", cwe), (number, cwe)


def test_both_skills_wire_the_pre_scan_and_the_checklist():
    for skill in ("secure-code-audit", "vuln-scan"):
        text = (HARNESS_ROOT / "harnessing" / "3-audit" / skill / "SKILL.md").read_text()
        assert "adapters llm-app" in text, skill
        assert "llm-application-review.md" in text, skill
