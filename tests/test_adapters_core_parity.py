"""Each `traust adapters` / `traust util` op moved onto a traust-core door writes what the
traust-engine path it replaced wrote, over the same fixtures and the same (fake) binaries.

wave 2: removed by lane (f) once traust-engine is no longer installed.
"""

from __future__ import annotations

import dataclasses
import json
import os
import struct
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from traust_core.v1.context import tool_reports

# delete with the engine (final-drop follow-up)
from traust_engine._util import safe_exec as engine_safe_exec
from traust_engine._util.elf import ElfAnalyzer
from traust_engine.adapters import checkov as engine_checkov
from traust_engine.adapters import gitleaks as engine_gitleaks
from traust_engine.adapters import govulncheck as engine_govulncheck
from traust_engine.adapters import joern as engine_joern
from traust_engine.adapters import opengrep as engine_opengrep
from traust_engine.adapters import osv as engine_osv
from traust_engine.adapters import osv_sbom as engine_osv_sbom
from traust_engine.adapters import yara as engine_yara

from traust.context import load

PROFILES = Path(__file__).parent / "fixtures" / "config" / "safe-exec-profiles.yaml"
# The report's `version` names the package that produced it: traust-engine, now traust-core.
PRODUCER_VERSION = "version"


@pytest.fixture
def bindir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "bin"
    path.mkdir()
    monkeypatch.setenv("PATH", f"{path}{os.pathsep}{os.environ['PATH']}")
    return path


def fake(bindir: Path, name: str, body: str) -> None:
    path = bindir / name
    path.write_text(f"#!{sys.executable}\nimport json, sys\nargs = sys.argv[1:]\n{body}\n")
    path.chmod(0o755)


def checkout(root: Path, files: dict[str, str], *, commit: bool = False) -> Path:
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    if commit:
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        ident = ["-c", "user.email=t@example.test", "-c", "user.name=t"]
        for argv in (["init", "-q"], ["add", "."], [*ident, "commit", "-qm", "c"]):
            subprocess.run(["git", "-C", str(root), *argv], check=True, env=env)
    return root


def without(doc: dict, *keys: str) -> dict:
    return {k: v for k, v in doc.items() if k not in keys}


OPENGREP = """
if args == ["--version"]:
    print("opengrep 1.25.0")
else:
    target = args[-1]
    print(json.dumps({
        "results": [
            {"check_id": "pack.go.weak-hash", "path": f"{target}/main.go",
             "start": {"line": 3}, "end": {"line": 4},
             "extra": {"severity": "ERROR", "message": "md5 // nosemgrep", "lines": "md5.Sum(b)",
                       "metadata": {"cwe": ["CWE-328: weak hash"], "owasp": "A02",
                                    "confidence": "HIGH"},
                       "dataflow_trace": {}}},
            {"check_id": "pack.go.tls-skip", "path": f"{target}/test/x_test.go",
             "start": {"line": 1}, "end": {"line": 1},
             "extra": {"severity": "WARNING", "message": "skip verify"}},
        ],
        "errors": [{"level": "warn", "type": "Syntax", "message": "skipped", "path": "y.go"}],
        "paths": {"scanned": ["main.go", "test/x_test.go"]},
        "skipped_rules": [{"rule_id": "z"}],
    }))
"""


@pytest.mark.parametrize("rule_allow", [None, "weak-hash"])
def test_opengrep(tmp_path: Path, bindir: Path, rule_allow: str | None) -> None:
    fake(bindir, "opengrep", OPENGREP)
    # the engine's coverage block always counted the default pack, so parity holds on it
    pack = engine_opengrep.default_rule_pack_dir()
    repo = checkout(
        tmp_path / "repo",
        {"main.go": "package main\n\n// nosemgrep\nx\n", "test/x_test.go": "package x\n"},
    )
    engine = engine_opengrep._execute_opengrep_scan(
        repo, [], timeout=60, opengrep_bin="opengrep", rule_pack=pack, rule_allow=rule_allow
    )
    core = tool_reports.opengrep_report(
        load(), repo, [], pack=pack, rule_allow=rule_allow, timeout=60, binary="opengrep"
    )
    assert without(core, PRODUCER_VERSION) == without(engine, PRODUCER_VERSION)


GOVULNCHECK = """
for rec in [
    {"config": {"scanner_name": "govulncheck", "scanner_version": "v1.1.4", "db": "x"}},
    {"osv": {"id": "GO-1", "aliases": ["CVE-1"], "summary": "bad"}},
    {"osv": {"id": "GO-2", "aliases": [], "details": "worse"}},
    {"finding": {"osv": "GO-1", "fixed_version": "v1.2.0", "trace": [
        {"module": "m", "version": "v1.0.0", "package": "m/p", "function": "F"},
        {"module": "app", "package": "app", "function": "main"}]}},
    {"finding": {"osv": "GO-2", "trace": [{"module": "n", "version": "v0.1.0"}]}},
]:
    print(json.dumps(rec))
"""


def test_govulncheck(tmp_path: Path, bindir: Path) -> None:
    fake(bindir, "govulncheck", GOVULNCHECK)
    repo = checkout(tmp_path / "repo", {"go.mod": "module app\n"}, commit=True)
    section = SimpleNamespace(profiles=yaml.safe_load(PROFILES.read_text())["profiles"])
    rc, _out, _err, tool, candidates = engine_govulncheck._run_govulncheck(
        repo, 60, "govulncheck", profile_map=engine_safe_exec.profiles_from_section(section)
    )
    doc = tool_reports.govulncheck_report(
        load(), repo, timeout=60, binary="govulncheck", harness_version="h"
    )
    assert rc == 0
    assert doc["metadata"]["tool"] == tool
    assert doc["metadata"]["commit"] == engine_govulncheck.repo_head(repo)
    assert doc["candidates"] == candidates
    reach = dict.fromkeys(engine_govulncheck.REACH_ORDER, 0)
    for c in candidates:
        reach[c["reachability"]] += 1
    assert doc["summary"] == {"osv_total": len(candidates), **reach}


def test_checkov_k8s_hardening(tmp_path: Path) -> None:
    repo = checkout(
        tmp_path / "repo",
        {
            "deploy/pod.yaml": (
                "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n  namespace: n\nspec:\n"
                "  hostNetwork: true\n  containers:\n  - name: c\n    image: i:latest\n"
                "    securityContext:\n      privileged: true\n      runAsUser: 0\n"
            ),
            "deploy/rbac.yaml": (
                "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n"
                "  name: r\nrules:\n- apiGroups: ['*']\n  resources: ['*']\n  verbs: ['*']\n"
            ),
            "charts/t.yaml": "kind: Pod\nmetadata:\n  name: {{ .Values.name }}\n",
            "main.go": "package main\nvar _ = tls.Config{InsecureSkipVerify: true}\n",
        },
    )
    scanner = engine_checkov.Scanner(repo)
    scanner.run()
    assert tool_reports.k8s_hardening_report(repo) == scanner.report()


GITLEAKS = """
if args == ["version"]:
    print("8.30.1")
else:
    report = args[args.index("--report-path") + 1]
    repo = args[1]
    json.dump([
        {"RuleID": "aws-access-token", "Description": "AWS", "File": f"{repo}/k.env",
         "StartLine": 1, "EndLine": 1, "Entropy": 4.2, "Fingerprint": "c:k.env:aws:1",
         "Line": "KEY=REDACTED", "Commit": "abc", "Date": "2026-01-01", "Email": "a@example.test"},
        {"RuleID": "generic", "Description": "", "File": f"{repo}/a.txt", "StartLine": 2,
         "EndLine": 2, "Fingerprint": "c:a.txt:generic:2"},
    ], open(report, "w"))
"""


@pytest.mark.parametrize("mode", ["dir", "history"])
def test_gitleaks(tmp_path: Path, bindir: Path, mode: str) -> None:
    fake(bindir, "gitleaks", GITLEAKS)
    rules = checkout(tmp_path / "rules", {"g.toml": "title = 't'\n"}) / "g.toml"
    repo = checkout(
        tmp_path / "repo", {"k.env": "KEY=x\n", "a.txt": "x\nt # gitleaks:allow\n"}, commit=True
    )
    raw = engine_gitleaks._run_gitleaks(repo, mode, rules, 60, "gitleaks")
    engine = {
        "metadata": {
            "artifact": "gitleaks-secret-candidates",
            "mode": mode,
            "repository": str(repo),
            "head": engine_gitleaks.repo_head(repo),
            "gitleaks_version": engine_gitleaks.tool_version("gitleaks"),
        },
        "candidates": engine_gitleaks.parse_report(raw, repo, mode),
    }
    core = tool_reports.gitleaks_report(
        load(), repo, mode=mode, config=rules, timeout=60, binary="gitleaks"
    )
    assert core == engine


YARA = """
if args == ["--version"]:
    print("4.5.8")
else:
    target = args[-1]
    print(f"Family_Trojan {target}/payload.bin")
    print(f"Family_Trojan {target}/tests/sample.bin")
    print("warning: slow rule", file=sys.stderr)
"""


def test_yara(tmp_path: Path, bindir: Path) -> None:
    fake(bindir, "yara", YARA)
    rules = checkout(
        tmp_path / "rules",
        {"malware/Win32.Trojan.Family.yara": "rule Family_Trojan { condition: true }\n"},
    )
    target = checkout(tmp_path / "target", {"payload.bin": "x", "tests/sample.bin": "y"})
    engine = engine_yara._execute_yara_scan(
        target, [str(rules)], timeout=60, yara_bin="yara", max_file_mb=4
    )
    core = tool_reports.yara_report(
        load(), target, [str(rules)], timeout=60, binary="yara", max_file_mb=4
    )
    assert without(core, PRODUCER_VERSION) == without(engine, PRODUCER_VERSION)


JOERN_PARSE = """
out = args[args.index("--output") + 1]
open(out, "w").write("cpg")
"""
JOERN = """
if args == ["--version"]:
    print("joern 4.0.600")
else:
    params = dict(a.split("=", 1) for a in args if "=" in a)
    pattern = open(params["symbolsFile"]).read().split()[0]
    repo = sys.argv[0].rsplit("/bin/", 1)[0] + "/repo"
    open(params["outFile"], "w").write(
        f"SITE\\t{pattern}\\t{repo}/src/A.java\\t7\\tA.run\\tB.call\\n"
        f"SITE\\t{pattern}\\t{repo}/src/test/T.java\\t3\\tT.t\\tB.call\\n"
        f"COUNT\\t{pattern}\\t2\\n"
    )
"""


@pytest.mark.parametrize("symbols", [["com.example.B#call"], []])
def test_joern(tmp_path: Path, bindir: Path, symbols: list[str]) -> None:
    fake(bindir, "joern-parse", JOERN_PARSE)
    fake(bindir, "joern", JOERN)
    repo = checkout(
        tmp_path / "repo",
        {"src/A.java": "class A { void run() { new B().call(); } }\n", "src/test/T.java": "x\n"},
    )
    kw = {"language": "java", "packages": "", "module": "", "timeout": 60, "max_sites": 10}
    engine = engine_joern._run_joern_scan(repo, symbols=symbols or None, **kw)
    out = tmp_path / "engine.json"
    engine_joern.emit(out, engine)
    core = tool_reports.joern_report(load(), repo, symbols=symbols, **kw)
    assert core == json.loads(out.read_text())


OSV_SCANNER = """
if args == ["--version"]:
    print("osv-scanner version: 2.7.0")
    sys.exit(0)
target = args[-1]
pkg = {"name": "golang.org/x/net", "ecosystem": "Go", "version": "0.1.0"}
affected = [{"package": {"name": "golang.org/x/net", "ecosystem": "Go"},
             "ranges": [{"events": [{"introduced": "0"}, {"fixed": "0.2.0"}]}]}]
print(json.dumps({"results": [{"source": {"path": f"{target}/go.mod"}, "packages": [
    {"package": pkg, "groups": [{"ids": ["GO-2"], "max_severity": "7.5"}],
     "vulnerabilities": [{"id": "GO-2", "aliases": ["CVE-2"], "summary": "s",
                          "affected": affected}]}]}]}))
sys.exit(1)
"""


def _engine_osv_scanner_body(repo: Path) -> dict:
    """`adapters osv --source osv-scanner` on the engine, as the CLI built it."""
    proc, invocation = engine_osv.run_scanner("osv-scanner", repo, 600, freeze=True)
    scan = json.loads(proc.stdout)
    return {
        "provenance": {
            "source": "osv-scanner",
            "tool_version": (scan.get("experimental_config") or {}).get("version")
            or engine_osv._tool_version("osv-scanner")
            or "",
            "invocation": invocation,
            "status": "complete",
        },
        "candidates": engine_osv.parse_output(scan, repo),
    }


def test_osv_scanner_offline(tmp_path: Path, bindir: Path) -> None:
    fake(bindir, "osv-scanner", OSV_SCANNER)
    repo = checkout(tmp_path / "repo", {"go.mod": "module m\n"})
    core = tool_reports.osv_report(load(), repo, scanner="osv-scanner", timeout=600)
    assert core == _engine_osv_scanner_body(repo)


SYFT = {
    "source": {"name": "example/app", "metadata": {"userInput": "registry.example.test/app"}},
    "artifacts": [
        {"id": "r1", "type": "rpm", "purl": "pkg:rpm/redhat/python3-urllib3@1.26.5"},
        {
            "id": "p1",
            "type": "python",
            "purl": "pkg:pypi/urllib3@1.26.5",
            "locations": [{"path": "/usr/lib/python3.9/site-packages/urllib3"}],
        },
        {
            "id": "p2",
            "type": "python",
            "purl": "pkg:pypi/requests@2.19.0",
            "locations": [{"path": "/opt/app-root/lib/requests"}],
        },
        {"id": "p3", "type": "npm", "purl": "pkg:npm/left-pad"},
    ],
    "artifactRelationships": [{"parent": "r1", "child": "p1", "type": "ownership-by-file-overlap"}],
}
SBOM_SCANNER = """
print(json.dumps({"results": [{"packages": [
    {"package": {"name": "requests", "ecosystem": "PyPI", "version": "2.19.0"},
     "vulnerabilities": [{"id": "GHSA-a", "aliases": ["CVE-1"]}]}]}]}))
sys.exit(1)
"""
GRYPE = {
    "matches": [
        {"artifact": {"purl": "pkg:pypi/requests@2.19.0"}, "vulnerability": {"id": "CVE-1"}},
        {
            "artifact": {"id": "p1", "type": "python", "purl": "pkg:pypi/urllib3@1.26.5"},
            "vulnerability": {"id": "GHSA-38jv", "severity": "High"},
        },
    ]
}


def _engine_sbom_body(sbom: Path) -> dict:
    """`adapters osv --sbom … --grype …` air-gapped on the engine, as the CLI built it."""
    doc = engine_osv_sbom.load_syft(sbom)
    packages, stats = engine_osv_sbom.collect_sbom_packages(doc)
    cdx = engine_osv_sbom.write_cyclonedx(packages, sbom.parent / "packages.cdx.json")
    proc, invocation = engine_osv_sbom.run_offline("osv-scanner", cdx, 600)
    body = {
        "provenance": {"source": "osv-scanner", "invocation": invocation, "status": "complete"},
        "candidates": engine_osv_sbom.parse_offline(json.loads(proc.stdout), packages),
    }
    engine_osv_sbom._with_stats(body["provenance"], stats, doc)
    matches = engine_osv_sbom.grype_os_installed_matches(GRYPE, doc)
    body["provenance"]["grype_os_installed_matches"] = len(matches)
    body["provenance"]["grype_dedupe"] = engine_osv_sbom.mark_grype_duplicates(
        body["candidates"], GRYPE
    )
    return {**body, "grype_os_installed": matches}


def test_osv_sbom_offline(tmp_path: Path, bindir: Path) -> None:
    fake(bindir, "osv-scanner", SBOM_SCANNER)
    sbom = tmp_path / "app.syft.json"
    sbom.write_text(json.dumps(SYFT))
    engine = _engine_sbom_body(sbom)
    core = tool_reports.osv_sbom_report(
        load(), sbom, scanner="osv-scanner", timeout=600, grype=GRYPE
    )
    # the CycloneDX file osv-scanner reads now lives in a scratch directory
    engine["provenance"]["invocation"] = engine["provenance"]["invocation"].split(" -L ")[0]
    core["provenance"]["invocation"] = core["provenance"]["invocation"].split(" -L ")[0]
    assert core == engine


def _elf(libs: tuple[str, ...] = ()) -> bytes:
    """A little-endian x86_64 ELF header followed by `libs` as plain strings."""
    header = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    header += struct.pack("<HHIQQQIHHHHHH", 3, 62, 1, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0)
    return header + b"\x00".join(lib.encode() for lib in libs)


@pytest.mark.parametrize("symbols", [["SSL_CTX_new", "EVP_.*"], []])
def test_util_elf(tmp_path: Path, symbols: list[str]) -> None:
    import re

    binary = tmp_path / "bin"
    binary.write_bytes(_elf(("libssl.so.3", "SSL_CTX_new", "EVP_sha1")))
    analyzer = ElfAnalyzer(binary)
    meta = analyzer.metadata()
    engine = {
        "path": str(binary),
        "metadata": {"arch": meta.arch, "elf_class": meta.elf_class, "endian": meta.endian},
        "linked_libraries": [lib.name for lib in analyzer.linked_libraries()],
    }
    if symbols:
        patterns = [(s, re.compile(s.encode("ascii", errors="ignore"))) for s in symbols]
        engine["string_matches"] = [
            {"pattern_id": m.pattern_id, "matched": m.matched, "offset": m.offset}
            for m in analyzer.scan_strings(patterns, max_scan=32_000_000)
        ]
    assert tool_reports.elf_report(binary, symbols, max_scan=32_000_000) == engine
    text = tmp_path / "text"
    text.write_text("not an elf")
    assert ElfAnalyzer(text).metadata() is None
    assert tool_reports.elf_report(text, symbols, max_scan=10) is None


SAFE_EXEC_COMMANDS = [
    ("go-scan", ["govulncheck", "-json", "./..."]),
    ("go-scan", ["curl", "https://example.test"]),
    ("go-scan", "govulncheck -json ./... | grep x"),
    ("validation-step", "curl -s https://example.test | jq .x"),
    ("validation-step", "curl -k --config /etc/x https://example.test"),
    ("validation-step", ["kubectl", "--token", "t", "get", "pods"]),
    ("validation-step", "cat $(whoami)"),
    ("validation-step", "FOO=bar echo hi"),
    ("go-fuzz", ["git", "-c", "core.sshCommand=x", "fetch"]),
    ("go-fuzz", ["go", "test", "./..."]),
    ("java-build", ["./gradlew", "build"]),
    ("java-build", ["/usr/bin/java", "-version"]),
    ("generic-build", ["bash", "-c", "make"]),
    ("generic-build", []),
]


@pytest.mark.parametrize(("profile", "cmd"), SAFE_EXEC_COMMANDS)
def test_util_safe_exec_verdicts(profile: str, cmd: str | list[str]) -> None:
    section = SimpleNamespace(profiles=yaml.safe_load(PROFILES.read_text())["profiles"])
    engine_profile = engine_safe_exec.profiles_from_section(section)[profile]
    safe_exec = load().safe_exec
    core_profile = safe_exec.profile(profile)
    assert dataclasses.asdict(core_profile) == dataclasses.asdict(engine_profile)
    if isinstance(cmd, str):
        engine = engine_safe_exec.vet_command_string(cmd, engine_profile)
        core = safe_exec.vet_command_string(cmd, core_profile)
    else:
        engine = engine_safe_exec.validate_argv(cmd, engine_profile)
        core = safe_exec.validate_argv(cmd, core_profile)
    assert (core.ok, core.reason) == (engine.ok, engine.reason)
    if isinstance(cmd, str):
        assert core.segments == engine.segments
