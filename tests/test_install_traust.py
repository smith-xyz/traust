"""scripts/install_traust — the adopter's starting point and its --doctor."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "install_traust"


def _run(args, env_extra=None, cwd=REPO):
    env = {**os.environ, "HOME": os.environ.get("HOME", "/tmp"), **(env_extra or {})}
    return subprocess.run(
        ["bash", str(SCRIPT), *args], capture_output=True, text=True, env=env, cwd=cwd
    )


def test_help_exits_zero():
    r = _run(["--help"])
    assert r.returncode == 0 and "TRAUST_CONFIG_HOME" in r.stdout


def test_noninteractive_install_copies_traust_yaml_and_the_model_registry(tmp_path):
    home = tmp_path / "cfg"
    r = _run(["--yes", "--config-home", str(home), "--no-toolchain", "--no-profile-write"])
    assert r.returncode == 0, r.stdout + r.stderr
    assert sorted(p.name for p in home.iterdir()) == ["model-registry.yaml", "traust.yaml"]
    assert (home / "traust.yaml").read_text() == (
        REPO / "config" / "traust.example.yaml"
    ).read_text()
    assert (home / "model-registry.yaml").read_text() == (
        REPO / "config" / "model-registry.yaml"
    ).read_text()


def test_install_never_overwrites_without_force(tmp_path):
    home = tmp_path / "cfg"
    home.mkdir()
    (home / "traust.yaml").write_text("execution: {sandbox: podman}\n")
    r = _run(["--yes", "--config-home", str(home), "--no-toolchain", "--no-profile-write"])
    assert r.returncode == 0
    assert (home / "traust.yaml").read_text() == "execution: {sandbox: podman}\n"
    assert "kept existing traust.yaml" in r.stdout


def test_doctor_fails_closed_when_unset_and_default_absent(tmp_path):
    env = {"HOME": str(tmp_path)}
    r = subprocess.run(
        ["bash", str(SCRIPT), "--doctor"],
        capture_output=True,
        text=True,
        env={k: v for k, v in {**os.environ, **env}.items() if k != "TRAUST_CONFIG_HOME"},
        cwd=REPO,
    )
    assert r.returncode == 1 and "run scripts/install_traust" in r.stdout


def test_doctor_smoke_on_a_fresh_install(tmp_path):
    """Fresh install: the copied traust.yaml loads; unset locations are warnings, not errors."""
    home = tmp_path / "cfg"
    _run(["--yes", "--config-home", str(home), "--no-toolchain", "--no-profile-write"])
    r = _run(
        ["--doctor", "--toolchain", "ledger-signing"], env_extra={"TRAUST_CONFIG_HOME": str(home)}
    )
    assert "traust configuration loads" in r.stdout, r.stdout
    assert "locations.workspace unset" in r.stdout
    assert "none left in the home" in r.stdout


def test_doctor_names_retired_files_and_the_migrate_command(tmp_path):
    home = tmp_path / "cfg"
    _run(["--yes", "--config-home", str(home), "--no-toolchain", "--no-profile-write"])
    (home / "locations.yaml").write_text("workspace: /w\n")
    (home / "feeds.yaml").write_text("sources: {}\n")
    r = _run(
        ["--doctor", "--toolchain", "ledger-signing"], env_extra={"TRAUST_CONFIG_HOME": str(home)}
    )
    assert (
        "no longer read: locations.yaml feeds.yaml — fold them into traust.yaml with: " in r.stdout
    )
    assert f"traust config migrate {home}" in r.stdout


@pytest.mark.skipif(
    not os.environ.get("TRAUST_CONFIG_HOME") or os.environ.get("HARNESS_TEST_FIXTURE_CONFIG"),
    reason="no operational config in this environment (the suite fixture is a bare template)",
)
def test_doctor_passes_on_the_operational_config():
    """With a real TRAUST_CONFIG_HOME (developer workstation / SCI) the doctor's
    file + config-load sections pass; toolchain is checked for the smallest profile."""
    r = _run(["--doctor", "--toolchain", "ledger-signing"])
    assert "traust configuration loads" in r.stdout, r.stdout
    assert "missing" not in r.stdout.split("3. Retired files")[0]
