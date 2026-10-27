#!/usr/bin/env python3
"""Build the pinned Traust Python dependencies as wheels, at the commits uv.lock resolved.

The image installs these with --no-deps: traust-core, the traust-contracts and traust-ledger it
imports (through its pins), and traust-engine while traust's sweep, portfolio-graph and
metrics-journal ops still run on it. Every revision is read from the lock.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

PACKAGES = ("traust-contracts", "traust-ledger", "traust-core", "traust-engine")
COMMIT_SHA = re.compile(r"[0-9a-f]{40}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel_dir", type=Path)
    wheel_dir = parser.parse_args().wheel_dir

    project_root = Path(__file__).resolve().parents[1]
    with (project_root / "uv.lock").open("rb") as stream:
        locked = {p["name"]: p.get("source", {}) for p in tomllib.load(stream)["package"]}

    env = os.environ.copy()
    env["GIT_ALLOW_PROTOCOL"] = "https"
    for package in PACKAGES:
        git = locked.get(package, {}).get("git")
        if not isinstance(git, str):
            raise SystemExit(f"uv.lock has no Git source for {package}")
        url, _, revision = git.partition("#")
        url = url.split("?", 1)[0]
        if not url.startswith("https://"):
            raise SystemExit(f"{package} must use an HTTPS Git URL")
        if not COMMIT_SHA.fullmatch(revision):
            raise SystemExit(f"{package} must be pinned to a full commit SHA")

        requirement = f"{package} @ git+{url}@{revision}"
        print(f"Building {package} at {revision}", flush=True)
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "--wheel-dir",
                str(wheel_dir),
                requirement,
            ],
            check=True,
            env=env,
        )


if __name__ == "__main__":
    main()
