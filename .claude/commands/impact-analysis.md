---
description: "Determine which portfolio commits are affected by an advisory using SBOM, reachability and source evidence."
---

Determine per-commit advisory affectedness across the portfolio using the impact-analysis skill. Load the skill at .claude/skills/impact-analysis/SKILL.md and follow it: `traust impact find` fetches the advisory from its source, `traust impact analyze` walks the blast radius over recorded SBOMs, classifies each commit (Go: govulncheck symbol reachability; npm/PyPI/Maven/Cargo/Ruby/NuGet/C: SBOM pin plus source scans; Actions/Docker/Helm: manifest-level) and records an `impact` assessment per commit in traust-core, with a dependency finding for each `affected` commit. `$ARGUMENTS` is the advisory id, optionally `--repo-url <url> --sha <commit>` and `--scan`.
