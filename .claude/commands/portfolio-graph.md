---
description: "Build or query the portfolio dependency graph to trace shared components and vulnerability impact."
---

Build, refresh, or query the portfolio source-code graph using the portfolio-graph skill. Load the skill at .claude/skills/portfolio-graph/SKILL.md and follow it: `python3 -m traust.cli portfolio build` builds L0 spine + L1 Go module dependencies into a SQLite db from repo-graph.json (gh-authenticated go.mod fetch, cached per repo), with canned queries top-shared / internal-coupling and SQL for the rest, and the blast radius from traust-core (`python3 -m traust.cli portfolio dependents --name <package> [--ecosystem <eco>] [--version <v>]`). `$ARGUMENTS` may be a query (e.g. "blast-radius golang.org/x/net") or build/refresh. Layers 2-4 are gated on explicit user go-ahead per progress-tracker/plans/portfolio-graph-plan.md.
