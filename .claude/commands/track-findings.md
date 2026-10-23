---
description: "Record human statements on findings as decisions in traust-core and report their current state."
---

Record human triage feedback against the findings of an audited repository and report their current state. Load the skill at .claude/skills/track-findings/SKILL.md and follow its full procedure — $ARGUMENTS names the repository (its https URL) and its audit report, followed by zero or more sources: merge-request/PR/commit URLs, Jira keys, --interactive for a triage session with the person, or --auto to import without walking the review queue (no sources = auto-discover the findings' Jira tickets). Statements go through `traust findings import`: core records what needs no interpretation (the /traust grammar from a maintainer, a commit fix trailer) as the logged-in caller and queues the rest for the person to confirm or reject. Machine reports (triage, validation, verification) record through their own skills.
