---
description: "Record a verified human's direct severity judgement through core services."
---

Load .claude/skills/countersign/SKILL.md and follow its direct severity-record procedure. $ARGUMENTS is an existing core finding UUID, not a findings directory or legacy report ID. Confirm the requested canonical severity and the human's own rationale, then use `python3 -m traust.cli admin countersign record --decision severity` with `--finding`, `--severity`, `--rationale`, `--token-stdin` and the deployment config home. The operator delivers the credential only through stdin; never read it into the agent context, argv or logs. Quote all dynamic arguments safely. Show the token/rationale-free JSON receipt. Queue, bulk apply, validity overrides and mapping review remain unported: report that limitation rather than invoking retired commands or writing layer files.
