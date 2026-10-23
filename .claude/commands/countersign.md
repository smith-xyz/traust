---
description: "Review pending findings and record verified-human judgements through core services."
---

Load .claude/skills/countersign/SKILL.md and follow its reviewed-human workflow. $ARGUMENTS selects a core finding UUID, the pending queue, or a private reviewed-answer JSON file. Read queue cards and their evidence through `python3 -m traust.cli admin countersign queue`; page with the returned cursor and unchanged filters. Obtain the human's explicit canonical judgement and own rationale before direct `record` or selected-review `apply` (single JSON object or bulk array). Both confirm and reject require real selected fields; never infer an opposite verdict, parse evidence as approval, or adopt a machine rationale. Operator credentials arrive only on stdin; never read them into agent context, argv or logs. Core owns identity, evidence admission, actor, clock, persistence and atomic review closure. Never fall back to legacy layers or another login store.
