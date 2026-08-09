---
name: compose-task
description: Turn an off-playbook, multi-step hunting request into brain-integrated work. Use when the hunter asks for something no single skill or flow covers — a custom pipeline such as "extract JS from the 404 hosts, pull the params, then test them", "chain these three steps", "do X then feed it into Y", or any ad-hoc request that stitches several capabilities together. Decomposes into existing skills plus the minimum novel glue, runs every step through the harness, and persists the result.
---

Read `skills/compose-task.md` and follow it.

That file is the single body for this skill; this pointer exists only so Claude Code
can auto-trigger on the description above. Every other runtime dispatches to the same
file through the router table in `AGENTS.md`.
