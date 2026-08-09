# HunterStick

**The instructions for this project live in [`AGENTS.md`](AGENTS.md). Read it now, in full,
before doing anything else.**

This file exists only because Claude Code loads it automatically. It is deliberately a pointer:
one canonical instruction set, so the two can never drift.

Claude Code specifics — everything else is in `AGENTS.md`:

- `.claude/skills/*/SKILL.md` frontmatter **descriptions** are what Claude Code matches on, so
  saying *"test IDOR on /api/orders"* fires the right skill without naming a path. `self-check.py`
  now enforces that the `AGENTS.md` router names only real skills and that its advertised count
  matches the dispatchers the runtime exposes; keeping each description in step with its router row
  is still yours to do. Runtimes that load root `AGENTS.md` use the same router; runtimes without
  instruction or skill discovery must be pointed to `AGENTS.md` explicitly.
- `.mcp.json` wires the browser and Burp MCP servers used by application mapping.
