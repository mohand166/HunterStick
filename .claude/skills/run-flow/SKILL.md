---
name: run-flow
description: Run a named flow — a bundled response to a situation — against the bug bounty target the human names. Use for "what should I run on X", "what now", "suggest a flow", "this host returns 404 on everything", "the host is a dead end", "no signup on this target", "this is a JS app / SPA", "there's an OpenAPI spec", "we have thousands of hosts", "this looks like a static site", "I'm coming back to this target after a while", "everything returns 200 / soft-404", or any request to run a multi-step recon bundle in one command. Two intents: "what should I run?" recommends and stops; a named flow runs without asking again. Always declares steps and cost first; a missing required input is the one hard stop; never sends a payload.
---

Read `skills/run-flow.md` and follow it.

That file is the single body for this skill; this pointer exists only so Claude Code
can auto-trigger on the description above. Every other runtime dispatches to the same
file through the router table in `AGENTS.md`.
