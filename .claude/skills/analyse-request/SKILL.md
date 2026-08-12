---
name: analyse-request
description: Analyze a pasted raw HTTP request as a bug-bounty entrypoint. Use when the human pastes a Burp, DevTools, mobile-proxy, curl, or raw HTTP request and asks what to test, what vulnerabilities apply, or to analyze/analyse the request. Routes directly to the request-analysis workflow without recon.
---

Read `skills/analysis/analyse-request.md` and follow it.

That file is the single body for this skill; this pointer exists only so Claude Code
can auto-trigger on the description above. Every other runtime dispatches to the same
file through the router table in `AGENTS.md`.
