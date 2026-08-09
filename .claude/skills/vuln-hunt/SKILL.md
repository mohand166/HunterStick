---
name: vuln-hunt
description: Hunt a specific vulnerability class (or family) on one entrypoint of the bug bounty target the human names. Use for "test for SQLi/XSS/IDOR/SSRF/XXE/CSRF/SSTI/RCE", "hunt <class> on <url>", "check access control / authz / BOLA", "look for business logic bugs", "test the login/password reset/OAuth flow", "race condition", "prototype pollution", "cache poisoning", "subdomain takeover", "GraphQL/API testing", "client-side injections", "server-side bugs", or any request to actively test a target for a vuln class. One entrypoint, one class at a time, evidence-backed.
---

Read `skills/vuln-hunt.md` and follow it.

That file is the single body for this skill; this pointer exists only so Claude Code
can auto-trigger on the description above. Every other runtime dispatches to the same
file through the router table in `AGENTS.md`.
