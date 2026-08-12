---
name: tech-analysis
description: Analyze a bug-bounty application through its known or suspected web framework, CMS, API/gateway, identity provider, BaaS, enterprise product, server, or versioned component. Use when the hunter names a technology (for example Next.js, Django, Spring, WordPress, GraphQL, Keycloak, Supabase, Jenkins), asks what a detected stack changes, asks which vulnerabilities or entrypoints the technology suggests, or wants technology-fingerprinting or component-inventory evidence converted into target-specific hypotheses. Verify the stack and deployment mode, compose multiple layers, consult current upstream sources when needed, update the target brain, and stop before testing unless the hunter separately authorizes a vulnerability test.
---

# Analyze one technology stack

## Inputs

- `@hunter.technology` — **the stack, product or component to analyse**, either named by the
  hunter or fingerprinted and confirmed. Without it there is nothing to reason about.
- `@tech` (optional, from `technology-fingerprinting`) and `@components` (optional, from
  `component-inventory`) — evidence for the claim, and the version confidence behind it.
- `@hunter.host` (optional) — the deployment to reason about, when the analysis is
  target-specific rather than about the product in general.


1. Resolve the named target and load its scope, index, technology/component evidence, application map
   and relevant captured traffic. Do not infer authorization from a fingerprint.
2. Read `playbooks/tech/_analysis.md` and `playbooks/tech/_index.md` in full.
3. Build the stack graph. Do not collapse client, server, gateway, identity, data and extension
   layers into one framework name.
4. Load only the matching deep profile and family reference named by the index. For an unknown,
   version-sensitive or current-advisory question, load `playbooks/tech/references/live-research.md`
   and use current primary sources.
5. Verify identity, deployment mode, version precision, reachability and target ownership before
   deriving hypotheses.
6. Map observed mechanisms and cross-layer seams to canonical vulnerability classes. Let target
   behavior override generic framework expectations.
7. Record corrected facts, implicated entrypoints and bounded hypotheses in the target brain using
   the output contract in `_analysis.md`.
8. Report the delta, uncertainties, lower-priority paths and 2–3 conditional next actions. Stop.

Do not turn a framework fingerprint, public client identifier, CVE match or default endpoint into a
finding. Do not run vulnerability probes unless the hunter explicitly invokes the normal
vulnerability-hunt unit.
