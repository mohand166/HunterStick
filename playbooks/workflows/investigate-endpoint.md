# Investigate Endpoint

> Process helper. Deep-dive **one** endpoint until you understand it better than the
> people who wrote it — then enumerate what could go wrong across classes. This is
> understanding work, not testing work: passive by default. You leave with hypotheses, not
> claims. Active probing is a separate, human-invoked step.

## Objective
Build a complete mental model of one endpoint — its function, data flow, roles, and trust
boundary — and from that model derive specific, testable hypotheses across every class the
surface plausibly supports.

## When to use
- The human points you at a single endpoint worth a patient look (usually a top-ranked row
  from `attack-surface.md` or a lead from JS/API discovery).
- Before testing a rich endpoint, so the test is aimed by understanding rather than sprayed.

## Inputs
- The endpoint (URL, method) the human named.
- `recon/endpoints.md`, `recon/js-findings.md` — what's already known about it.
- `applications/<host>/map.md` — where it sits in the app, which roles reach it.
- `accounts.md` — the roles/accounts available to observe it from different vantage points.
- `target.md`, `recon/technologies.md` — the backend stack behind it.
- `scope.md` — confirm it's in scope before touching it at all.

## Process
1. **Function.** What does this endpoint actually *do*? Intended behavior, who calls it,
   why it exists. Read the client code / JS that calls it and any API contract.
2. **Inputs.** Enumerate every parameter, header, and body field — including
   client-supplied ones the server might trust (ids, roles, flags, prices, URLs, file
   refs). Note types, formats, and which look like identifiers or authorization inputs.
3. **Data flow.** Trace where each input enters, how it's transformed, and where it lands
   — the DB query, the file path, the outbound fetch, the template, the auth decision.
   The sink is where a class fires; name the sinks.
4. **Roles & trust boundary.** What authorization *should* gate this? Whose data does it
   touch? Is it a tenant boundary, a privilege boundary, an ownership check? Observe the
   response as different roles/accounts (read-only) to see what actually changes.
5. **Enumerate what could go wrong, per class.** Walk the plausible classes against the
   sinks you found — IDOR/authz on the identifier params, injection on the ones reaching a
   query, SSRF on a URL param, mass-assignment on the body, workflow/state abuse if it's a
   step in a flow. For each, state the mechanism and the discriminator you'd test.
6. **Tag findings FACT / HYPOTHESIS / ASSUMPTION.** Observed behavior is FACT (save the
   artifact if you sent anything). The un-proven mechanisms are HYPOTHESIS. Anything you're
   taking for granted (e.g. "ids are sequential") is an ASSUMPTION to verify.

## Output
- `investigations/<endpoint-slug>/notes.md` — the function/inputs/data-flow/roles model,
  tagged; plus any request/response artifacts saved to that folder or `raw/`.
- `hypotheses.md` — the derived hypotheses appended (H-NNN, `status = open`), each tied to
  a sink you mapped.
- `applications/<host>/map.md` / `endpoints.md` — promote any newly-learned architectural
  facts so the brain stays current.
- `index.md` — investigation + hypotheses counts, phase log, timestamp.
- Summarize the model, the top hypotheses ranked by value/novelty, and what you'd test
  first. Then **STOP** — the human decides whether to authorize active testing.
