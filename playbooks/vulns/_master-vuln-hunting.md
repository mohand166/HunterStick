# Master Vuln-Hunting Skill (the reasoning scaffold)

Every per-class vuln file (`sql-injection.md`, `idor-bola.md`, …) is **thin** — it only
carries what's *specific* to that class. This file carries the *method* they all share.
When the human says "test <class> on <target>", read this file **and** the class file,
then work the loop below. When they name a **category/family** instead (e.g. "client-side
injections", "access control", "business logic", "server-side bugs"), consult
`playbooks/vulns/_index.md` for that family's class files, load the applicable ones, and
work each through the loop — **scoped to the surfaces that actually exist on the target**
(skip classes whose *Where it hides* isn't present). One class at a time, evidence-backed;
a category command means "test the applicable ones," not "spray all of them."

You are a researcher, not a payload cannon. You do not fire a wordlist of payloads at a
parameter. You **understand the function, model the data flow, form a hypothesis, and
design the smallest safe test that proves or kills it.** A scanner already fired the
payloads — that's why those bugs are duplicates.

Load first: system prompt, target `index.md`, `target.md`, `scope.md`, `accounts.md`,
`tested.md` (so you don't repeat work), and the relevant app map. You are never seeing
this target for the first time — the brain already knows its stack and neighbors.

---

## Tooling — what to run where
- **VPS CLI (curl / httpx / ffuf / nuclei) — the default.** All recon and most
  server-side testing (SQLi, SSRF, IDOR/BOLA, auth logic, API/injection) is HTTP-level;
  do it here. Traffic exits the VPS IP.
- **Chrome MCP (local) — only when a real browser is needed.** Check first whether the
  task genuinely needs a DOM + JS engine: client-side classes (DOM XSS, postMessage,
  prototype pollution, DOM clobbering), SPA route/state discovery, complex SSO/OAuth/MFA
  flows. Don't reach for it on plain HTTP work. If it isn't connected, say so and fall
  back to curl — never pretend a browser step ran.
- **Burp MCP (local) — for validating candidate bugs.** When a hypothesis needs hands-on
  request tampering (Repeater-style), drive it through Burp. **When a bug is confirmed,
  send its request/response to Burp** as the organized artifact. **Do not log everything
  to Burp** — only candidate and confirmed requests, not the recon firehose. The stored
  artifact in `raw/`/`findings/` is still the source of truth (§5 / system prompt §2).

See `playbooks/system/mcp-tooling.md` for setup and the full policy.

---

## The loop

### 0. Orient (from the brain, not from scratch)
- What do we already know about this target/endpoint? (`target.md`, `endpoints.md`,
  app map, `technologies.md`.)
- Has this exact thing been tested already? Check `tested.md`. If yes, don't repeat —
  either go deeper or move on.
- Read `scope.md` for **standing constraints** the hunter set (*"read-only on billing"*,
  *"no new accounts"*) and honour them — those are the hunter's own instructions, not scope
  policing. Scope is otherwise context, not a veto: the hunter named this target and this class,
  so you do not stop to re-authorise it. If something looks outside what they named, say so in one
  sentence and carry on with what they asked.
- **Where the data lives:** orient from the **curated brain locally** (fast — `index.md`,
  `target.md`, `endpoints.md`, `technologies.md`, `tested.md`, app map). Pull **heavy or
  raw** data (full URL/param corpora, raw responses, stored artifacts) **from the VPS on
  demand** via the pointers in `index.md`, and **run the actual requests on the VPS**.
  Don't drag gigabytes of raw output into context — query it where it lives.

### 1. Recognize the surface — enumerate every class that fits, test the one you were given

**Enumerating is analysis. Testing is work the hunter authorised.** Keep those apart; this is the
one place the loop can quietly turn a one-class request into a twelve-class sweep.

- **Enumerate first, always.** Derive the `(entrypoint × class)` candidate set: every class whose
  "Where it hides" matches this entrypoint's source→sink shape, via `_index.md`, or read it off
  the entrypoint's `properties` in `attack-surface.md`. One entrypoint hosts many: a *read*
  endpoint invites path-traversal **and** cache/authz confusion **and** IDOR **and**
  path-parameter normalization; a *search filter* invites SQLi **and** NoSQL **and** tenant
  bypass; an *import/upload* invites zip-slip **and** mass-assignment **and** canonicalization; a
  *token issuer* invites CORS **and** JWT **and** logic flaws. List them all — that list is what
  makes your closing suggestions worth reading.
- **Then test exactly what was invoked:**
  - **a named class** → work that class on that entrypoint, to depth, through every variant its
    file names. This is where "nothing stops you" applies: not a clean scan, not a WAF block, not
    a first negative, not "it looks simple".
  - **a named family** ("access control", "client-side injections") → work the classes in that
    family whose surface is actually present. The family *is* the selection.
  - **everything else you enumerated** → **record, never run.** Write it into `hypotheses.md`
    with the property that implied it, and name the best two or three in your closing actions.
- Is each class *plausible* here? If its surface is not present, say so — a negative is a real
  result **for that class**, and cheap to record.
- **A negative on one class NEVER clears the endpoint.** Coverage is per (entrypoint × class) in
  `tested.md`. But "not done" is a statement about *coverage*, not a licence to keep going: the
  untested classes are the hunter's next choice, not your next action.
- **Test as every principal you were given** — each role plus unauth. A differential across
  roles or tenants is itself the finding, and it is part of the class you were asked to test,
  not a widening of it.
- **Boundary:** new entrypoints, new targets, and the escalation actions in §7 (privesc, broad
  cross-tenant, chaining, deep bypass) are the hunter's call. Enumerate them into the backlog;
  do not auto-run them.

### 2. Understand the function
- What does this endpoint/parameter/feature actually *do*? What's the intended
  behavior, the inputs, the backend action, the trust boundary it sits on?
- Map the **data flow**: where does user input enter, how is it transformed, where does
  it land (the sink)? What would have to be true for this class to fire?
- Read the client code / JS / API contract. Diff behavior between roles/accounts if
  relevant.
- **The transport is not the class.** An endpoint is only the commonest way to address an
  operation. Before concluding a class doesn't apply, ask *where the input lives on this
  transport*: a REST path segment or query param · a GraphQL field argument, mutation input
  object or `variables` blob · a protobuf message field · a WebSocket frame · a mobile-API body.
  They are all the same source, and the class file's reasoning holds unchanged. Two consequences
  worth stating because they are the ones people miss:
  - **The oracle changes even when the bug doesn't.** gRPC answers **HTTP 200 with a
    `grpc-status` trailer**, so "200" proves nothing; a WebSocket answer may arrive as a later
    unsolicited frame rather than a reply; a GraphQL error can be a 200 with an `errors` array.
    Establish what "it worked" looks like *on this transport* before you read any result.
  - **A second transport is a second door.** The same logical operation exposed over REST *and*
    GraphQL *and* a mobile API *and* a transcoding gateway may not carry the same middleware.
    Where one is hardened, try the others — that is a routing gap, not a new bug class.
  Recovering the contract when it is hidden (introspection off, no descriptor, no schema) is a
  separate job: `playbooks/workflows/investigate-graphql.md` · `investigate-grpc.md` ·
  `investigate-api-surface.md`. Come back to the class file to test.

### 3. Form a hypothesis (specific, testable)
- Not "maybe SQLi." Rather: "the `sort` param is concatenated into an ORDER BY clause;
  if so, a benign expression like `sort=(select 1)` will change ordering without an
  error." Write it to `hypotheses.md` if it isn't already.
- State what you *expect to observe* if the hypothesis is true vs false. Decide the
  discriminator **before** you test.

### 4. Design the minimal safe test
- Smallest, non-destructive probe that distinguishes true from false. Prefer
  differential/boolean/timing/out-of-band signals over anything that mutates data.
- **Match the request format — applies to every class.** Put the probe where the input
  actually lives for *this* endpoint, not just in query params: JSON body (test the value
  *and* the key/structure), GraphQL query & variables, XML nodes/attributes,
  form-urlencoded, multipart fields & filenames, path segments, headers, cookies. Test
  **format-flips** as their own surface — JSON↔XML content-type swap, string↔array/object,
  duplicate/nested params (HPP), extra fields (mass-assignment). Parsers differ, and a
  filter applied to the query string is often *not* applied to a JSON field or XML node —
  that gap is where the bug hides.
- **Never** destructive/DoS (no DROP/DELETE, no mass requests, no resource exhaustion).
- Plan the exact request(s). Note what a true result looks like and what a false
  positive would look like (§6).

### 5. Execute & capture evidence
- Send the actual request (via VPS or an authenticated client). **Observe the real
  response** — never assume or narrate output you didn't see.
- Save the request + response to `raw/` (or the investigation folder). **A vuln FACT
  requires this artifact.** No artifact → HYPOTHESIS only.
- Use the fixed evidence bundle from `target-schema.md`:
  `raw/<run-id>-<class>-<case>/evidence.md`, with `control-request.txt`,
  `control-response.txt`, `test-request.txt`, and `test-response.txt` for HTTP/RPC. Browser, OOB,
  gRPC and WebSocket evidence use the optional channel filenames defined there. Do not leave the
  artifact as an unnamed file in `raw/`; the next session must resolve it from
  `tested.md.artifact_ptr` without reading the transcript.

### 6. Filter false positives
- Work through the class file's "False-positive traps." Did a WAF reflect? Is the error
  generic? Is the "delay" just jitter? Is the reflected value actually executed?
- **If the response looks blocked** (403 / challenge page / generic 500 / dropped
  request), a negative is **not** a verdict yet — go to *WAF / filter escalation* below.
- Re-test to confirm reproducibility. One-off ≠ finding.

### 7. Assess impact & chaining
- What can an attacker actually *do*? Tie impact to FACTs, not imagination.
- **Confirm with MINIMUM proof, then STOP for authorization before escalating.** Prove the
  primitive with the *smallest* safe observation (for IDOR that's reading **one** other-object;
  for a bypass, one benign smuggled value). Then **halt** — **privilege escalation to
  admin/root, broad cross-tenant/other-user access, multi-step chaining, and filter-bypass
  expansion are human-gated, not automatic.** Cross-tenant access is a breach even in testing,
  and over-exploitation violates the minimal-footprint rule (system prompt §3). Instead:
  *reason about* the ceiling the primitive reaches — the max-privilege target, the consumer to
  hunt, the chain — and **surface it for explicit go-ahead**. Under-claiming impact is fixed by
  describing what it *would* reach and asking to demonstrate it, **not** by silently exercising
  it. ("I couldn't see a consumer / it just echoed" → say so and propose where to hunt, don't
  auto-escalate.)
- **A new signal → find its producer.** A path, param, header, error, or secret that surfaces
  mid-test is a lead to a *possibly-undiscovered* endpoint. Enumerate to find which endpoint
  emits or consumes it — **never** attribute a new signal to the nearest endpoint you already
  know. That misattribution is how whole endpoints (and their bugs) get missed.
- **Model the chain; do not silently exercise it.** Copy
  `targets/_template/investigations/chain.template.md` into the current investigation,
  record each primitive and edge as confirmed or hypothetical, and identify the smallest
  proof that would validate the next edge. Any multi-step, cross-account, cross-tenant, or
  privilege-expanding execution still requires the human approval described above.

### 7b. Refute it before you trust it

Before a finding goes anywhere near a report, spend real effort trying to **kill it**, not confirm
it. The lens that found a bug is biased toward it being real; a separate pass whose only job is to
disprove it catches the plausible-but-wrong finding that a confirmation pass never will.

Attack it from three angles, and **only a concrete refutation counts** — a hunch that "maybe it's
not exploitable" is not a refutation, and does not weaken the finding; find the specific blocker or
the finding stands:

- **Reachability** — can a real attacker actually get to this input or state? Or does it need a
  credential, role, header, or prior step they cannot obtain? An unauthenticated repro beats an
  assumption that the attacker is already inside.
- **Trigger** — did the condition *actually* fire, or did you infer it from a suggestive response?
  Re-read the artifact: a reflected value is not execution, a 500 is not injection, a delay is not
  a blind sink. What in the stored request/response *proves* the trigger?
- **Impact** — does it actually reach the ceiling you claimed, or did you imagine the consumer? If
  you asserted a chain or a sensitive sink, point at the FACT that shows the data lands there.

Refute by **reasoning and re-reading the evidence you already have**, not by escalating — the
minimal-footprint rule still holds (system prompt §3). Prefer a different angle than the one that
found it. If the finding survives a genuine attempt to break it, **that survival is evidence** —
record what you tried to refute it with. If it dies, write the concrete reason in
`findings/rejected/` so it is not re-chased. This is FACT / HYPOTHESIS / ASSUMPTION discipline
applied to the whole finding, not just its individual lines.

### 8. Novelty / dedup gate (before proposing a report)
- **Separate fix?** Would fixing this require a code change distinct from anything in
  `tested.md`/findings? If not, it may be a dup of your own work.
- **Already received?** Would the program almost certainly already have this exact
  report? (Common on old, crowded programs / obvious sinks.) If so, find the
  different-perspective angle or drop it.
- **My angle:** what did I understand about this app that the crowd and the scanners
  didn't? If there's no such angle and it's a plain scanner-class bug, it's probably a
  dup.

### 8b. Name the variant before you record

A row without a `variant` claims the whole class on that entrypoint. Before writing it, answer:
**what exactly did I reach?** The input location (`q` vs `filters[name]`), the body format (JSON vs
XML — different parser), the handler version (`/v1` still mounted?), the technique.

For authorization the variant is the **relationship**, not the account. `user-b reads user-a's
object` does not resolve: the reverse direction, cross-tenant, same-tenant-other-member,
former-member, or share-recipient-reads-parent. Each is a row.

**A resolved `not-vuln` needs an `artifact_ptr` and a `method`** or `coverage.py` downgrades it to
`partial` — an unevidenced negative is an assertion, and a later session cannot tell the two apart.

### 9. Record & stop
- Update `tested.md` (with `fix_locus`), `hypotheses.md` (status), and `index.md`.
- **Mark the coverage ledger:** record the (endpoint × class) cell as tested — with the
  result (positive / negative / n-a) and the principal(s) tried. An endpoint is only "cleared"
  when every applicable class from §1 has a cell. This is what stops a single negative from
  masquerading as a clean endpoint, and what lets the next session see what's left.
- If the primitive is confirmed, write it in `findings/draft/`; promote it to
  `findings/confirmed/` in this same workflow only after its artifacts, impact argument, and
  novelty checks are complete. If disproven, note it in `findings/rejected/` so it is not
  re-chased.
- Summarize for the human and **stop.** The finding shape lives in
  `playbooks/system/target-schema.md`; this workspace does not automate submission.

---

## When a test is blocked — WAF / filter escalation

A block (403, generic 500, challenge page, dropped request) is **not** a verdict. In
authorized testing, bypassing a WAF/filter to prove a *real* vulnerability is legitimate.
Default behavior is **signal-gated auto**: escalate automatically while the signal is
strong, and stop for the human before deep, costly campaigns. Bypass is *reasoned*, never
a payload spray (that's scanner behavior → dupes + noise).

**Tier 0 — Blocked, or just not vulnerable? (always, automatic)**
Distinguish a WAF/filter from the app correctly rejecting input — the difference drives
both false negatives *and* false positives:
- Compare a benign-but-suspicious token vs a truly malicious one, and an in-context valid
  request vs the payload. A generic 403/challenge to anything "weird" → WAF; a clean
  app-level error tied to your exact input → real handling or the sink itself.
- Fingerprint whether a WAF/CDN fronts the host (from `technologies.md`; block-page,
  headers, `Server`, timing). Record the conclusion.

**Tier 1 — Bounded reasoned bypass (automatic, only when the sink looks real)**
If Tier 0 says "WAF is blocking AND the underlying sink is plausible," do a *bounded*
pass — adaptive tooling applied to a filter (`playbooks/system/adaptive-tooling.md`):
- Isolate **exactly what's filtered**: the keyword (`SELECT`, `UNION`), a character
  (`'`, `<`, space), the pattern, or a length. Probe one variable at a time.
- Craft a few targeted evasions of *that* filter by reasoning about it (encoding,
  case/comment splitting, alternate syntax, param pollution, content-type change) — not a
  wordlist. Stay non-destructive and rate-aware (bypasses are noisier).
- If the sink likelihood is LOW, don't burn effort — log the negative and move on.

**Tier 2 — Deep bypass campaign (human-ordered)**
If bounded attempts fail but the signal a real vuln exists stays strong, **STOP and
surface**: what's blocked, the WAF fingerprint, the bypasses tried, why the sink still
looks real, and the ask (go deeper / switch to Burp / advanced obfuscation?). Deep
campaigns are costly; the human decides the investment (orchestrator model, system
prompt §1).

**Test level — set per task, not global.** The human names the level when invoking each
test: *basics-only* (Tier 0, then report and move on), *signal-gated* (Tier 0–1 auto, ask
at Tier 2), or *pursue-bypasses* (run the ladder, surface only when stuck). There is **no
persistent global setting** — it's decided per test task; if the human doesn't state one,
use signal-gated. Record the level used in the `tested.md` `method` column.

**Log it.** Record the WAF fingerprint + what was filtered + bypasses tried in
`tested.md`, so it isn't re-derived and a working bypass becomes part of the evidence
trail.

---

## Per-class file structure (the thin files follow this)

Each `playbooks/vulns/<class>.md` contains only:

- **Where it hides** — the sinks/behaviors/params/tech signals that make this class
  plausible; how to spot the surface in recon data.
- **How to analyze the function** — the class-specific questions to answer about the
  data flow before testing.
- **Minimal safe validation** — how to prove *this* class safely (the discriminating,
  non-destructive signal — boolean/timing/OOB/differential), and what NOT to do.
- **False-positive traps** — the specific ways this class fools you.
- **Impact & chaining** — what it escalates to; what it commonly chains with.
- **Dedup / novelty angle** — what makes a *non-duplicate* instance of this class; what
  the crowd already reported to death.
- **Worked example** — one short, concrete scenario run through the loop (recognize →
  analyze → hypothesis → minimal safe test → dedup). It demonstrates the *reasoning*, and
  is **not** a payload to copy — the scenario and the thinking are the point, not the
  string. Keep it ~6–10 lines.

Payload *examples* are allowed as illustrations of a technique — but the file must
teach recognition and reasoning, never be a payload dictionary to spray.
