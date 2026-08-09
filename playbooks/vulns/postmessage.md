# postMessage Vulnerabilities — the method

> **This is a test of your ability to find a postMessage flaw** in the frame, widget or relay the
> human names — the chain that reaches a cross-origin data leak or an action in the victim's
> context. Model the source→sink in the JS: how the app takes and transforms `event.data`, or what
> it hands out, and where its origin/trust assumption breaks. Two directions, and you must reason
> about both: an insecure **receiver** (`onmessage` that trusts data without checking
> `event.origin`) and an insecure **sender** (`postMessage(secret, "*")` leaking data
> cross-origin). The value is a traced handler reaching a real sink, not a message sprayed at a
> frame. Work this with `playbooks/vulns/_master-vuln-hunting.md`.

---

## 1. Model the message channel before you touch anything

**SOURCE** — for a receiver, `event.data` posted from any window that can reach the frame. For a
sender, the data the app itself posts outward, and the `targetOrigin` it posts it with.

**FEED** — the handler body. Read the whole of it: the origin check (or its absence), any
`switch`/type dispatch that routes on a field of `event.data`, and any transformation applied on
the way to the sink. A dispatch table means some branches are reachable and interesting and others
aren't.

**SINK** — for a receiver, what `event.data` finally reaches: `innerHTML`, `eval`, `location`, a
function dispatch table, auth or session state, or a reflection into the page. For a sender, the
sink is *any origin that can host or embed the frame* — it reads whatever was posted to `"*"`.

**CONTEXT — the origin/target relationship, and what the listener does with the data.** These two
questions together decide whether there is a bug:

1. **Can you get into the relationship at all?** Map who embeds whom: can *you* open or iframe the
   vulnerable frame (so you can send it messages), or can *you* embed it and register a listener
   (so you can receive its broadcasts)? No reachable relationship, no bug.
2. **Does the receiver check `event.origin` against a strict allowlist *before* acting?** The weak
   checks to flag: **no check at all**; `indexOf`/`includes`/`startsWith` on the origin string
   (`https://trusted.com.evil.com`, `evil-trusted.com` both pass); a regex without anchors;
   checking `event.source` only; comparing against `document.referrer`.
3. **What does the handler do with the data, and is that dangerous?** A missing or weak origin
   check *plus* a dangerous sink is the bug. Either alone is not.
4. **For a sender:** is `targetOrigin` `"*"` or otherwise overly broad, and is the posted data
   actually sensitive — tokens, user info, session material?

**ROOT CAUSE** — one of: no origin check in the listener · an origin check done by substring,
prefix or unanchored regex · trust placed in `event.source` or `document.referrer` instead of
`event.origin` · a check that runs but not before the branch that acts · `targetOrigin` of `"*"`
on a message carrying auth material · a broad `targetOrigin` that admits an origin the app doesn't
control. **That answer is your `fix_locus`** — the specific listener or `postMessage` call site,
so distinct handlers count separately.

## 2. Derive the candidates — read the JS for both directions

1. **Receivers**: find every `window.addEventListener("message", handler)` and
   `window.onmessage` in the bundle, then read what each handler *does* with `event.data` — routes
   it to a DOM or script sink, uses it to navigate, updates auth or session state, or reflects it
   into the page.
2. **Senders**: find every `targetWindow.postMessage(data, "*")` and every too-broad
   `targetOrigin`, especially where `data` contains tokens, user info or session material.
3. **Follow the product shapes that must use this channel**: iframes, popups, OAuth/SSO relays,
   payment and embed widgets, chat and SDK bridges, analytics. **Tech signals** from recon:
   embedded third-party iframes, OAuth flows that return codes or tokens over `postMessage`,
   cross-frame SDKs, widget/embed products, single-sign-on relays.
4. **Note the dispatch surface.** Where a handler switches on a message type, enumerate the
   branches — the sensitive one may be unreachable from the app's own UI but reachable from you.

## 3. Determine the context — locate yourself before weaponizing

**Tooling:** this class needs a real browser to observe the listener firing — validate via
**Chrome MCP** (local), not curl. See `_master-vuln-hunting.md` → Tooling.

Cheap, non-destructive probes:

- **Confirm the frame is embeddable or openable from your origin.** If it isn't, the channel isn't
  reachable and everything below is moot.
- **Send a benign, well-formed message from your own foreign origin** and watch whether the handler
  runs at all — before caring what it does.
- **For a sender, register a listener on your embedding page** and observe what arrives unprompted.
- **Establish which origin you are testing from.** A same-origin "success" proves nothing (§4).

## 4. Test → Confirm → Validate

**TEST — from your own attacker page, exercise the relationship.** *Receiver:* open or iframe the
target and `postMessage` a **benign** payload that would only succeed if the origin isn't
validated. *Sender:* host a page that embeds or opens the target and registers an `onmessage`
listener. **Outcome: a hypothesis.**

**CONFIRM — the default oracle is "a message from my unrelated origin was accepted and acted
on".** Show the handler *acted*: a harmless DOM change, a `console`/marker sink, or
`alert(document.domain)` if it reaches a script sink (see `xss.md`). For a sender leak, the oracle
is your own listener *receiving* the sensitive `data` because `targetOrigin` was `"*"` — capture
the received object. **The oracle inverts or lies in these ways:**

- The handler reads `event.data` but the origin **is** properly checked earlier — no bug.
- Your test "worked" only because you loaded it **same-origin**. Re-test from a genuinely foreign
  origin; this is the single most common false positive in the class.
- The data flows to a harmless sink (it updates a UI counter) — no security impact.
- The listener is **dead code**, or belongs to a third-party script that isn't actually wired up.
- `targetOrigin: "*"` but the payload carries nothing sensitive — informational at best.
- A browser extension or devtools noise posting messages, mistaken for app behaviour.

**VALIDATE — the smallest page that proves the channel is open.** One accepted message, or one
captured leak. Redact real secret values in the capture: record enough to prove readability, not
the full token.

## 5. Safety, artifact, and PoC handoff

- **Never replay a captured real token** to take over an account to "prove" it — the capture is the
  proof. **Don't spray messages at production users**: the PoC is a page you load yourself, not
  something you get anyone else to open.
- **Store the artifact**: the attacker PoC HTML plus the observed accepted or leaked message —
  the event object, redacted. **No artifact → HYPOTHESIS, not FACT.**
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): the smallest self-contained
  attacker page, hosted on a genuinely foreign origin, plus the captured event. State the origin
  you served it from — a triager who reproduces it same-origin will reproduce nothing.

## 6. Log it

Every probe goes to `targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with the
`fix_locus` from §1 — the specific listener or `postMessage` call site, and which direction
(receiver or sender) you tested. Log negatives with the oracle used and **the origin you tested
from**, because a same-origin negative is not a negative.

**Novelty.** This class requires reading the app's own JS message handlers, and scanners rarely
model it, so well-analyzed instances are frequently novel. Dups cluster on well-known SDK and
widget advisories. Novelty is an **app-specific handler** with a weak or absent origin check
reaching a real sink, or a **sender leaking auth material to `"*"`** in an SSO or embed flow.
Impact: a receiver flaw reaches **DOM XSS** (data into a script sink), open redirect or navigation
control, auth-state manipulation, or CSRF-like forced actions inside the frame; a sender leak
reaches theft of OAuth codes and tokens, session identifiers, and PII readable by any embedding
origin → account takeover. Chains: `postMessage` is a prime **XSS source** (see `xss.md`);
OAuth-over-postMessage token leak → ATO; combine with clickjacking or framing to force the victim
to open your relay; a sender leak plus a receiver on another frame completes a cross-origin exfil.

**Worked example.** The embeddable widget's JS registers `window.addEventListener("message", h)`
where `h` does `if (e.origin.indexOf("trusted.com") > -1) location = e.data.url`; recon flagged
this as an embed/SDK bridge (`technologies.md`: cross-frame widget). *Model:* the origin check is
`indexOf` — a substring — so `https://trusted.com.evil.io` passes; and `e.data.url` flows straight
into `location`, a navigation sink. Both halves present. *Context:* the discriminating probe is a
message from a *genuinely foreign* origin whose host merely **contains** `trusted.com`, because
that isolates the substring flaw from a real allowlist. *Hypothesis:* a page at such an origin can
`postMessage` a URL the handler navigates to. *Test/confirm:* in Chrome MCP, host an attacker page
on that origin, iframe the target, post `{url: <benign same-origin marker path>}`, and confirm the
frame navigates — or, if it reaches a script sink, that `alert(document.domain)` fires. The proof
is "a message from my unrelated origin was accepted and acted on"; save the PoC HTML and the
accepted event. *Novelty:* an app-specific handler with a substring origin check reaching a
navigation sink, not a known SDK advisory — `fix_locus = message listener h() origin check`.
