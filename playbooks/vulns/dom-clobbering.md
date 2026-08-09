# DOM Clobbering — the method

> **This is a test of your ability to clobber a JS variable → gadget → XSS** via the
> HTML-injection sink the human names — the chain where script is blocked but named markup still
> hijacks execution. Model the flow to the **JS gadget** that reads an undeclared
> `document`/`window`/DOM property, understand how the sanitizer lets `id`/`name` markup through
> while stripping script, then find where your clobbered value redirects that gadget into a sink.
> **Find the gadget first — the injection is worthless without it.** The value is a reasoned,
> app-specific gadget, not a sprayed named element. Work this with
> `playbooks/vulns/_master-vuln-hunting.md`.

## 1. Model the flow before you touch anything

**SOURCE** — a sink that lets you inject **HTML but not script**: a sanitizer (DOMPurify, allowlist
filters) that strips `<script>`/handlers but permits `<a>`, `<form>`, `<img>`, `<iframe>`,
`<object>` carrying `id`/`name`. Comment fields, markdown renderers, rich-text, "safe HTML" profile
bios, ad/tag containers.

**FEED** — the sanitizer, then the HTML parser. Whatever survives sanitization is parsed into named
DOM, and named markup populates `window`/`document` properties before the consuming script runs.

**SINK — the gadget, and it lives in the JS, not at the injection point.** Code that reads a
property off `document`, `window`, or a DOM collection *without* declaring it: `document.<x>`,
`window.<x>`, `<x> || defaultUrl`, `if (window.config)`, feature-flag/analytics/config objects
assembled from globals, a `.src`/`.href` built from an undeclared variable.

**CONTEXT — which property path the gadget reads, and what type it expects.** This decides the
markup you write:

| gadget reads | named markup that clobbers it | what the gadget then sees |
|---|---|---|
| a single global (`window.x` / `document.x`) | `<a id=x>` | an element reference |
| the same name twice | two elements sharing `name`/`id` | an `HTMLCollection` |
| a nested path (`x.y`) | `<form id=x><input id=y>` | the chained property |
| a value coerced to string | `<a id=x href="...">` | `toString()` yields the URL |

Determine the *type* the gadget expects (string vs object vs truthy) and whether coercion
(`toString`, template literal, `+`) turns your element into that value. The `href` string-coercion
path is the classic one.

**ROOT CAUSE** — the specific undeclared read: a global the code assumes is a string/object and
never declares, a truthy guard with no type check, a config path assembled from globals. **That
undeclared read is your `fix_locus`** — two gadgets reading two different globals are two findings.

## 2. Derive the candidates — find the gadget, then the injection

1. **A DOM-clobber only matters if a gadget consumes the clobbered value.** Grep the app JS for
   undeclared reads of `document.*`/`window.*` and named-form/collection access. For each ask: if
   this property were an attacker-controlled DOM node instead of the expected string/object, what
   breaks?
2. **Read the tech signals** — legacy JS reading globals, an HTML sanitizer in the pipeline that
   keeps `id`/`name`, `document.getElementById`-style lookups feeding a security decision.
3. **Only then go find the injection point** whose sanitizer profile keeps the attribute you need
   on the element you need. Candidates come from reading the bundle, never from a gadget wordlist.

## 3. Determine the context — before you weaponize

- **Tooling:** the clobbering and the gadget pickup only resolve in a real DOM — validate via
  **Chrome MCP** (local), not curl. See `_master-vuln-hunting.md` → Tooling.
- Show the injection point renders a **named** element you control — that `id`/`name` survives the
  sanitizer at all. One save, one read.
- Check the target global is genuinely undeclared: read it in the console on a clean page. A
  declared `var`/`let`/`const` shadows DOM named properties.
- Check your node still exists at the moment the gadget runs — framework re-rendering is a timing
  question you answer before, not after, a failed test.

## 4. Test → Confirm → Validate

**TEST — does named markup survive the sanitizer?** Inject a plain `<a id=x>` at the sink and see
the element come back with its `id` intact. **Outcome: a hypothesis.**

**CONFIRM — did the gadget pick up *your* node?** The default oracle is **the gadget's consumer
carrying a value only your markup could have supplied**: read `window.<x>` / `<x>.<y>.toString()`
in the console and observe the `.src`, `.href` or config value now pointing at your benign marker
instead of its default. Where that oracle inverts or lies:

- Injection renders but **no gadget consumes it** — an inert named element is not a finding. The
  gadget is mandatory.
- The variable is actually declared (`var`/`let`/`const`) or set before your DOM parses —
  clobbering fails silently.
- Modern code using `window.x` explicitly with strict typing, or reading via `getElementById` into
  a checked value — coercion never happens.
- Browser differences: some clobbering vectors behave differently across engines; verify in the
  target's supported browser.
- Framework re-rendering wipes your node before the gadget runs (timing).

**VALIDATE — the least that proves impact.** Cleanest PoC: clobber a value that flows into a
*visible, benign* effect — a link target, an image src pointing at your own harmless asset — so the
change is observable but inert. If the gadget ultimately reaches a script sink, prove it with
`alert(document.domain)`-class markers only (see `xss.md`), then stop.

**Impact & chaining.** Rarely standalone — DOM clobbering is a **primitive that enables another
bug**: redirect/open-redirect via a clobbered URL, CSP bypass (clobber a config controlling a
script src or a nonce lookup), disabling a security check (clobber a truthy guard), or turning
HTML-injection into XSS by feeding a clobbered value into an existing script sink. Chains:
sanitizer-allowed HTML injection + clobbering gadget → XSS despite "no script"; clobber a config
object read by a later `eval`/`src` sink; combine with prototype pollution where both target the
same undeclared config path.

## 5. Safety, artifact, and PoC handoff

- **Never** weaponize into real script execution against other users, and never chain to a live
  account takeover to "prove" it — demonstrate the clobber + gadget pickup and stop.
- **Store the artifact**: the injected HTML, the JS gadget snippet, and the observed clobbered
  value. **No artifact → HYPOTHESIS, not FACT.** Redact what the proof doesn't need.
- **Ship a runnable PoC, never prose** (`playbooks/system/mcp-tooling.md`): the saved markup plus
  the Chrome MCP steps showing the gadget's consumer change, reproducible in one action from a
  clean session. Respect the program's rate limit.

## 6. Log it

`targets/<t>/tested.md` as `(entrypoint × class × principal × variant)`, carrying the `fix_locus` from §1 —
the specific undeclared read, because that is what must be fixed. Log negatives *with the oracle
used* (did a gadget exist? did the node survive? did coercion happen?). **Novelty:** this class is
inherently novel-leaning — it requires reading the target's JS to find a bespoke gadget, which
scanners don't do. Dups happen only on well-known library gadgets; novelty = **an app-specific
undeclared-global gadget** you found by reading the code, especially one that upgrades a "safe
HTML" feature into XSS/CSP-bypass.

## 7. Worked example

*Model:* the profile "bio" renders through DOMPurify (strips `<script>`/handlers but keeps
`<a>`/`<img>` with `id`/`name`) — that's the SOURCE. Reading the app JS, an analytics loader does
`var s = window.cfg || {}; script.src = s.endpoint || '/a.js'`; `cfg` is never declared — that
undeclared `window.cfg` read is the SINK and the `fix_locus`. CONTEXT: a nested path coerced to a
string into a `.src`.
*Derive:* injection point ≠ gadget; the gadget came from grepping the bundle for undeclared global
reads, and the bio field was then chosen because its sanitizer profile keeps `id`/`name`.
*Context probe:* in Chrome MCP, confirm `window.cfg` is undefined on a clean page and that a plain
`<a id=cfg>` survives the sanitizer.
*Test → confirm:* the two-node chain `<a id=cfg>` plus `<a id=cfg name=endpoint href=...>` clobbers
`window.cfg` and `cfg.endpoint`, whose `toString()` yields the href. Save the bio, then read
`window.cfg` / `cfg.endpoint.toString()` in the console and confirm the loader's `script.src` now
points at a benign same-origin asset I chose — observable but inert; stop before pointing it at
live script.
*PoC/artifact:* injected HTML + gadget snippet + observed clobbered value.
*Dedup:* not a known-library gadget — bespoke undeclared `window.cfg`;
`fix_locus = undeclared window.cfg read in analytics loader`.
