# Prototype Pollution — the method

> **This is a test of your ability to find prototype pollution** in the parser/merge/param flow the
> human names — the chain that reaches XSS, RCE or an authz bypass. Model the source→sink twice
> over: where user-controlled *keys* reach an object write, and where a **gadget** later reads that
> property back into something dangerous. You inject `__proto__` / `constructor.prototype` keys so
> that *every* object inherits an attacker-controlled property — but **pollution without a gadget is
> noise**. The value is a concrete source→gadget chain traced in this app, not a generic
> `?__proto__[x]=y`. Work this with `playbooks/vulns/_master-vuln-hunting.md`.

---

## 1. Model both halves before you touch anything

**SOURCE** — where user-controlled keys enter. *Client-side:* the URL query or hash parsed into an
object (`?__proto__[x]=y`), jQuery `$.extend(true, ...)`, `deparam`/`querystring` helpers,
`JSON.parse` of user data merged into config, `postMessage` or `localStorage` data merged in.
*Server-side:* a JSON body recursively merged (`Object.assign` deep-merge, `lodash.merge`, `_.set`,
`_.defaultsDeep`, `mixin`, config loaders), query parsers (`qs` with nesting), and multipart/form
parsers that build nested objects.

**FEED** — the parser and the merge itself. Which keys does the parser admit — `__proto__`,
`constructor.prototype`, both? Does a guard strip `__proto__` but miss `constructor`? Is
`Object.create(null)` in use (immune)? Vulnerable merge/set libraries in `technologies.md` (old
`lodash`, `merge`, `hoek`, `set-value`) are a signal, not the finding.

**SINK (half one)** — the recursive merge, the `[a][b]=c` assignment, or the
`Object.setPrototypeOf`-adjacent path where your key lands on `Object.prototype`.

**CONTEXT — the pollution sink and the downstream gadget that reads it.** Both halves are required,
and they are different pieces of code:

| half | what you must name | if you can't |
|---|---|---|
| **pollution sink** | the merge / assignment that writes an attacker-named key onto the prototype | there is no pollution — a guard or a null-proto object stopped you |
| **gadget** | later code that reads a property **undefined by default** and does something dangerous with it: renders HTML, sets a script or `img` `src`, spawns a process, makes an auth or feature-flag decision | there is no finding, only a curiosity |

Concretely: *client* — trace the URL or JSON source into the merge, then hunt gadgets that read config
props into DOM or script sinks (→ XSS). *Server* — trace the JSON body into the merge, then hunt
gadgets in the template engine, the command spawn, or the auth check. Typical gadget shapes:
`options.<x> || default`, template config, an HTML or script tag built from a config field,
`child_process` options, template-engine internals.

**ROOT CAUSE** — one of: the merge recurses without excluding `__proto__` · the guard excludes
`__proto__` but admits `constructor.prototype` · the parser builds nested objects from user-named
keys · a downstream read treats an inherited property as its own configuration · a security decision
(a role, an `isAdmin`, a feature flag) is read from a property that defaults to undefined. **That
answer is your `fix_locus`** — log it for **both** the merge/parse sink *and* the gadget when they
are separately fixable, because they can count as distinct findings.

## 2. Derive the candidates — hunt sources and gadgets separately

1. **Enumerate the merges and the parsers.** Deep-merge, `set`-style and config-loader calls in the
   bundle and the server code are candidate pollution sinks; anywhere query, hash, JSON,
   `postMessage`, `localStorage` or multipart input becomes a nested object, the key names are
   attacker-controlled.
2. **Enumerate the gadgets independently** — reads of properties that are normally undefined,
   feeding HTML, a `src`, a spawn, or a decision. Do this as its own pass; a gadget hunt driven by
   "what did I just pollute" finds nothing.
3. **Cross the two lists.** The finding is a pair, and either half may be in a dependency while the
   other is in the app's own code. **Check for immunity first** — `Object.create(null)`,
   `Object.freeze(Object.prototype)`, a patched library — before spending effort on a no-op merge.

## 3. Determine the context — detect the pollution harmlessly first

**Tooling:** client-side pollution and its gadget need a real JS engine — validate via **Chrome
MCP** (local); server-side pollution is HTTP-level (curl/VPS). See `_master-vuln-hunting.md` →
Tooling.

Send a benign, **uniquely-named** property via `__proto__` and check whether it leaked onto a
*fresh* object:

- **Client, in console:** after triggering the source, `({}).hacked_marker_uniq` returns your value.
- **Server, blind:** pollute a property that a *known reflective* gadget echoes — for example a
  JSON response field that defaults to your polluted value — or watch for an out-of-band or
  behavioural change, a harmless status or header flip, **never a destructive one**.
- Try `constructor.prototype` as well as `__proto__` where a guard exists — two different probes.

## 4. Test → Confirm → Validate

**TEST — did the prototype actually change?** The §3 marker probe. **Outcome: a hypothesis** — and
only about half one.

**CONFIRM — the default oracle is a *fresh, unrelated* object inheriting your uniquely-named
marker.** Not the response code, and not the object you touched. Only once that holds do you show a
**gadget consumes it**, with a harmless effect: for a client XSS gadget, an
`alert(document.domain)`-class marker (see `xss.md`); for a server gadget, a benign, observable,
non-destructive side effect. **The oracle inverts or lies in these ways:**

- Pollution "succeeds" but there is **no gadget** — you set `({}).x` and nothing reads it. Not a
  finding on its own.
- The property was set on the **instance**, not the prototype. Verify a *fresh, unrelated* object
  inherited it, not just the one you touched — that is what the marker probe is for.
- A guard silently drops `__proto__`: the key looks accepted but the prototype is unchanged. Confirm
  the pollution; never infer it from a `200`. Likewise the framework or library may already be
  patched, or `Object.freeze(Object.prototype)` / null-proto objects in place — your write no-ops.
- A behavioural change that is actually unrelated (caching, error handling), mistaken for a gadget.

**VALIDATE — the minimum that proves the chain.** Marker inherited by a fresh object, plus the
gadget rendering or acting on one benign value. Escalate the *minimum* needed to show severity —
never spawn a real command or write files to "prove" RCE.

## 5. Safety — pollution is process-global on the server, page-global in the browser

- **Never pollute a property that could crash the app for all users, DoS the process, or corrupt
  shared state at scale.** It is not scoped to your session. Keep it scoped, use a **unique marker
  key** you can identify and reason about, and clean up. Prefer a name nothing in the app is likely
  to read, until you deliberately choose the gadget's property.
- **Store the artifact**: the polluting request or URL, the observed inherited-property evidence on
  a fresh object, and the gadget's benign effect. **No artifact → HYPOTHESIS, not FACT.**
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): the polluting URL or request, and —
  for a client-side chain — the console check that proves prototype (not instance) inheritance.

## 6. Log it

Every probe goes to `targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with the
`fix_locus` from §1 — potentially **two rows**, one for the merge/parse sink and one for the gadget,
when they are separately fixable. Log negatives with the oracle used, and record whether you tested
`__proto__` only or `constructor.prototype` as well, since a guard on one is common.

**Novelty.** Generic "`?__proto__[x]=y` pollutes an object" reports against known-vulnerable
libraries are often dups or already patched. Novelty is a **concrete source→gadget chain traced in
*this* app** (pollution reaching a real XSS, RCE or authz sink), a server-side gadget in the target's
own code, or a parser that admits `constructor.prototype` where a `__proto__` guard exists. Impact:
client-side, pollution → **DOM XSS** via a config or HTML gadget → account actions, plus bypass of
client-side auth and feature flags; server-side, → **RCE** via template-engine or `child_process`
gadgets, an authorization bypass (a polluted `role`/`isAdmin` default), or DoS. Chains: the classic
high-value pattern is *pollution source + separate gadget*, often two distinct fix loci; pair with
`dom-clobbering.md` (both target undeclared config reads) and `xss.md` (pollution is a prime XSS
delivery on script-restricted pages).

**Worked example.** The SPA parses the URL query with an old `$.extend(true, {}, defaults, params)`
deep-merge (jQuery in `technologies.md`), and a later widget builder does
`el.innerHTML = opts.template || ''` where `opts.template` is normally undefined. *Model:* both
halves are present — the pollution sink is `?__proto__[template]=...` reaching the recursive
`$.extend`; the gadget is the `opts.template` read into `innerHTML`. *Context:* detect pollution
*before* weaponizing, because a benign uniquely-named key discriminates a real prototype write from
an instance-only set — I check a **fresh** object. *Hypothesis:* polluting
`Object.prototype.template` makes every options object inherit it, and the widget renders it into
`innerHTML` → DOM XSS on a script-restricted page. *Test/confirm:* in Chrome MCP, load
`?__proto__[hacked_uniq]=1` and confirm `({}).hacked_uniq === '1'` in the console — a fresh object
inherited it. *Only then* set the `template` key to an `onerror` marker firing
`alert(document.domain)` and confirm the widget renders it, same-origin. Unique key, page-global,
clean up after; save the polluting URL and the inherited-property evidence. *Novelty:* a concrete
source→gadget chain in *this* app rather than a "the library is vulnerable" report — separable loci:
`fix_locus = $.extend query merge` and `fix_locus = opts.template → innerHTML gadget`.
