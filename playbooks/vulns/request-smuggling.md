# HTTP Request Smuggling / Desync — the method

> **This is a test of your ability to find HTTP request smuggling / desync** in the request path the
> human names — the chain that reaches request hijack or cache poisoning. Model the **chain of HTTP
> processors** and find the pair that disagrees on message length (`Content-Length` vs
> `Transfer-Encoding`, or obfuscated headers): how each hop parses the body, and where their
> assumptions diverge. The value is a mapped, named parser pair — not a payload fired at an edge.
> **This is the most dangerous class to test on production** — a wrong probe poisons *other users'*
> connections. Read §5 first and mean it: detect via timing, confirm with the smallest self-contained
> differential, never with a payload that captures or alters someone else's request. Work this with
> `playbooks/vulns/_master-vuln-hunting.md`.

---

## 1. Model the processor chain before you touch anything

**SOURCE** — the headers and framing you control on a single request: `Content-Length`,
`Transfer-Encoding`, their duplicates, and the whitespace, casing and line-folding around them.

**FEED** — the chain of hops. Map it: how many processors, what software at each, who terminates TLS
and HTTP/2, and **where an H2→H1 downgrade happens**. Typical shapes: a CDN or front proxy plus an
origin, a load balancer plus an app server, or an HTTP/2 front downgrading to HTTP/1.1 for the back.

**SINK** — the backend connection itself. The effect lands not on a parameter but on the *byte
stream* of a connection, which is why the blast radius is other people.

**CONTEXT — which parser disagrees with which about message length.** The vulnerability is a property
of the **pair**, never of one server. Establish three things:

1. **Which processor is authoritative for length at each hop**, and could an obfuscated `TE` or `CL`
   make two adjacent hops differ? The named variants: **CL.TE, TE.CL, TE.TE, CL.CL, H2.CL, H2.TE**.
2. **What obfuscations survive hop 1 and are still honoured at hop 2** — header-name or whitespace
   obfuscation the front normalizes but the back doesn't, two `Content-Length` values, a
   `Transfer-Encoding : chunked` with stray whitespace, a duplicated `TE`, `\n` folding.
3. **Is the connection to the backend reused across clients** (shared keep-alive)? That reuse is
   exactly what makes a real attack harm others — **and why your test must not create a dangling
   prefix.** If keep-alive is disabled end-to-end, cross-request smuggling isn't possible even where
   lengths disagree.

**Tech signals from `technologies.md`**: layered proxies, mismatched server software (a modern edge
in front of a legacy origin), HTTP/2 frontends, and `Via`/`Server` headers revealing two stacks.

**ROOT CAUSE** — one of: the front normalizes an obfuscation the back still honours (or the reverse)
· the pair disagrees on which of `CL`/`TE` wins · a duplicated header is resolved differently at each
hop · an H2 front rebuilds an H1 request whose framing no longer matches what it validated · a legacy
origin honours framing a modern edge assumes is impossible. **That answer is your `fix_locus`** — the
specific proxy-pair and normalization gap, so distinct chains count separately.

## 2. Derive the candidates — map hops, not URLs

1. **Enumerate the request paths that traverse two or more HTTP processors.** Anything with a single
   processor cannot desync; the candidate set is pairs, so start by counting hops. **Confirm
   keep-alive behaviour per path** before spending effort — no backend connection reuse, dead end.
2. **Read the headers that betray the chain** — `Via`, `Server`, any hop-injected header — to
   identify where two distinct stacks meet.
3. **Prioritise the seams the crowd skipped**: an **H2→H1 downgrade** (H2.CL/H2.TE), obfuscations
   specific to a **particular backend's parser**, a **second internal proxy** nobody mapped, and
   newly acquired origins behind an old load balancer.

## 3. Determine the context — cheap, self-affecting probes only

- **Establish the control.** A well-formed request on the same path and connection, timed — every
  later measurement is a comparison against this.
- **Determine whether the front normalizes** your obfuscation at all: does the malformed variant come
  back rejected, cleaned, or passed through? A rejection tells you the front parses it; a clean
  pass-through tells you it may reach the back untouched.
- **Determine whether H2 is end-to-end or downgraded**, since the classic CL/TE tricks don't apply to
  an end-to-end H2 path. **And whether the backend connection is reused** — a safety input as much as
  a technical one.

## 4. Test → Confirm → Validate

**TEST — detect with self-targeting timing only, and know what "self-targeting" does not promise.**
Use the **timing differential technique** (Burp/`Smuggler`-style): a probe crafted so that *if* the
backend disagrees, **your own** request stalls waiting for bytes that never come.

> **This is the safest detection available. It is not risk-free, and PortSwigger says so.** A
> desynchronising probe leaves bytes in the front-end↔back-end connection. That connection is
> **pooled and shared**, so a residual prefix can attach itself to the *next* request through it —
> which may be a real user's. CL.TE probes are the usual offender. Mitigate, do not assume:
> keep the poisoned portion empty or inert, never send a probe with a payload you would mind
> prepending to a stranger's request, prefer low-traffic windows, stop after the differential is
> established, and if the program forbids techniques that can affect other users, **this class is
> out of bounds for that program** — say so rather than proceeding carefully.

**Outcome: a hypothesis.**

**CONFIRM — the default oracle is a consistent, repeatable latency gap between the malformed variant
and a well-formed control, measured in paired samples on the same path.** A delay on the malformed
variant and none on the control is your primary, non-destructive signal. Require a clean statistical
gap across several paired samples — **never one slow response**. **The oracle inverts or lies:**

- **Network jitter, cold caches or GC pauses** mimic a delay. Require repeated paired measurements
  with a control on the same connection.
- A front proxy that **normalizes** the obfuscation before the backend ever sees it — many do. That
  is no desync, just a rejected or cleaned request. Or **timeouts from rate-limiting or a WAF**,
  not from a stalled backend.
- **Keep-alive disabled end-to-end** (every request a fresh connection) — no cross-request smuggling
  is possible even if lengths disagree, so a timing artefact means something else. Likewise
  **HTTP/2 end-to-end with no H1 downgrade** — the classic CL/TE tricks don't apply.

**VALIDATE — stop at the timing evidence unless the program says otherwise.** If — and **only if** —
the program explicitly permits active desync confirmation, the safe confirmation is a
**self-contained differential you close yourself**: two requests on one connection where the
*second, attacker-authored* request is completed by the smuggled prefix, observed entirely within your
own session. **You send the trailing bytes yourself**, so no other client's request is ever appended
to your prefix.

## 5. Safety — a wrong probe poisons a shared front-end for real traffic

**Read this before sending anything. The blast radius of this class is other people's requests.**

- **Never leave a dangling partial request on a shared connection.** That is precisely the mechanism
  that captures a stranger's traffic.
- **Never use the "capture another user's request" PoC on production** — not as a demo, not briefly.
- **Never socket-flood or hold many sockets open** — that is a DoS. **Do not run desync probes
  against pooled backends during peak traffic**; budget and announce first — this is a loud phase.
- **Demonstrate with the least intrusive PoC that proves the desync, and stop.** Because the impact
  lands on other users, "how far can I go" is exactly the wrong question here.
- **Store the artifact**: the paired timing samples — malformed versus control, with latencies — and
  the path and hop map they were taken on. **No artifact → HYPOTHESIS, not FACT.**
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): the malformed probe **with its
  well-formed control**, as Burp Repeater requests or a copy-pasteable equivalent, plus the measured
  latencies — a triager reproduces the differential without escalating it.

## 6. Log it

Every probe goes to `targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with the
`fix_locus` from §1 — the **proxy pair and normalization gap**, not the URL, since one pair usually
spans many paths. Log negatives with the oracle used and the variants tried (CL.TE, TE.CL, TE.TE,
CL.CL, H2.CL, H2.TE), and record the §3 keep-alive and H2-downgrade findings even when the answer is
"no desync" — that context is what the next session needs most.

**Novelty.** The obvious CL.TE/TE.CL on a mainstream CDN edge is heavily hunted and usually patched
at the edge. Novelty lives in **H2→H1 downgrade** desync (H2.CL/H2.TE), obfuscations specific to a
**particular backend's parser**, chains through a **second internal proxy** the crowd never mapped,
and newly acquired origins behind an old load balancer. Impact: the highest-severity web class —
mass credential and session theft (victims' requests routed into attacker-visible responses),
request-routing and authz bypass, cache poisoning at scale, forced browser interaction. Chains:
desync → cache poisoning (`cache-poisoning.md`) for persistence; desync plus an internal-only header
the front injects → auth bypass; desync → a stored front-end redirect or XSS.

**Worked example.** `technologies.md` shows an HTTP/2 edge (`Server` reveals a modern CDN) in front
of a legacy origin (`Via` exposes a second, older stack) — a classic H2→H1 downgrade pair where front
and back can disagree on body length. *Model:* two hops, the downgrade at the edge, and a backend
whose framing rules predate the front's assumptions. *Context/safety:* I will **not** send a
socket-poisoning payload on prod, because a dangling prefix on a shared keep-alive connection captures
*other users'* requests; the safe discriminator is *my own* request's latency — an H2.TE/H2.CL probe
crafted so that if the backend desyncs, only my connection stalls waiting for bytes that never
arrive. *Hypothesis:* the front strips or ignores a `Transfer-Encoding` the legacy origin honours, so
the malformed variant stalls while a well-formed control returns promptly. *Test/confirm:* send
several paired samples — the malformed timing probe versus a clean control — and require a
consistent, repeatable delay gap on the malformed one only, never one lucky slow response. No
cross-user capture PoC, no held-open sockets. Save the paired latencies as the artifact. *Novelty:*
the edge already normalizes plain CL.TE; the H2→H1 downgrade against this specific old origin is
unhunted — `fix_locus = CDN-H2 to legacy-origin downgrade`.
