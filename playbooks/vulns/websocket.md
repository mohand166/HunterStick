# WebSocket — the method

> **This is a test of your ability to find a WebSocket flaw** on the socket the human names — the
> chain that reaches Cross-Site WebSocket Hijacking or a per-message authz bypass. Model how the app
> authenticates the **handshake**, what re-checks **each message**, and what the message handler
> **trusts**, then find where that assumption breaks. WebSockets skip the same-origin policy and
> often the usual auth/authorization plumbing, which is exactly why reasoning beats scanning here.
> **Probe safely — don't flood the socket.** Work this with
> `playbooks/vulns/_master-vuln-hunting.md`.

---

## 1. Model the socket before you touch anything

**SOURCE** — where attacker-controlled data enters: the **upgrade request** (its `Origin`, cookies,
URL and any token in it) and every **frame** you can send once connected.

**FEED** — what carries it: the HTTP upgrade through any reverse proxy, then the framing layer and
whatever protocol rides on top — `socket.io`, `ws`, SockJS, STOMP, GraphQL-WS, SignalR. A proxy in
this path can rewrite or strip headers before the server ever sees them.

**SINK** — two distinct sinks, and they fail independently: the **handshake authenticator** (what
decides this socket belongs to this user), and the **message router** (what a frame is dispatched to
once the socket is up).

**CONTEXT** — the discriminator is **the handshake's origin trust, plus what the router does with
the frame**. Answer both halves:

| half | the question | the failure it names |
|---|---|---|
| handshake | what authenticates it — a **cookie** (auto-sent cross-site, CSWSH-prone) or a **token in the URL / first message** (not auto-sent, so a cross-site page can't obtain it)? does the server validate `Origin` on upgrade? | **CSWSH** — any site opens an authenticated socket in the victim's context |
| router: authz | is authorization enforced **per message**, or only at connect? can a connected low-priv user send a frame naming another user's or tenant's ID? | **IDOR over WS** |
| router: sink | where does inbound frame data land — `innerHTML`/DOM, another user's screen, an eval/dispatch, a backend query? where does *outbound* content get stored or rebroadcast? | **stored XSS over WS**, injection |
| router: transport | is the socket a transport for another protocol (SSH, DB, SOCKS)? | **tunneling** — SSRF-ish reach |

**ROOT CAUSE** — one of: no `Origin` validation on upgrade · authentication that rides on cookies
alone · authorization checked at connect and never again · a frame field trusted as an object
reference · frame content rendered into a DOM sink or rebroadcast unencoded · a proxy normalizing
the header the check depends on. **That answer is your `fix_locus`** — the specific handshake check
or message handler, so distinct issues count separately.

## 2. Derive the candidates — read the client, not a URL list

1. **Find every `ws://` / `wss://` endpoint** and the client JS that opens and handles it: live chat
   and notifications, collaborative editors, dashboards, trading and streaming feeds,
   terminals/consoles, GraphQL subscriptions.
2. **Read the client's contract** — the message shapes it sends and the ones it handles tell you the
   server's verb list. That list rarely appears in the URL space.
3. **Grep the handler for sinks** — `innerHTML`-class DOM writes, eval/dispatch, and any path that
   re-renders content that arrived from another client.
4. **Look for IDs in frames** — channel, room, record, tenant. Every one is an IDOR candidate.
5. **Read `technologies.md`** for the stack (`socket.io`, `ws`, SockJS, STOMP, GraphQL-WS, SignalR),
   which tells you the framing and the auth convention you're facing.
6. **Map role and tenant boundaries** — diff what two accounts can do over the same socket.

## 3. Determine the context — one handshake at a time

- **Send a handshake with a foreign or absent `Origin`** and see whether it is accepted. This is the
  single cheapest discriminator in the class.
- **Identify what actually authenticates** — watch whether the upgrade carries a cookie, or a token
  in the URL or first frame.
- **Establish whether the socket carries anything sensitive** at all, before you spend effort on it.
- **Test against the real endpoint**, not through a proxy of your own that might rewrite `Origin`.
- Use a WS client that shows you **raw frames**; you cannot reason about the router through a UI.

## 4. Test → Confirm → Validate

**Accounts gate:** the message-authz half needs **≥2 principals** you control, and the CSWSH half
needs a logged-in test victim of your own. Without them the honest result is
`coverage = blocked (needs-account)` — not "not vulnerable".

**TEST — is the socket reachable in a way it shouldn't be?** The foreign-`Origin` handshake is
accepted, or a frame naming an object you don't own is not rejected. **Outcome: a hypothesis.**

**CONFIRM — did data or an action actually cross the boundary?** The **default oracle is that a
socket opened from a genuinely foreign origin receives the victim's session-scoped data, or accepts a
privileged command** — for the authz half, that account A's frame returns B's data or changes B's
object, observed as a differential against the same frame with A's own ID. Connecting is not the
oracle; *what flowed after connecting* is.

The oracle inverts or lies here — rule each out:

- **Handshake accepted cross-origin but the socket carries no authenticated or sensitive data** (a
  public feed) → CSWSH with no impact.
- **Auth is via a token in the URL or first message, not cookies** → a cross-site page cannot obtain
  it, so it is not classic CSWSH. Confirm what actually authenticates.
- **`Origin` *is* checked, but the server returns a generic accept and then closes** — read whether
  data actually flowed before concluding.
- A **reverse proxy strips or normalizes `Origin`**, masking real server behaviour — test against the
  real endpoint.
- **Reflected message content that the client HTML-encodes** is not XSS.
- The connection "works" because **your test page is same-origin** — re-test from a genuinely foreign
  origin.

**VALIDATE — the least that proves impact.** One connection, one captured frame. CSWSH → read the
victim's real-time data or issue authenticated actions over the socket → account compromise;
message-authz IDOR → cross-tenant data access or modification; WS injection → stored XSS hitting
other connected users; tunneling → SSRF and internal pivot. Chains: CSWSH + a socket command that
changes account settings → ATO; WS stored XSS reaching an admin dashboard → privilege escalation;
message IDOR across tenants → broad data exposure. Escalate the *minimum* needed to show severity,
then say what you did not do.

## 5. Safety, artifact, and PoC handoff

- **Never flood or spam the socket** — one crafted frame per hypothesis, cleaned up afterwards.
- **Never send destructive commands**, and **never tunnel to real internal hosts** to "prove" reach.
- **Both accounts are yours.** For the message-authz test, account B is your own test account; for
  CSWSH, the logged-in victim is your own test victim.
- **Injection proofs stay in your own room.** Send a benign marker (an `alert(document.domain)`-class
  or console/DOM marker per `xss.md`) into an object you own and show it renders — **do not broadcast
  to real users.**
- **Store the artifact** under `targets/<t>/raw/`: the handshake request and response (`Origin` sent,
  status returned) and the received or rendered frame, with real sensitive values redacted.
  **No artifact → HYPOTHESIS, not FACT.**
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): the attacker-origin page that opens
  the socket, or the raw frame pair with its control, reproducible in one action from a clean
  session.
- Respect the rate limit; announce anything loud before running it.

## 6. Log it

Every probe goes to `targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with `result`,
`coverage` and the **`fix_locus` from §1** — the specific handshake check or message handler. The
principal column matters: "as foreign origin, logged-in victim" and "as account A naming B's ID" are
different cells. Log negatives *with the oracle used*.

**Novelty.** Scanners rarely model WS auth and authz, so well-reasoned instances are frequently
novel. Dups cluster on trivially-detected missing-`Origin` CSWSH on public feeds. Novelty =
**CSWSH that yields authenticated or sensitive data or actions**, **per-message authorization gaps
(IDOR over WS)**, **stored XSS via broadcast messages**, and **protocol tunneling**.

## 7. Worked example — the spine in one pass

*Model / derive:* the live-notifications client JS opens `new WebSocket("wss://target/ws")` with no
token in the URL or first frame — the endpoint and its auth convention came from reading the client
JS, not a URL scan (`technologies.md`: `socket.io` notifications feed). The handshake rides on the
session cookie, so the handshake half is cookie-authenticated and therefore CSWSH-prone.
*Context:* the deciding question is whether the server validates `Origin` on upgrade, so the
discriminating probe is a handshake from a *genuinely foreign* origin — not my same-origin test page,
which would pass for the wrong reason.
*Hypothesis:* any site can open an authenticated socket in the victim's context and read their
private notification stream.
*Confirm:* in Chrome MCP, host an attacker-origin page that scripts
`new WebSocket('wss://target/ws')` while logged in **as my own test victim**; confirm it connects
*and* that the first frame carries that account's private data (redact real values). The oracle is
the data flowing, not the socket opening. One connection, one frame — no flooding. Artifact =
handshake request/response (`Origin` sent, `101` returned) plus the received frame.
*Novelty:* CSWSH yielding authenticated data, not a trivial missing-`Origin` on a public feed —
`fix_locus = Origin validation on /ws upgrade`.
