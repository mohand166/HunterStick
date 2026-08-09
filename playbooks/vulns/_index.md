# Vuln Class Index / Families

When the human names a **category / family** (e.g. "test client-side injections on X",
"check server-side bugs", "look at access control") instead of a single class, use this
map to load the right set of class files. Then work each **applicable** class through
`_master-vuln-hunting.md` — scoped to the surfaces that actually exist on the target (skip
classes whose *Where it hides* isn't present), one class at a time, evidence-backed. A
category command means "test the applicable ones," not "spray all of them."

Some classes appear in two families (e.g. `csrf`, `websocket`) — that's intended.

---

## Families → class files

### Client-side  (executes in the victim's browser)
*aliases: "client-side injections", "DOM bugs", "browser-side"*
- `xss` · `dom-clobbering` · `postmessage` · `prototype-pollution` · `cors` · `csrf`
  · `open-redirect` · `websocket`
- Core *injection/execution* subset: `xss`, `dom-clobbering`, `postmessage`,
  `prototype-pollution`.

### Server-side injection  (input → a server interpreter/parser)
*aliases: "injection", "server-side injection"*
- `sql-injection` · `nosql-injection` · `command-injection` · `ldap-injection`
  · `xpath-injection` · `template-injection` (SSTI) · `xxe` · `lfi-rfi`
  · `path-traversal` · `deserialization`

### SSRF & HTTP-layer manipulation
*aliases: "SSRF", "request/host bugs", "HTTP layer"*
- `ssrf` · `host-header-attacks` · `request-smuggling` · `cache-poisoning`
  · `origin-exposure`

### Access control / authorization
*aliases: "authz", "access control", "IDOR/BOLA"*
- `idor-bola` · `function-level-authorization` · `privilege-escalation`
  · `multi-tenant-isolation` · `mass-assignment` · `baas-rls`
- `baas-rls` = client-side-RLS backends (Supabase/Firebase/PostgREST/Appwrite) where the browser hits
  the DB gateway directly and RLS/security-rules are the *only* authz. Also relevant to the API and
  Cloud families below.

### Authentication & session
*aliases: "auth bugs", "login/session"*
- `authentication-bypass` · `user-enumeration` · `registration` · `password-reset` · `mfa` · `session-management`
  · `oauth-oidc` · `csrf`

### Business logic
*aliases: "logic bugs", "workflow abuse"*
- `workflow-abuse` · `race-conditions` · `limit-bypass`
  *(`state-machine-abuse` is a compatibility pointer to `workflow-abuse`, not a class of its own)*
  · `payment-abuse` · `coupon-and-credit-abuse`

### API & protocol
*aliases: "API testing"*
- **Transports are lenses, not classes.** "Test GraphQL/gRPC/the API" names a *surface*, not a bug.
  Use `playbooks/workflows/investigate-graphql.md` · `investigate-grpc.md` ·
  `investigate-api-surface.md` to find the surface and recover the contract, then test the actual
  classes from their own files — the transport never changes which bug it is.
- Classes that live here: `websocket` (handshake authz, origin check, message authz) · `baas-rls`.
- Where the classes usually land: `idor-bola` (**§I8** carries the transport specifics for GraphQL,
  gRPC and WebSocket) · `function-level-authorization` · `multi-tenant-isolation` ·
  `mass-assignment` · the injection classes · `limit-bypass` / `race-conditions` (batching).

### Files & upload
- `file-upload` · `path-traversal` · `lfi-rfi`

### Cloud & infrastructure
- `cloud-misconfiguration` · `subdomain-takeover` · `origin-exposure` · `baas-rls`

### AI / LLM features
- `llm-prompt-injection`

---

## Umbrella terms

- **"client-side"** → the *Client-side* family above.
- **"server-side"** → spans *Server-side injection + SSRF/HTTP-layer + access control +
  auth + business logic + API + files + cloud*. That's most of the catalog, so for a
  focused pass prefer a specific family (or the `investigate-endpoint` workflow, which
  enumerates every applicable class for one endpoint). If the human really means "all
  server-side," say what you'll cover and prioritize by the target's actual surface.
- **"everything applicable to this endpoint/host"** → use
  `playbooks/workflows/investigate-endpoint.md` / `investigate-asset.md` — they walk the
  full picture for one target rather than a class list.

## How a category command runs
1. Load `_master-vuln-hunting.md` + this index.
2. From the named family, keep only classes whose *Where it hides* matches the target's
   observed surface (from `endpoints.md`, `technologies.md`, JS, app map).
3. Test each kept class through the loop; log each in `tested.md` by `fix_locus`.
4. Summarize which classes applied, which were skipped (and why), and any findings. STOP.
