# NoSQL Injection — the method

> **This is a test of your ability to find NoSQL injection** in the endpoint the human names — the
> chain that reaches auth bypass or data exfiltration. Model how your value travels into a
> Mongo/Mongoose query filter, work out whether it stays a **string** or becomes an **operator
> object**, and find where that assumption breaks. Reason about how input reaches a query operator
> — don't spray `$ne` at every field. Work it with `playbooks/vulns/_master-vuln-hunting.md`.

---

## 1. Model the query before you touch anything

**SOURCE** — the parameter you control, and crucially the *type* you can give it. JSON request
bodies where a value can become an object (`{"user":{"$gt":""}}` instead of a string) are the
operator-injection surface. Query strings parsed into nested objects (`user[$ne]=x` with
Express/`qs`) mean even GET params can smuggle operators.

**FEED** — the body parser and any casting between the wire and the query. A `String(input)` cast
or a schema-typed field kills most operator injection; a parser that preserves nested objects
preserves the attack.

**SINK** — the document-store query filter the value lands in: `username`/`password` on login,
`email` on reset, `id`/`_id` lookups, `filter`/`where`/`sort` on list endpoints. Non-obvious sinks:
`$where`/`$function` (server-side JS eval), `mapReduce`, aggregation `$expr`, `sort`/`limit` built
from user input, and keys used as *field names*.

**CONTEXT** — the discriminator is **whether your value is interpreted as data or as structure**,
and if as structure, which position: a value slot that accepts an operator object, a field-name
slot, or a JS-eval slot. On auth, is the query the `find({user, pass})` shape? If so, `pass` as
`{"$ne":null}` bypasses the password check — the classic auth-bypass primitive. Second-order
counts: a stored value later used as a filter key.

**ROOT CAUSE** — one of: the value is placed directly into the filter with no cast to string or
number · the schema doesn't type the field · the parser preserves nested keys the handler assumed
were flat · `$where`/`$function`/`$expr` is reachable with user-controlled JS. **That answer is
your `fix_locus`** — the specific query builder, so distinct sinks count separately.

## 2. Derive the candidates — reason about where a value becomes structure

1. **Take the parameters from the app's own artifacts** (HTML, JS bundle, spec, recon
   `parameters.txt`) and ask, for each, whether it plausibly lands in a filter.
2. **Prefer JSON bodies and nested-key query strings** over flat form posts — that is where a value
   can change type without the handler noticing.
3. **Include the non-auth endpoints**: search, filter, aggregation, list endpoints with
   `sort`/`limit`. These are where the surface survives.
4. **Tech signals from `technologies.md`**: Node/Express + Mongoose/MongoDB driver, body parsers
   that keep nested objects, GraphQL resolvers over Mongo, `qs`/`body-parser`.

## 3. Determine the context — before you send an operator

- **Does the endpoint accept JSON**, and does the value reach a filter without a cast? One
  legitimate request with a typed vs untyped value usually tells you.
- **Is the output reflective** (returns a record, or login succeeds) **or blind** (only
  success/fail)? That chooses boolean vs timing.
- **Is `$where` reachable?** Raw JS makes timing and OOB possible; without it, don't reach for them.
- **Baseline the normal result** — the row count or auth outcome for a plain string — so a
  difference means something.

## 4. Test → Confirm → Validate

**TEST — a single type-confusion probe.** Send the field as an object with a benign operator
(`{"$gt":""}` / `{"$ne":"x"}`) versus the plain string. **Outcome: a hypothesis.**

**CONFIRM — the default oracle is a consistent differential in result set or auth outcome between
the object form and the string form**, i.e. the value is being interpreted structurally. On a
lookup, an always-true versus always-false operator returns different row counts. Blind timing is a
last resort and only where `$where`/JS eval is reachable: a single short `sleep`-style expression,
one request, never a loop. The oracle lies when:
- the app returns the same result because the field is **schema-cast to string** before the query —
  your object was stringified, not executed;
- a login "succeeds" because of a default or test account, not your operator;
- the WAF or body parser rejects nested keys with a generic 400 — that is a block, not a bypass;
- result differences are driven by pagination or caching rather than your operator;
- `user[$ne]=` appears to "work" only because the framework silently dropped the bracket key.

**VALIDATE — the least that proves impact.** One differential pair is enough to prove structural
interpretation; stop there rather than walking data out. Impact: auth bypass (login without valid
creds), record enumeration, blind data exfil operator by operator, and RCE-ish server-side JS via
`$where`/`$function` on old configs. Chains: auth bypass → account takeover on the boundary you
bypassed; operator-driven boolean exfil → password-reset tokens/secrets → full ATO; injection in a
multi-tenant filter → cross-tenant read.

## 5. Safety, artifact, and PoC handoff

- **Never inject destructive operators** — `$out` overwriting a collection, `$merge`.
- **Never mass-match to dump a whole collection**, and never hammer `$where` with heavy loops; JS
  eval on a live database is an availability risk as much as a data one.
- Differential and boolean probes only, non-destructive, one request per hypothesis.
- **Store the artifact**: the object-vs-string request/response pair, both bodies. **No artifact →
  HYPOTHESIS.**
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): Burp Repeater or copy-pasteable
  `curl` for both requests — the operator object **and its plain-string control**.

## 6. Log it

Every probe goes to `targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with the
`fix_locus` from §1 recorded as the specific query builder. Log negatives with the oracle used, and
note *why* it was negative — a schema cast is a different negative from a WAF 400. **Dedup:**
`password[$ne]=` on the login form of a popular program is the single most-reported instance —
assume dup or already patched. Novelty lives in **JSON-body operator injection on non-auth
endpoints** (search/filter/aggregation), **query-string nested-key parsing** the scanner sent as
flat strings, `$where` and aggregation `$expr` sinks, GraphQL-over-Mongo resolvers, and
**second-order** injection where a stored value is later used as a filter key.

## 7. Worked example — the spine in one pass

*Model:* `endpoints.md` has `POST /api/products/search` taking a JSON body
`{"category":"...","name":"..."}`; `technologies.md` shows Express + Mongoose + `body-parser` with
nested objects preserved — so `name` almost certainly lands in `find({name: <input>})`, and if it
isn't `String()`-cast or schema-typed, an object value becomes an operator. *Derive:* a non-auth
filter endpoint the scanner only hit with flat strings. *Context:* output is reflective (a result
set comes back), so the discriminator is *set size*, not timing — the right probe is type confusion,
not `$where`. *Hypothesis:* `name` is placed directly into the filter, so a benign operator object
changes which documents match versus the same value as a plain string. *Confirm:* send `name` as
`{"$gt":""}` (matches all) versus the literal string `"zzz"` (matches few or none); a consistent,
large difference in returned count proves structural interpretation. No `$out`/`$merge`, no
mass-dump. *PoC:* both body/response pairs. *fix_locus:* the `find()` builder in
`/api/products/search` — the crowd sprayed `password[$ne]=` at login; almost nobody sent an operator
object to this product-search body.
