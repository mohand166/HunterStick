# XPath / XQuery Injection — the method

> **This is a test of your ability to find XPath/XQuery injection** in the endpoint the human names —
> the chain that reaches data extraction or auth bypass. Model the request down to the **expression
> builder** over its XML backing store, understand how the app splices your input into a predicate
> like `//user[name='<x>']` and whether it is parameterized, and find where that assumption breaks.
> Reason about the expression context — **don't spray quotes at search boxes**. The value is a
> located sink with a consistent boolean oracle behind it. Work this with
> `playbooks/vulns/_master-vuln-hunting.md`.

---

## 1. Model the expression before you touch anything

**SOURCE** — the request parameter that reaches the lookup: `username`/`password` on XML-backed auth,
`search`/`q`, `id`/`ref`, `category`/`node` — anything that becomes part of `//user[name='<input>']`.

**FEED** — what carries it: the HTTP layer, then possibly a SOAP envelope, an XSLT pipeline or an
outer XML parser before the value reaches the expression builder. Each of those can produce its own
errors, which matters when you read the response (§4).

**SINK** — the XPath/XQuery expression the app builds over its XML datastore, and what that
expression decides: which nodes are returned, or whether a login succeeds.

**CONTEXT** — the discriminator is **where in the expression your input lands: data position or
structure position.**

| position | how your input sits | what breaks it |
|---|---|---|
| data — inside a string literal in a predicate | `//user[name='<x>']` | quote parity: a `'` (or `"`) closes the literal |
| structure — the expression itself, once you're past the quote | `… or '1'='1`, `and`, `and position()` | you are writing XPath directly, so it must stay syntactically valid |
| parameterized — variable binding | your value never leaves data position | **not injectable** |

Two follow-on questions decide technique:

- **Is it AND-style auth** (`//user[name='<u>' and pass='<p>']`)? Then `' or '1'='1` collapses the
  predicate → auth bypass.
- **Is output reflective (nodes returned) or blind (login yes/no)?** That decides boolean
  differencing versus char-at-a-time `substring()`/`string-length()` enumeration.

**XPath 1.0 has no comment token** — you cannot truncate the tail the way you would in
SQL. **XPath 2.0+ and XQuery do**: `(: comment :)`. Fingerprint the engine before assuming;
if the target is XQuery (or XPath 2.0), `(:` *does* let you comment out the remainder, and
that changes the whole payload strategy. The original sentence continues for XPath 1.0:
SQL — every payload must close the string *and* leave the whole expression syntactically valid. Plan
the balanced form before you send anything.

**ROOT CAUSE** — the value was concatenated into the expression instead of bound as a variable.
Name the builder. **That answer is your `fix_locus`** — the specific expression builder, so distinct
sinks count separately.

## 2. Derive the candidates — reason from the backing store

1. **Ask what backs this data.** The class only exists where data or auth is backed by **XML** rather
   than a SQL DB: XML config and user stores, SAML/SSO attribute lookups, legacy SOAP services, XML
   feeds and catalogs, "search this document" features, `web.xml`/appliance-style products.
2. **Read `technologies.md` for the tells:** XML databases (BaseX/eXist), Java XPath/XQuery APIs,
   SAML processors, SOAP/`.asmx`, XSLT pipelines, appliances with XML user files.
3. **Then enumerate the inputs that must reach a lookup** on those surfaces — anything that filters,
   finds, authenticates or resolves a node. Reason about what the feature must query; don't start
   from a parameter wordlist.
4. **Prefer the surfaces scanners don't model** — XML-backed search and catalog endpoints, SAML/SSO
   attribute lookups, blind XQuery contexts (see §6).

## 3. Determine the context — before you write a payload

Cheap, safe, read-only probes; one request each.

- **Quote parity.** A lone `'` (or `"`) that errors or empties the result says you are inside a
  string literal and the app is concatenating. It proves position without injecting any logic — but
  on its own it is not a finding (§4).
- **Establish the baseline.** Record what a normal, valid value returns, so "all" versus "none" is a
  measured difference rather than an impression.
- **Decide reflective vs blind** by whether the node set is visible in the response or only the
  auth outcome is.
- **Note the AND-style shape** if the endpoint takes two credentials — that predicts which balanced
  form collapses it.

## 4. Test → Confirm → Validate

**TEST — does the expression break?** The lone `'` from §3 changes behaviour. **Outcome: a
hypothesis** — nothing more, because a broken input is not necessarily a broken expression.

**CONFIRM — is it XPath, and is my payload causing it?** The **default oracle for this class is a
balanced break-and-fix pair producing a *consistent* true/false difference** — `' or '1'='1` versus
`' and '1'='2`, read in the node set or the auth outcome, repeated to show it is stable. Both arms
must be syntactically valid; a consistent all-versus-none difference is the signal that cannot be
coincidence. For a blind context, a `substring(...,1,1)='a'` style predicate proving you control one
boolean serves the same purpose.

The oracle inverts or lies here — rule each out:

- A `'` producing an error may be **generic input validation**, not XPath syntax breaking. Require
  the balanced true/false pair to differ consistently.
- **"`1=1` returns everything"** may just be legitimate empty-search-returns-all behaviour.
- The error text may be **reflected from an outer XML parser**, not from the XPath engine.
- **Timing is unreliable here — there is no sleep primitive.** Don't lean on it; use boolean.

**VALIDATE — the least that proves impact.** Confirm a *single* boolean and stop. The impact argument
is that the same control yields auth bypass on XML-backed login, and full disclosure of the XML store
node-by-node (users, password hashes, secrets) via blind enumeration — you argue that from the
demonstrated boolean, you do not perform it. Chains: auth bypass → ATO on that boundary; disclosed
credentials or tokens feed reuse on other in-scope assets; and because XPath surface often neighbours
an XML parser that resolves entities, **XXE is worth a pivot** (`xxe.md`). Say what you did not do.

## 5. Safety, artifact, and PoC handoff

- **XPath is read-only by nature — keep it that way.** Boolean and differential probes only.
- **Never** use `doc()` / `unparsed-text()` / external-entity tricks to pull local files or URLs as
  your "proof". That is a different, higher-touch issue — **note it, don't fire it.**
- **Never loop-enumerate an entire store.** One differential pair proves the bug; char-at-a-time
  extraction beyond a single boolean is exfiltration, not evidence.
- **Store the artifact** under `targets/<t>/raw/`: the true-versus-false request/response pair, plus
  the lone-`'` probe that located you. **No artifact → HYPOTHESIS, not FACT.**
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): the pair sent to **Burp Repeater**, or
  a copy-pasteable `curl` for both arms **with the valid-value control**, so the difference is visible
  in one glance. Reproducible in one action from a clean session.
- Respect the rate limit; blind enumeration is a **loud** activity and is out of bounds here anyway.

## 6. Log it

Every probe goes to `targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with `result`,
`coverage` and the **`fix_locus` from §1** — the specific expression builder, so distinct sinks count
separately. Log negatives *with the oracle used*: "lone quote errored but the balanced pair did not
differ" is a meaningful negative that stops the next session re-chasing it.

**Novelty.** `' or '1'='1` on an obvious XML login demo is textbook and often already found. Novelty
lives in **XML-backed search and catalog endpoints**, **SAML/SSO attribute lookups**,
appliance/legacy SOAP products on newly discovered hosts, and **blind XQuery contexts the scanners
don't model**.

## 7. Worked example — the spine in one pass

*Model / derive:* `endpoints.md` has `GET /catalog/find?ref=` on a legacy SOAP-fronted product
catalog; `technologies.md` shows a Java XPath API over an XML datastore with no SQL DB — an XML-backed
search sink reached by asking what backs the catalog, not by fuzzing parameter names. `ref` most
likely builds `//item[ref='<x>']`: **data position** inside a string literal, injectable via `'`,
`or`, `and`, with reflective output (nodes returned).
*Context:* XPath **1.0** has no comments, so a probe must close the quote and stay syntactically
valid (XQuery/XPath 2.0 allow `(: … :)`);
timing is useless here, so the oracle has to be boolean.
*Hypothesis:* `ref` is concatenated unparameterized into the predicate, so a break-and-fix pair will
produce a consistent true/false difference in the node set.
*Confirm:* send a lone `'` (expect error or empty), then the balanced `' or '1'='1` versus
`' and '1'='2`; a consistent all-versus-none node-set difference confirms XPath control. One boolean
only — no `doc()`/file-read tricks, no whole-store enumeration. Artifact = the true/false pair with
the valid-value control.
*Novelty:* `' or '1'='1` on the XML login is textbook; this catalog-search predicate builder is the
novel sink, and it neighbours XXE worth a pivot — `fix_locus = XPath builder in /catalog/find`.
