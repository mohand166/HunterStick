# SQL Injection — the method

> **This is a test of your ability to find SQL injection** in the target the human names — the chain
> that reaches data exfiltration, auth bypass, or (at the extreme) RCE. Model the data flow, locate
> the **query sink**, understand the **context** your input lands in and **why the code could not
> parameterize it**, then break that assumption with the smallest test that can't lie. You are a
> researcher, not a payload cannon. Work this with `playbooks/vulns/_master-vuln-hunting.md`.

**Read this file every time. It is the whole method.** Techniques, payload catalogues and corpus
evidence live in **`ref/sql-injection.md`** — open it only when you hit one of its triggers:

| you observe | open `ref/sql-injection.md` § |
|---|---|
| An ORM / framework builds the query | **R1** identifier & structure positions |
| A field expects a string but the API speaks JSON | **R2** send the wrong shape |
| No visible output, or the body never changes | **R3** oracles that aren't the body |
| Something is filtering or blocking your probe | **R4** parser-differential evasion |
| Your probe *appears* to do nothing | **R5** false-negative checklist |
| A value you write is read somewhere else later | **R6** second-order |
| Confirmed — you now need evidence of impact | **R7** minimum-footprint extraction |
| Proving severity, or judging duplication | **R8** impact · **R10** novelty |
| You have source (component, patch, leaked code) | **R9** audit the helper, enumerate callers |

---

## 1. Model the flow before you touch anything

Five questions. You cannot choose a technique before you can answer them, and answering them *is*
most of the work.

**SOURCE** — where does attacker-controlled data enter? Every byte of the request is a source: path
segments, headers, cookies, body fields at any nesting depth, uploaded file contents and filenames —
plus anything the *app* stores now and reads later.

**FEED** — what carries the value from source to the query? Each hop is a place the developer's
mental model stops, and each can encode, decode, validate or mangle your probe:
HTTP → framework binding → an intermediate parser (JSON, XML, base64, template, RPC) → maybe
*storage* → the query builder. Every extra parser multiplies the surface.

**SINK** — what SQL construct does it become? A comparison value, a column or table name, a sort
direction, a LIMIT, a raw fragment, a placeholder name, a JSON key path.

**CONTEXT** — the exact lexical position at the sink. This decides every payload you will write:

| context | how your input sits | what breaks it |
|---|---|---|
| numeric / unquoted | `WHERE id = 6` | arithmetic; no quote needed at all |
| single-quoted string | `WHERE name = 'x'` | quote parity, concatenation operators |
| double-quoted string | `VALUES ("x")` | as above with `"` |
| identifier | `ORDER BY <col>`, an alias, a table | expressions, not quotes |
| structure | `LIMIT n`, a raw fragment, a connector | you are writing SQL directly |

**ROOT CAUSE** — *why* could this not be parameterized? The answer is one of: it's an identifier
(bindings can't name things) · a raw fragment is a product feature · an escape hatch was used ·
the escaping function doesn't cover this character class · the value crosses a parser that
re-introduces it. **That answer is your `fix_locus`** — write it down before you test.

> **Positions beat names.** Most corpus bugs are still ordinary value-position injections — but the
> identifier and structure positions are where the *uncontested* ones lived (**R1**), because that is
> where parameterization cannot reach. If your input *names a thing* rather than compares to one, you
> are probably already past the boundary.

## 2. Derive the candidate inputs — don't start from a wordlist

A wordlist finds the contested surface everyone already fuzzed. **Reading the application finds the
rest, and that's where the novelty is.** Derive candidates in this order:

1. **What must this endpoint query to do its job?** Anything that renders, sorts, filters, validates,
   exports, counts, deletes or *looks something up* is running a query. Enumerate the inputs that
   could reach each clause of it. Reasoning, not guessing.
2. **Harvest the app's own vocabulary** — HTML including hidden fields, JS bundles, OpenAPI / WSDL /
   GraphQL schema, mobile bundle, and `targets/<t>/recon/parameters.txt` from parameter-discovery. The app tells
   you its parameter names; you never have to invent them.
3. **Decode every wrapper and attack the leaves** — base64, JSON nested in a form field, a JSON blob
   in a query string, XML nodes, multipart fields, RPC arguments. What's opaque to a scanner is where
   the value actually lives.
4. **Include the whole request** — path segments (recurring and under-tested, because param-mining
   tools need an explicit marker to reach them), headers, cookies, and the sort/filter/field
   *structure* parameters, not only the data ones.
5. **Read the tells.** Hidden fields carrying sentinel defaults land straight in filter SQL. A
   parameter named for a query concept — a report id, a sort expression, a "clause" or "filter
   expression" in a BI/admin surface — is naming its own sink. So is an undocumented, oddly named
   cookie.
6. **Type is not protection.** Enums, UUIDs, opaque tokens and structured ids were all injectable.
   "Only numeric ids reach SQL" is false.

## 3. Determine the context — before you write a payload

Cheap, safe probes whose only job is to tell you *where you are*. One request each, none changes data.

- **Quote parity.** One `'` errors, two `''` restore normal behaviour → you are inside a string
  literal and the app is concatenating. The cleanest structural probe there is: it proves position
  without injecting any logic.
- **Arithmetic in a numeric context.** If `id=6-1` returns the `id=5` row, you're unquoted and the
  database is evaluating your expression — no quote needed for anything that follows.
- **Keyword-free boolean.** `UPPER('asd')='asd'` vs `='ASD'` separates evaluation from reflection
  with no digit and no `1=1` signature.
- **Error dialect → DBMS.** Write one trivial expression three ways — `CHR(..)||CHR(..)` (Oracle),
  `CHAR(..,..)` (MySQL), `CHAR(..)+CHAR(..)` (MSSQL). **The engine is the one whose form the database
  parses and *errors* on**; the forms that return no error are the engines you rule out. (Sound
  craft, but its single corpus instance was a report the program declined — see R4.)
- **Polyglot only to decide "is anything live?"** — it can't tell you *which* context fired, since
  all arms ride one request behind one oracle. Follow up with a single-context probe.

**If the DBMS stays unknown:** infer from `technologies.md`, error strings and quoting behaviour,
then try candidate engines **one at a time, reasoning from each response**
(`playbooks/system/adaptive-tooling.md`) — never a blind spray. Don't infer the engine from the web
tier; the corpus has SharePoint over MySQL and `.asp` over PostgreSQL.

## 4. Test → Confirm → Validate

Three steps, three different bars. Most false reports come from treating step 1 as step 3.

**TEST — is my input evaluated at all?** Cheapest signal that something reaches an interpreter: a
structural probe from §3, a differential pair, an unexpected error class. **Outcome: a hypothesis.**

**CONFIRM — is it SQL, and is my payload causing it?** The bar is *a signal that cannot be
coincidence*:

1. **Differential / in-band — first whenever output is visible.** `AND 1=1` vs `AND 1=2`, arithmetic
   in numeric context, error-based, or a `CASE` in an ORDER BY. Cheapest, safest, reproducible.
2. **Blind — time-based is the DEFAULT.** It is *channel-independent*: no outbound network needed, so
   it still works where egress is filtered and OOB fails silently. To make it un-dismissable:
   **(a)** baseline the endpoint's normal timing over several samples; **(b)** establish the parameter
   plausibly reaches the DB — never trust timing on a parameter with no other evidence; **(c)** demand
   a repeatable delta against baseline *and* control requests, one short sleep, never a flood; and
   **(d) make the delay self-evidently yours** — put arithmetic inside it (`sleep(5*5)` → 25 s) with
   the `*0` variant as the immediate control. A delay you *computed* cannot be jitter. A ladder of
   several values with a zero point works too.
3. **OOB — a fast confirm when egress is open**, unambiguous when it fires. But **a silent callback
   is NOT a negative**; fall back to baselined timing.
4. **Body never changes and timing unusable → `ref/sql-injection.md` R3.** The channel isn't the response body.

**VALIDATE — the minimum evidence that proves impact.** Not "can I dump the database" but *what is
the least I can retrieve that makes the severity undeniable* — usually one benign value: a version
string, the current user, a row count, or a single field proving cross-boundary access
(**R7** for doing that in the fewest requests). Then stop, and say plainly what you did not do.

## 5. Safety, artifact, and PoC handoff

- **Never** `DROP`/`DELETE`/`UPDATE`, stacked destructive statements, sleep floods, or bulk dumping.
- **Store the artifact** — the true/false pair, the timing set with its controls, or the callback —
  under `targets/<t>/raw/`. **No artifact → HYPOTHESIS, not FACT.** Redact what the proof doesn't need.
- **Ship a runnable PoC, never a prose description of one** (`playbooks/system/mcp-tooling.md`):
  - **Burp MCP** for candidate and confirmed requests — send them to **Repeater** so the human can
    tamper hands-on and it lands as an organized artifact. Candidates and confirmations only; don't
    log everything to Burp.
  - **Otherwise a copy-pasteable `curl`** — full URL, method, every required header including the
    program's mandated bug-bounty header, exact body, **and the paired control request** so the
    differential is visible in one glance.
  - Either way: reproducible in one action, from a clean session.
- Respect the rate limit. A blind extraction is a **loud** activity — budget it and say what it will
  cost *before* running it. Where the program mandates an identifier, put it in the payload itself so
  your traffic is attributable in their logs.

## 6. Log it

Every probe goes to `targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with `result`,
`coverage`, and the **`fix_locus` from §1** — that's the dedup key, so distinct sinks count as
distinct findings. Negative results get logged too; that's what stops the next session re-chasing
them. Novelty judgement: **R10**.
