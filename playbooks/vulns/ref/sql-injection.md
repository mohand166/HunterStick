# SQL Injection — reference layer

> **Lookup, not reading.** Open a section when its trigger fires; don't read this end to end.
> The method lives in `../sql-injection.md` — that one you read every time.
>
> Grounded in 210 disclosed HackerOne reports (`knowledge/reports/sql-injection/`). `[#id]` =
> hackerone.com/reports/id — go read it when you need the detail. **Corpus bias:** skews legacy
> PHP/ASP/WordPress and older disclosures; thin on modern warehouses, serverless data layers and
> non-PHP ORMs.
>
> ⚠️ **Access & environment:** roughly a third of these citations carry a precondition an ordinary
> tester lacks — an admin panel, a signed-in account, a self-hosted or locally built install, a
> staging host, or a library reproduced in isolation. Around a quarter never touched a live target
> at all (framework test-suites, `npm install` harnesses, localhost PoCs). Inline markers are
> incomplete: **check the report before presenting a technique as ordinarily reachable.**
>
> Reason from the model in `../sql-injection.md` §1, not from these examples.

| § | trigger |
|---|---|
| **R1** | an ORM / framework builds the query |
| **R2** | a field expects a string but the API speaks JSON |
| **R3** | no visible output, or the body never changes |
| **R4** | something is filtering or blocking your probe |
| **R5** | your probe appears to do nothing |
| **R6** | a value you write is read somewhere else later |
| **R7** | confirmed — you need evidence of impact |
| **R8** | proving severity / building the chain |
| **R9** | you have source |
| **R10** | judging novelty and duplication |
| **R11** | worked examples |

---

## R1. An ORM or framework builds the query

**"We use an ORM" is where the audit starts, not where it ends.** Bindings protect *values*;
everything in the identifier and structure positions is outside that boundary.

- Django: a `FilteredRelation` **annotation alias** flows unquoted into `select_related()` SQL
  [#3292573]; `values()`/`values_list()` via a crafted **JSON object key used as a column alias**
  [#2646493]; `Q(**user_dict)` with the framework-internal key `_connector` formatted into SQL
  [#3335709]; **JSONField key transforms** built by concatenation — `"value_custom__" + user_input`
  into `.values()` lands raw in the JSON-path/alias position [#2588426], and `HasKey(lhs, rhs)`
  with an untrusted lhs on Oracle (CVE-2024-53908) [#2882887].
- TypeORM: the **keys** of a `where` object are unescaped [#319458]; a bound parameter that is a
  **function** skips escaping entirely [#506654]; `mergeDeep` prototype pollution injects a `where`
  into *every later query* — SQLi with no concatenation anywhere [#869574].
- Drupal `expandArguments` built PDO **placeholder names** from user-supplied array keys — pre-auth,
  and PDO multi-query made it stacked-query RCE [#31756].
- `$wpdb->prepare` with an array first-arg silently ignores the rest and re-quotes `%s` [#179920].
- Rails `items.reorder(params[:order])` in a finder fed by `params.merge(...)` [#298176].
- Prisma `queryRaw()` on a thoroughly modern stack — the 500 that leaked it carried a full
  COOP/COEP/CORP header set [#1626226].
- **Products that ship the raw fragment as a feature.** GIS/BI/orchestration software exposes the
  clause as a documented parameter: an ArcGIS `/MapServer/N/query?where=` takes `where=1=1` with no
  craft at all [#2433970]; Airflow's SQL check operators let an authenticated DAG user shape query
  construction → SQLi/RCE [#3078856]. Fingerprint these products in recon — "documented" ≠
  hardened, and "by design" is a triage conversation, not a dead end.

**The move:** wherever the API lets you *name a thing* — sort field, sort direction, filter key,
field list, column type, projection, table — attack the name, not the value.

## R2. The field expects a string but the API speaks JSON

Shape confusion, not string escaping. Ask what the parser does with a type it wasn't expecting.

- String → **send an object**. Pre-auth, `{"$regex":"^A"}` where a reset token was expected turns
  "is this token valid" into a per-character oracle [#1130721]. A sibling post-auth bug used `$where`
  on a `users.list` query as a general-purpose oracle → admin ATO → incoming webhook running a
  server-side script → shell [#1130874]. `getS3FileUrl({"$regex":".*"})` returns someone else's
  signed URL [#1458020].
- Flat kwargs → **send a framework-reserved key** [#3335709].
- Value → **put the payload in the key** [#319458, #31756].

Root fix on one of these was literally "ensure the parameter is a string" — which tells you how
rarely anyone sends anything else.

**Wrappers worth decoding** (the leaf is injectable; the blob is what gets fuzzed): base64'd JSON in
a link param [#150156] · nested JSON in an ASP.NET postback field [#1250293] · a JSON blob in a query
string [#1044698] · XML nodes of an uploaded document [#531051] · WebDAV `REPORT` body [#1390331] ·
multipart field [#272506] · path segments [#1626226, #17225, #319279, #1527284] · sentinel `-999`
defaults on hidden fields [#692326] · undocumented oddly named cookies [#300176] · enums/UUIDs/opaque
ids [#1627995, #435066, #648346] · **headers into analytics/logging INSERTs** — `X-Forwarded-For`
[#115304, not-applicable], `Referer` [#723044], `User-Agent` [#771215, #2597543]: the query fires on tracking
pixels and 404 handlers rather than input forms, so the oracle is time-based by default.

## R3. No visible output — oracles that aren't the body

**Principle: any observable the query can influence is a bit.** Find one you can read reliably, then
hold everything else constant.

1. **Business outcome.** If the query's job is "does this code/id exist," the workflow's verdict *is*
   the bit — a validation that fails normally but succeeds under an always-true condition [#269279];
   an id that stays valid under `AND 1=1` and invalidates under `AND 1=0` [#1044716]. No error, no
   diff, no timing — and no scanner models "did the signup go through."
2. **Error class / status class.** Quote parity [#761304, #2209130]; Oracle `ORA-01756` (odd quotes)
   vs `ORA-01722` (even quotes, valid SQL, wrong type) [#519631]; 404↔200 on a path payload
   [#1107536, informative]; redirect-vs-500 where *both* branches are failures [#1527284, #982202].
3. **Type confusion as the FALSE branch.** `CASE WHEN (<pred>) THEN 'a' ELSE <a number> END` — string
   branch returns cleanly, number branch throws [#982202]. Or division by zero:
   `1/(CASE WHEN <pred> THEN 0 ELSE 1 END)` [#3006666].
4. **Row order.** Emails leaked character by character purely by flipping the relative order of two
   rows the attacker owned — no error, no timing, no row-count change [#298176]. Also
   `ORDER BY IF(<pred>, id, -id) LIMIT 1` [#506644].
5. **Row identity / presence.** OFFSET injection changes *which* row returns, not how many [#1015406];
   results vs no-results [#1893800]; empty vs a random row [#2051931].

**Timing controls** (when you do fall back to time-based): computed delays `sleep(5*5)` → 25 s,
`sleep(6*6-30)` → 6 s, `sleep(5*5*0)` → immediate [#297478]; a ladder 15→15.9 s, 10→10.7 s, 2→2.7 s,
1→1.9 s with a `DELAY '0:0:0'` zero point [#2020429, #2759243]; arity control — `SLEEP(25)` hangs
while a bare `SLEEP()` does not [#310031 — the report says only "won't hang", not that it errors, and
its leaked query looks like MSSQL, which has no `SLEEP()`; treat as unconfirmed]; watch for a
**multiplier** — one target returned exactly 5× the requested sleep, the reporter concluding the
statement executes five times [#488795]. No sleep primitive? Oracle cartesian `ALL_USERS T1,…,T5`
[#214798]. (`BENCHMARK()` is often suggested; its only corpus citation is a one-sentence report with
no artifact, closed informative — and it is MySQL, which has `SLEEP()` anyway [#144359].)

## R4. Something is filtering you — evade by parser differential

**Principle: the filter and the database parse the same bytes with different grammars; the bug is
the disagreement.** Don't iterate a payload list — identify which token class is rejected, then
express the same semantics with a different one. A block is a *fingerprint of the filter*.

| what's blocked | express it another way |
|---|---|
| whitespace | `/**/` between tokens — documented filters: "spaces are not accepted, so I must replace them with `/**/`" [#982202] and a backend that splits search terms on whitespace [#1893800]; the same syntax appears without a documented filter in [#836079, #301257]; versioned comments `/*!50000…*/` [#1125752 — keyword obfuscation rather than whitespace substitution, and no filter is documented]; a comment between a function name and its paren — `sleep/*f*/(10)`, which the finder reports as an Akamai Kona bypass he'd found previously [#403616] |
| `'` / quotes entirely | **Honest caveat: no corpus report documents a live quote filter being defeated.** The two genuine escaping bypasses are both local/lab — PostgreSQL dollar-quoting past a quote-blocking regex [#3417967] and backticks past `addslashes` [#983710]. The quote-free *syntax* worth knowing anyway: hex literals (`0x…`) [#301257, #506654]; `CHR()`/`CHAR()` concatenation [#360539, not-applicable]; arithmetic-only truths (`3*2*1=6` vs `3*2=5`) [#1250293] |
| `=` | `LIKE` — the clearest documented character filter in the corpus (`=`, `\|`, `;`, `>`, `<` all rejected) though the reporter reached only first-character oracles, severity medium [#3006666]; `IS NOT NULL` around a division-by-zero. (The null-safe `<=>` belongs to the WAF-signature row below, not here — `=` was never blocked there.) |
| `>` / `BETWEEN` (bisection ops) | `IN()` as the comparison [#3234050]; `NOT BETWEEN 0 AND n` |
| the canonical payload (WAF signature) | grammar-mutated equivalents. Default `AWSManagedRulesSQLiRuleSet` blocked `alice' OR 1=1--` (403) while `\|\|`/`&&` + `<=>` + arithmetic + an early `;` returned 200 with all rows [#3591725, closed **informative**] — **a purpose-built lab app with multi-statement execution deliberately enabled**, so treat it as proof the grammar gap exists, not as a field-tested payload |
| the outer format rejects your char | encode in *that* format — `&apos;` inside XML [#531051]; re-encode base64/JSON wrappers to reach the leaf — note that in [#150156] base64 is the link's native encoding, not a filter being evaded |
| the edge, not the app | request the origin IP directly, behind the CDN's WAF [#1107536, informative] |

**Syntax worth knowing where no filter is proven** (these appear as working payload shapes, not as
documented bypasses): `&&`/`||` and `XOR` [#3591725 (informative), #1069531]; staying inside the string with
concatenation instead of breaking out — `'||(SELECT …)||'` [#1627995].

**Terminators matter:** `-- ` (trailing space), `-- -`, `--+-`, `#`, or junk after the comment. If
the tail of the real query must survive, **don't comment it out — balance it** (close your literal,
reopen theirs).

Tool tampers (`space2comment`, `between`, `bluecoat`, `randomcase`, `htmlencode`) encode these same
transformations. Use them **after** you understand the filter, not instead of understanding it.

## R5. Your probe did nothing — probably a false negative

**Principle: a negative is a claim about your probe, not about the application.** Before recording
"not vulnerable," enumerate every layer between your keyboard and the SQL parser that could have
absorbed it — transport encoding, client-side validation, a length cap, a framework binder, a cache,
an edge device — and rule each out. Below are the corpus's instances, not the complete set.

- **Something ate your quote before SQL saw it.** On an XML endpoint `'` looked "properly escaped";
  the *XML parser* was rejecting an illegal character. `&apos;` produced a database error at once
  [#531051].
- **Client-side truncation** — a `maxlength` meant only short payloads ever ran; raising it in
  DevTools turned a clean negative into an auth bypass [#419017].
- **The base value must be valid** — the differential only appears when the surrounding id is real
  [#23014].
- **Pre-existing state required** — "only fires when at least one record exists" [#1757676]; needs an
  object created through a multi-step wizard [#1046084]. Fresh instances test clean.
- **The block isn't a status code** — a WAF answered with a **TCP reset**, reading as a flaky
  connection [#227102]; a 302 swallowed the signal until redirect-following was disabled [#1627970].
- **Caching keyed on part of your value** — replaying the identical payload made the delay vanish;
  varying the leading integer restored it [#403616]. Any tool that confirms by replay calls this a
  false positive.
- **Filtered operators ≠ no bug** — see R4.
- **CAPTCHA doesn't protect the query** — an injection fired on a login form with a valid captcha
  token attached [#1224660].
- **"Not vulnerable" from a tool** is a statement about that tool's charset and oracle. Default
  settings missed a bug that raised risk/level plus tampers found [#692326]; a human built a custom
  type-error oracle where the tool gave up [#982202].
- **Modern stack ≠ safe stack** [#1626226].

## R6. Second-order — change state here, break something over there

**Principle: your input's journey doesn't end at the response.** Find every place it is stored and
every later query that reads it. Structurally invisible to fuzz-and-diff-the-same-response.

- **Config fields.** Put a non-numeric character in a numeric-looking setting (page size, feed count,
  row limit) and load the page that consumes it — the value lands raw in a `LIMIT` [#374748,
  authenticated admin; the reporter produced only an error message, never an extraction]. Cheap:
  one save plus one page load.
- **The app echoes its own INSERT.** A 404-logger wrote the requested URL, IP, host and referer into
  a table and printed the statement verbatim on the error page [#31023] — all attacker-influenced.
- **The error surfaces where you weren't looking** — inside a *success* message [#232378], in an
  admin API's JSON rather than the UI [#923020], or in the backend's own exception monitoring
  [#435066].
- **Test as the privileged role too.** Several needed an admin or low-privileged user to *write* the
  value that later breaks a public page [#374748, #923020, #3198980, #1663299].

## R7. Confirmed — extract with the minimum footprint

You need evidence, not a database. Every extra request is noise, ROE risk and rate-limit exposure.
**Principle: prefer a one-shot that returns a value in an error message over any loop; if you must
loop, shrink the search space first.**

**One-shot, no loop:**
- Error-based MySQL: `updatexml(null,concat(0x0a,version()),null)` [#277380];
  `extractvalue(rand(),concat(0x3a,(select user())))` [#1626226]; the
  `GROUP BY CONCAT_WS(0x3a,VERSION(),FLOOR(RAND(0)*2)) HAVING MIN(0) OR 1` form [#186367].
- Type-cast leak — cast to an incompatible type and the value lands verbatim in the error:
  `AA'+OR(cast(current_user as date))LIKE'A` → `invalid input syntax for type timestamp: "<value>"`
  [#1489744]. (Report doesn't name the engine; the error string reads PostgreSQL — ASSUMPTION.)
- Hex literals (`0x0a`, `0x3a`) double as a visible delimiter in the error *and* keep quotes out.

**Walking rows without UNION:** `limit N,1` as a row cursor inside the subquery [#1626226]. Count
columns by differential (`ORDER BY n` true vs false), not by triggering UNION errors [#23014].

**When you must go bit by bit:**
- **Binary search**, not linear character walks — for a regex-capable sink, split the candidate set in
  half per request [#2580062].
- **Reduce the charset by the field's type first.** A hash is hex, a token is base62, a DB user string
  is mostly digits and `_-@.` — one corpus extraction ran its whole loop over an alphabet of about
  fifteen characters chosen from what the field could contain [#150156].
- **Budget it out loud** — say how many requests and at what rate before you run it, and stop at the
  value that proves the point.

## R8. Impact & chaining

- Data exfil (other tenants' data → also a multi-tenant/IDOR story), authn bypass, sometimes RCE
  (`xp_cmdshell`, `COPY TO PROGRAM`, file write). Escalate the *minimum* that shows severity.
- **Treat SQLi as a write primitive, then hunt what the app deserializes back out of the DB.** A
  debug analyzer wrapped queries in a transaction for safety; the injection escaped it
  (`; ROLLBACK; INSERT …; -- ` — the trailing comment killed the framework's own appended
  `ROLLBACK`), planting a row later revived into language objects → RCE [#1663299]. One reporter
  filed a deserialization sink **with no SQLi in hand**, as a pre-staged amplifier [#361341].
  Mapping DB→object gadgets first makes any future SQLi instantly RCE.
- **Break the safety wrapper, not the query.** The corpus case is an appended `ROLLBACK` commented
  away [#1663299 — HackerOne-internal tool, demonstrated on localhost]. Read-only replicas, LIMIT
  clamps and timeouts are the same idea extended by reasoning, not observed here.
- Blind command output has no HTTP channel: `xp_cmdshell` → **DNS exfil** [#1339430]. App-native
  escalation beats OS escalation where it exists: SQLi → reset token → admin → webhook script → shell
  [#1130874].
- Non-dump impacts that land well: authz bypass exposing unpublished content [#2453475]; a stacked
  `UPDATE` rewriting a user's email, triggered by an authenticated admin merely opening a crafted URL
  [#38778]; forged records via extra `INSERT` tuples [#508346].

**False-positive traps:** WAF returning a generic 403/500 to any quote ≠ injection · reflected error
text that's really client-side validation · timing "delays" that are network jitter · an ORM safely
stringifying your payload · rate-limiting or caching causing unrelated differences · a 503 under load
is not a negative [#31023].

## R9. Audit method — one unsafe helper, then every caller

With source (OSS component, disclosed patch, leaked code): classify a query-building helper's
parameters by escaping, then enumerate its call sites. One helper with four raw parameters led the reporter to **two** vulnerable call sites [#374748]; a vendor's own fix note inverted it — "check every API endpoint
that uses this parser" [#1130874].

- **Audit the sanitizer, not the caller.** `addslashes` doesn't cover backticks, so a backtick-quoted
  identifier stays injectable [#983710]. A framework's forbidden-alias regex blocked quotes but not
  `$`, reopening injection via dollar-quoting after two prior CVEs "fixed" it [#3417967]. A
  `sanitize_*` helper that strips tags does nothing about quotes [#3198980]. And the sanitizer may
  be a **platform global the code doesn't control** — a plugin's raw `$_GET` concatenation looked
  trivially injectable in source, but WordPress's magic-quotes layer silently slashes GPC; code that
  looks vulnerable isn't, until something removes the global [#310280].
- **Grep for functions whose name admits they remove protection** — `…Unslashed`, `raw`, `unsafe`,
  `unescaped` [#3395221].
- **Count your reflections.** If your value appears N times in the generated query, that's N chances
  to open and close a literal; design the payload to swallow the real SQL between the copies
  [#3417967].
- **A correct whitelist beside an unvalidated sibling is a signal, not reassurance** [#1081145].

## R10. Novelty and duplication

WHERE-clause SQLi on an obvious id parameter of a popular program is almost always a dup or already
hardened. Novelty in this corpus lived in: **identifier and structure positions** (R1), **path
segments**, **shape confusion** (R2), **second-order via config** (R6), **transports that hide the
parameter** (R2), and neglected assets — regional/country-market properties, campaign microsites,
vendor and ESP hosts reached from your own inbox [#150156], third-party beacons fired by a page the program had actually
excluded from scope — the reporter filed anyway [#433792], staging hosts [#23014], DB consoles on origin IPs or odd ports [#687908, #178632].

**Re-test what was already fixed.** Fixes get reverted and staging gets redeployed: a patch reverted
and the host vulnerable again [#277380]; a fix bypassed [#1224660]; a supposedly-resolved injection
point still live [#1018621]. Old disclosed reports on your target are an inventory of places that
were once vulnerable — and reading them is free.

## R11. Worked examples — one per position

**A. Identifier.** `GET /api/reports?sort=created_at` on a self-built reporting service.
*Model:* `sort` names a column → identifier position → root cause "a column name cannot be bound" →
`fix_locus = ORDER BY builder in /api/reports`. *Context:* a quote may still error here — identifier
position doesn't make quotes useless; one corpus builder emitted `Order by 'INJECTION' ASC` and threw
on an apostrophe [#310031] — but the *reliable* discriminator is ordering behaviour. *Confirm
(in-band):* `sort=(CASE WHEN 1=1 THEN created_at ELSE id END)` vs the `1=2` variant; if row order
flips, SQL evaluated it. *PoC:* both requests to Repeater, or two curls showing the flipped order.

**B. Value, blind.** A signup form validates a code and returns one generic failure however you shape
it. *Model:* a comparison value inside an existence check; feed is a plain form post. *Context:*
quote parity distinguishes string from numeric. *Confirm:* the body never varies, so time-based is
the default — baseline, then a computed delay (`sleep(5*5)` → 25 s) with `sleep(5*5*0)` as the
immediate control [#297478]. *But try R3.1 first:* the workflow's own verdict may be a cleaner oracle
than timing — if the code validates under an always-true condition, that's your bit with zero delay.

**C. Second-order.** An admin setting takes a row count; a public page renders using it. *Model:*
source = the settings form, feed = **storage**, sink = a `LIMIT`, context = structure. *Test:* save a
non-numeric character. *Confirm:* load the public page and observe the breakage — the error appears
on a page you never fuzzed. *fix_locus* is the query that reads the setting, not the form.
