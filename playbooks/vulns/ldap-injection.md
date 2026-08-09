# LDAP Injection — the method

> **This is a test of your ability to find LDAP injection** in the endpoint the human names — the
> chain that reaches auth bypass or directory-data disclosure. Model the request to the **LDAP
> filter builder**, work out how the app splices your input into a search filter like `(uid=<x>)`
> and whether it escapes the filter metacharacters, then find where that assumption breaks. The
> value is reasoning about the filter *context* — not spraying `*` at login forms. Thin class file;
> work it with `playbooks/vulns/_master-vuln-hunting.md`.

## 1. Model the flow before you touch anything

**SOURCE** — the request field that names a directory entry: `username`/`uid`, `email`/`mail`,
`cn`, `group`, `search`/`q`, `filter` — anything that becomes part of a filter.

**FEED** — the auth or directory layer between HTTP and the directory: an SSO gateway, a Java/`JNDI`
client, `.NET DirectoryServices`, `python-ldap`, an intranet app's own helper. Each hop may escape,
normalize, or pass your bytes through untouched.

**SINK** — the LDAP filter builder, and the search it issues against the directory backend (Active
Directory / OpenLDAP / FreeIPA, per `technologies.md`).

**CONTEXT — where in the filter your input lands.** This decides every probe you write:

| context | how your input sits | what breaks it |
|---|---|---|
| value context | `(uid=<x>)` | filter metacharacters `*` `(` `)` `&` `\|` `\` and NUL |
| AND-filter auth | `(&(uid=<x>)(password=<y>))` | closing the clause and appending `)(&)` / `*` drops the password condition — the auth-bypass primitive |
| fully parameterized / escaped filter | metacharacters neutralized | not injectable |

The second half of the context is **output shape**: is the result reflective (search returns
entries) or blind (login yes/no)? That decides boolean-differential versus entry-count differencing.

**ROOT CAUSE** — the specific filter builder that concatenates unescaped input into filter syntax.
**That is your `fix_locus`**, so distinct sinks count separately.

## 2. Derive the candidates — reason about which features must query a directory

1. **Enumerate the enterprise auth and directory features**: corporate/SSO login, "search the
   directory / address book / people finder", group-membership checks, self-service password reset
   keyed on `uid`/`mail`, admin user-management lookups. Anything that resolves a person to an entry
   is running a filter.
2. **Read the tech signals** from `technologies.md`: Active Directory / OpenLDAP / FreeIPA backends,
   Java/`JNDI`, `.NET DirectoryServices`, `python-ldap`, SSO gateways, intranet apps.
3. **Look past the login form.** Search, group and reset lookups build filters too, and they are
   where the untouched sinks live.

## 3. Determine the context — before you send a payload

Cheap, read-only probes whose only job is to locate you:

- **Which filter does this input build, and where in it?** Compare a benign exact value against a
  near-miss to learn whether the app is doing exact-match or substring matching by design.
- **Is it an AND-filter auth?** A login flow that takes both identity and password almost certainly
  is; that's the shape that yields the bypass primitive.
- **Is the output reflective or blind?** Decide your observation channel now — entries returned, or
  auth outcome — because you cannot confirm without one.

## 4. Test → Confirm → Validate

**TEST — does my input reach filter syntax?** A metacharacter probe: a value with `*` or an
unbalanced `)` that changes the result set or errors *differently* than a benign value (compare
`admin` vs `admin)` vs `admin*`). **Outcome: a hypothesis.**

**CONFIRM — is the filter really under my control?** The default oracle is a **consistent
true/false differential**: append a clause that is always-true versus always-false, balanced, and
observe a consistent difference in entries returned or auth outcome. A blind char-at-a-time
enumeration (`uid=a*`, `uid=b*`…) also proves control — do a *single* confirming character, not a
full dump. Keep everything read-only; LDAP is read-heavy and stays that way.

Where the oracle inverts or lies:
- `*` returning "more results" can just be a legitimate substring/wildcard **search feature**, not
  injection — confirm on a filter context that shouldn't allow it (e.g. exact-match login).
- A generic LDAP error surfaced by the driver is not the same as a filter-syntax break — read the
  message.
- An auth "bypass" that's actually anonymous-bind or default-account behaviour.
- Result differences caused by directory ACLs or paging rather than your metacharacter.

**VALIDATE — the least that proves impact.** One differential pair is enough. Do not size the
directory to prove severity.

**Impact & chaining.** Auth bypass, directory enumeration (users, emails, group membership),
attribute disclosure; occasionally reaching sensitive attributes → onward access. Chains: auth
bypass → intranet/admin ATO on the SSO boundary; enumerated emails/uids feed phishing or
password-spray on other in-scope apps; group-filter injection → privilege confusion.

## 5. Safety, artifact, and PoC handoff

- **Never** wildcard-match to enumerate the whole directory, never trigger expensive unindexed
  searches repeatedly (that's DoS), and **never attempt writes or `modify`**. Read-only, one
  differential pair.
- **Store the artifact**: the benign-vs-metacharacter request/response pair, and the true/false pair
  with its control. **No artifact → HYPOTHESIS, not FACT.** Redact directory data the proof doesn't
  need — real names, emails and group memberships are other people's data.
- **Ship a runnable PoC, never prose** (`playbooks/system/mcp-tooling.md`): the probe request to Burp
  Repeater or a copy-pasteable `curl` **with its paired control request**, so the differential is
  visible in one glance. Respect the program's rate limit; repeated directory searches are loud.

## 6. Log it

`targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with the `fix_locus` from §1 — the
specific filter builder. Log negatives *with the oracle used* (result-set differential? auth
outcome?), including the case where a `*` difference turned out to be a legitimate search feature.
**Novelty:** a `*`-in-username login test on a well-known SSO portal is a common report — likely dup
or hardened. Novelty lives in **directory-search and group-membership endpoints** (not just login),
**password-reset lookups**, attribute injection that leaks fields the UI hides, and internal or
acquired apps on newly found hosts.

## 7. Worked example

*Model:* `endpoints.md` exposes `GET /intranet/people?q=` on an internal address-book app;
`technologies.md` shows an OpenLDAP backend behind a Java/JNDI service — a directory *search*
endpoint, not the login everyone tests. SINK = the filter builder behind `q`; that's the `fix_locus`.
*Derive:* chosen precisely because it is a search rather than a login — the untouched sink.
*Context probe:* `q` most likely builds `(cn=<q>*)` or similar, so the value context is injectable
via `* ( ) & |` unless the filter is escaped. Output is reflective (entries returned), so the
discriminator is *result-set change* under filter syntax — and I must distinguish a real injection
from a legitimate substring search feature.
*Hypothesis:* `q` is spliced unescaped into the filter, so an unbalanced `)` breaks the expression
differently than a benign value, while a balanced true/false clause pair shifts the entry set
consistently.
*Test → confirm:* compare `q=smith` vs `q=smith)` (syntax break → different error/empty) vs a
balanced always-true vs always-false clause; a consistent entry-count difference confirms filter
control. One differential pair, no wildcard directory dump, no `modify`.
*Artifact:* the pair.
*Dedup:* the crowd tested `*` on the SSO login; the unescaped search-filter builder here is the
untouched sink — `fix_locus = LDAP filter builder in /intranet/people`.
