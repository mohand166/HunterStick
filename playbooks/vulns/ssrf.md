# Server-Side Request Forgery (SSRF) — the method

> **This is a test of your ability to find SSRF** in the target the human names — the chain that
> reaches internal services or cloud metadata. Model the data flow, locate the **fetch sink**, work
> out **how much of the outbound request you control** and **why the validation can't hold**, then
> prove it with a channel that can't be mistaken for someone else's crawler. Don't spray
> `169.254.169.254` at every parameter. Work this with `playbooks/vulns/_master-vuln-hunting.md`.

**Read this file every time. It is the whole method.** Technique catalogues live in
**`ref/ssrf.md`** — open a section only when its trigger fires:

| you observe | open `ref/ssrf.md` § |
|---|---|
| A validator, allowlist or blocklist stands in the way | **S1** parser differentials, encodings, fail-open |
| Your text ends up inside something the server *renders* | **S2** renderer & format-driven SSRF |
| The fetch is asynchronous, stored, or fired by someone else | **S3** blind & second-order |
| No callback, or an empty result | **S4** oracles, calibration, filtered-to-empty |
| Confirmed — you need to show reach | **S5** what to reach, and how to stop safely |
| Non-HTTP schemes, or host+port fields with no URL | **S6** protocols & non-HTTP sinks |
| Deciding whether it's really the target fetching | **S7** attribution traps |
| Building severity, or judging duplication | **S8** impact · **S9** novelty & hunting fixes |

---

## 1. Model the flow before you touch anything

**SOURCE** — where does something that *becomes* an outbound request enter? A `url` field is the
obvious case and the least productive one. Also: a host or port field with no URL at all · a
redirect you control · a filename · a cookie or a `Host` header · **any user text that reaches
something the server renders** (HTML, a document template, an SVG — even an *error message* that
interpolates your input) · a value stored now and fetched later · **content inside a response the
server just fetched** · configuration the app trusts.

**FEED** — what carries the value to the request, and **which library finally makes it**?
Fingerprint the client early (its User-Agent on your listener usually names it): its parser quirks,
redirect behaviour and protocol support decide everything downstream. Between source and sink sit
validators, normalizers, resolvers — and sometimes a *second* fetch derived from the first.

**SINK** — what actually makes the request, and **from whose network position**? The app server, a
worker, a headless browser, a converter container, a CI runner — or, in the highest-impact cases,
**infrastructure belonging to someone else**: a cloud vendor's control plane fetching a config
object you created, or other clients following a redirect you serve while carrying their own
credentials. The sink's position *is* the impact.

**CONTROL SURFACE** — how much of the outbound request do you own?

| you control | notes |
|---|---|
| full URL | scheme, host, port, path — strongest |
| host only, or host + port fields | common in mail/notification/integration config; often non-HTTP |
| path/query appended to a fixed base | terminate the appended suffix with `?` or `#`; sometimes the base host itself can be displaced |
| hostname → DNS only | oracle is DNS; impact usually recon or rebinding. *No corpus instance — reasoned, not observed.* |
| **request headers** | a `remote_*_request_header`-style setter, or CRLF in the URL. Would defeat a metadata header requirement — raised as impact in the corpus but **never demonstrated** |
| **method and body** | some sinks POST, carrying a body and auth headers |
| indirect — your text inside a rendered document | see **S2**; no URL parameter needed at all |

**ROOT CAUSE** — *why* can't the validation hold? Validator and client parse the URL differently ·
they **resolve DNS separately** (TOCTOU) · the check runs before a redirect · the validator **fails
open** (an exception, or an empty resolver answer, treated as "safe") · the allowlist matches a
substring instead of the authority · the app allowlists a *host* and then trusts **the data that
host returns** · validator and fetcher are **different processes** (a HEAD from one, a GET from
another) · no network-layer egress control at all. **That answer is your `fix_locus`.**

## 2. Derive the candidate sinks — reason about features, not parameter names

**The injectable field is rarely called `url`.** Derive candidates:

1. **What would this product have to fetch to work?** Webhooks · import-from-URL · link preview ·
   avatar/favicon-by-URL · PDF/screenshot/thumbnail rendering · document and media conversion ·
   feed and calendar subscriptions · SSO/OIDC/JWKS URLs · health checks and "test this integration"
   · anything that validates that a remote resource exists.
2. **Config that names a server** — mail (IMAP/SMTP/Sieve), notification servers, push endpoints,
   chat/XMPP, replication or mirror URLs, proxy settings, cluster webhooks.
3. **Anything that renders your text** (**S2**) — a class with no URL parameter to fuzz, and the
   source of several of the corpus's critical findings.
4. **Read the code when it exists.** If the target runs an open-source component, read its HTTP
   client construction, its allowlist, and above all its *error handling*. Source-reading is how the
   subtlest bugs here were found — though note it also produces plenty of low-severity findings, so
   it complements black-box probing rather than replacing it.
5. **Ask what the app trusts** — a third party's API response, a daemon the user can become, a
   redirect from a public host, a `Host` header. Each is user input laundered through something the
   developer considered internal.
6. **The URL is often not a query parameter.** It arrives as a GraphQL mutation variable, a
   protobuf message field, a nested JSON property, or a value the app *builds* from several fields.
   Read the schema/descriptor for anything typed as a URL, host, endpoint, callback or webhook —
   the crowd fuzzes `?url=` and stops there.

## 3. Determine the control surface — before you aim anywhere internal

Cheap probes, all pointed at **your own listener**, never at internal infrastructure.

- **Does it fetch at all?** Unique per-test token, always. Look for DNS *and* HTTP.
- **What is fetching?** The User-Agent names the library, and therefore its quirks. Leaked tracing
  headers may also name an internal service and route.
- **What does it accept?** Scheme, non-default port, path, query. What gets rewritten or rejected
  is the shape of the validator.
- **Does it follow redirects — and which ones?** The corpus datum is narrow but sharp: a client
  that otherwise did not follow redirects **did follow a 303**. So "redirects aren't followed" is a
  false negative until you've tried more than 302. Testing the other codes (301/307/308) is
  RFC-informed prudence rather than a corpus finding — no report here exercises them.
- **Does it re-resolve DNS?** Low-TTL record, count the queries. Leave ≥15 s between attempts and
  consider a CNAME chain — resolver caching makes a real bug look like a clean negative.
- **Does it fetch more than once?** Some sinks issue a HEAD then a GET. Probe each verb separately:
  a check applied to one says nothing about the other.
- **Where does the response go to live?** Before calling it blind, look for a log export, a delivery
  record, a stored file, a preview card, a rendered artifact, an error string. This question decides
  severity more than reach does.

## 4. Test → Confirm → Validate

**Two oracles, and the corpus prefers the second.** An out-of-band callback from the target's
egress is the cleanest proof when you can get one — but only about an eighth of the corpus used OOB
infrastructure at all. Most real findings were proven by a **response differential**: an error
string, a status code, a length, a timing gap. Reach for the callback first because it is
unambiguous; expect to fall back to **S4**, and don't read a silent listener as a negative.

**TEST — did something fetch it?** A DNS or HTTP hit on your unique token. **Outcome: a hypothesis.**

**CONFIRM — was it the target, from its network position?**
1. **Attribution is the confirmation, and it's harder than it looks.** Match the source IP against
   the target's known egress and read the User-Agent — but be careful in both directions: one
   corpus target's fetches arrived from **eight distinct cloud IPs inside nineteen seconds**, and
   link previewers, AV scanners and crawlers all fetch a submitted URL once. A hit alone proves
   nothing (**S7**).
2. **Reproducible** — fire twice with different tokens.
3. **Calibrate the oracle before trusting it — polarity is app-specific.** In the corpus, **HTTP 500
   meant "closed" in one app and "open" in another**. Timing was more consistent (closed fast, open
   slow or a gateway timeout) but the *shape* varied: sometimes a 504 from a fronting proxy,
   sometimes a hang. Establish a known-open and a known-closed baseline before reading anything into
   a response, or you will invert your results silently and not know it.
4. **No callback, or an empty result?** → **S4**. "Fetched but filtered to empty" is a real state,
   and so is "the fetch fires hours later".

**VALIDATE — the minimum that proves a trust boundary was crossed.** Reaching your own host proves
a fetch, not impact. What makes a report land is showing *what the sink can reach* and *what comes
back* — **S5** has the escalation ladder and the safe stopping points.

## 5. Safety and scope of testing

- **Bounded probing of the fetching host is legitimate, and is usually the finding.** For blind
  SSRF, enumerating a **short, named list of loopback/link-local ports** (22, 25, 80, 443, 3128,
  6379, 8080, 8443, 9200 …) is normal practice and is what turns "it fetched my URL" into a report
  with impact. Sequential, small, and stop when you have the answer.
- **Do not sweep the internal network.** Broad ranges, 65k-port scans and parallel workers against
  someone else's estate are a different act — noisy, disruptive, and a reliable way to get your IP
  blocked mid-assessment. If a wider sweep seems necessary, **ask the human first.**
- **Never retrieve credential material, and never use it.** **S5** carries two techniques that prove
  credentials are reachable *without* reading them — an existence differential on the credential
  path, and the absence of a platform failure notification. Both are stronger evidence than a pasted
  secret and keep the report on the right side of the line.
- **Never read other users' or the company's data** through the SSRF. Prove reach, not access.
- If the SSRF reaches something genuinely dangerous, **stop and tell the human.** Escalation is a
  decision, not a reflex.
- **Store the artifact**: the request, plus the callback log with **source IP, timestamp and your
  unique token** — or the response differential together with its control. **No artifact →
  HYPOTHESIS.**
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): the triggering request to **Burp
  Repeater**, or a copy-pasteable `curl` with the program's mandated header, plus the evidence
  alongside. Reproducible in one action from a clean session.
- Your listener is third-party infrastructure — don't route the target's internal data through it.

## 6. Log it

Every probe goes to `targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with `result`,
`coverage`, and the **`fix_locus` from §1** — the specific fetch call *and why the check failed*.
Two fetch sinks in one app are two findings. Log the negatives: "fetched, egress-filtered" and
"fetched, response filtered to empty" are real results worth not re-chasing. Novelty: **S9**.
