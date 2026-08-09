# SSRF — reference layer

> **Lookup, not reading.** Open a section when its trigger fires; don't read this end to end.
> The method lives in `../ssrf.md` — that one you read every time.
>
> Grounded in **128 cited reports out of a 219-report corpus** (`knowledge/reports/ssrf/`). `[#id]` =
> hackerone.com/reports/id. **Corpus bias:** skews web apps built on open-source components
> (GitLab, Nextcloud, Rocket.Chat, WordPress, Shopify) — which is *why* source-reading dominates the
> high-severity findings here. Thin on proprietary SaaS internals, and roughly a third of the fetched
> files are team-summary stubs with no technique. Reason from the model in `../ssrf.md` §1.

| § | trigger |
|---|---|
| **S1** | a validator, allowlist or blocklist stands in the way |
| **S2** | your text ends up inside something the server renders |
| **S3** | the fetch is asynchronous, stored, or fired by someone else |
| **S4** | no callback, or an empty result |
| **S5** | confirmed — what to reach, and how to stop safely |
| **S6** | non-HTTP schemes and host+port sinks |
| **S7** | attribution traps |
| **S8** | impact & chaining |
| **S9** | novelty, and hunting fixes |
| **S10** | worked examples |

---

## S1. A validator stands in the way

**Principle: the check and the fetch are different programs.** Different parsers, different
resolvers, sometimes different processes. Find the disagreement — or make the check *fail* rather
than *pass*.

### Make the defence error out (fail-open)
High-yield wherever a filter exists — though plenty of corpus targets had no filter at all.
- GitLab's `url_blocker` resolves the host, blocks private IPs and **pins the resolved IP** — but if
  resolution *raises*, pinning is skipped. A hostname that doesn't resolve at validation time and
  resolves to metadata at fetch time walks through [#632101]. The inverse of classic rebinding,
  which needs the first resolution to *succeed*.
- Ruby `Resolv.getaddresses` returned `[]` on some builds, so `ips.any? { private? }` was false;
  `0177.1` was one of the working payloads [#287245].
- **Some sinks issue more than one request** — a HEAD with a spoofed Chrome UA and a GET with a
  `Ruby` UA, i.e. two different clients on the same flow [#228377]. Whether both are validated is
  not established in the corpus; probe each verb separately rather than assuming.

### Redirects — the largest bypass family
The check covers URL #1; the redirect handler is an unvalidated code path.
- A plain `Location:` to metadata defeated an `https://`-only scheme check [#1108418], a port
  allowlist [#67389], and a `gopher://` scheme filter [#895696].
- **Status code matters**: a client that "in general … appears not to follow redirects" *did* follow
  a **303** [#508459] (302 was never tested there). That single datum is the whole corpus evidence —
  no report here exercises 301/307/308, so trying them is prudence, not a documented technique.
- A redirect can **inject credentials**: `Location: http://admin:admin@host:666` made cURL
  manufacture `Authorization: Basic …` at the internal host [#204513, #187520].
- No listener needed — a public shortener suffices [#3383079, #891270, #287496].

### Address representations
**Demonstrated against a live target:** `http://0:PORT/` and `http://0.0.0.0:PORT/` [#287496,
#288950, #178184] (also asserted in a CSRF write-up with no artifact, [#110801]) · `http://[::]:22/`, the IPv6 unspecified address, reaching anything bound
to `::` [#61312, #381129] · two-part octal/hex (`0177.1`, `0x7f.1`) rather than four octets [#215105,
#128685] · trailing dot [#1410214] · IPv4-mapped IPv6 as a dotted quad `[0:0:0:0:0:ffff:127.0.0.1]`
[#642675] (also [#736867] — but that PoC runs with **admin credentials** against a Nextcloud on the
reporter's own LAN).

**Established by source review or a lab harness, not against a live target — verify before relying
on them:** CGNAT `100.100.100.200` and the **hostname** `metadata.google.internal`, neither visible
to an IP-range filter (source review, rated low) [#1608039] · `[::ffff:0127.000.0.1]`, where curl
strips the leading zero and the validator doesn't (curl-CLI PoC against the reporter's own server)
[#2493548, not-applicable] · enclosed-alphanumeric digits and ideographic full stops, which make the string
not-an-IP so the guard short-circuits (tested against a dummy script the reporters wrote) [#1702864]
· non-`127.0.0.1` loopback via public hostnames, `127.0.0.2`/`127.0.0.6` (listed as candidates, no
artifact; closed **duplicate**) [#879803].

### Authority-parsing differentials
`http://trusted.example:80\@attacker.example/` — curl fetches the latter host while a WHATWG parser reports the former
[#704621, closed **informative**] · `http://<target>\@<allowed-host>` — the **allowed** host goes *after* the `@` to satisfy
a substring allowlist, and the backslash is the real differential [#1747596] ·
`https://1:@my.site:\@@@@w.youtube.com/@…` against a "must be youtube.com" check [#643622] ·
`undici.request({origin, pathname:"//127.0.0.1"})` — a *path* field replacing the origin [#1663788] ·
a port field concatenated then re-parsed, second parse wins [#423437] · `%0A` splitting the URL so
the fetcher takes only the pre-newline part while the allowlist saw the whole string [#514224].

### Below the URL layer
⚠️ **None of these three was demonstrated against a live target** — treat as leads, not techniques.
Hostname **truncation** at 256 chars before `getaddrinfo`, so validator and resolver see different
strings [#2429894 — found in a CTF, then filed as a library CVE] · **locale best-fit charset
mapping** — `http://¹²7.0.0.1` reaching 127.0.0.1 on CJK systems [#2552179, not-applicable; local
Python server] · the **host field used as a path segment** [#3366484, not-applicable; the PoC runs
the reporter's own simulated proxy].

### Path-append sinks
`#` truncates an appended suffix [#776017, #1189367] · a trailing `?` turns the suffix into a query
[#1628102] · `?` can smuggle parameters into someone else's request [#878779] · PATH_INFO satisfies
an extension check (`/index.php/test.png`) [#1364797], as does simply appending `/test.png`
[#1691501].

### The defence itself is a target
Stripe's Smokescreen egress proxy bypassed with **double brackets** `[[…]]` — only one set stripped
before matching [#1580495]. The `ssrf_filter` gem blocked `64:ff9b::/96` but not the NAT64 local-use
`64:ff9b:1::/48` [#3634400, Docker lab]. Reading a denylist constant and diffing it against the IANA
special-purpose registry is a cheap idea worth trying — but neither report describes doing that,
so it is a suggestion of mine, not an observed method.

### Trust laundering
The app allowlists a *host*, then trusts **the data that host returns**. A CI runner's docker client
followed redirects from a `dockerd` the attacker controls [#809248 — step 1 of that PoC is already
having code execution in the CI executor]. And an importer allowlisted a
third-party domain but took attachment URLs from that party's API response and downloaded them with
a redirect-following opener — argued as a trust-boundary flaw and simulated via `/etc/hosts` rather
than by compromising the third party, and accepted on that basis [#1092230].

## S2. Your text ends up inside something the server renders

**No URL parameter required, and several of the corpus's critical findings live here.** If user text
reaches a server-side renderer, the renderer is an HTTP client and your text is its instructions.

- HTML/JS injected into a **PDF generation** field, then the PDF re-opened to read IAM credentials
  off the page [#1628209]; the same through an HTML→PDF library [#2262382]; a **store screenshot**
  generator (rated medium) [#341876]; a logo/emblem editor [#347139, #265050].
- **The injection point can be an error message** that interpolates your input —
  `"Missing template for element: #{...}"` fed to the renderer [#2262382].
- **A headless browser is an interactive client, not one GET**: JS that port-scans localhost by
  iframe-load timing and reports results *into the screenshot* [#783392]; after DNS rebinding the
  page's own origin *becomes* the metadata service, so SOP no longer blocks reading responses
  [#530974] (authenticated). A CTF chain used XSS inside a PDF renderer to reach the browser's own
  debug interface and dump open tabs — plausible shape, but a CTF result, not a field one [#781295].
- **Format sniffing beats content-type checks**: `Content-Type: video/avi` with an m3u8 body, which
  ffmpeg parses by content [#115978]; an SVG uploaded as `x.png` [#223203]; `url(//attacker/…svg)`
  past a regex filter [#347139], with `<xi:include>` as an XXE alternative in the same renderer
  [#347139]; and separately, an SVG `fill="url(…)"` that **does not fire at all without a
  `#fragment`** [#265050].
- **FFmpeg/HLS**: `#EXTM3U` directives make libavformat fetch arbitrary URLs and `file://` paths —
  from an uploaded file [#237381, #1062888] or from a remote URL the service fetches [#115857];
  `concat:` chains [#115857, #1062888] and the `subfile,,start,N,end,M,,:` pseudo-protocol for
  line-by-line file reads [#1062888]. The tell is a `Lavf/…` User-Agent.
- **The renderer is a different container with its own cloud identity** — the credential you reach
  belongs to the converter, not the app [#671935, #530974]. Say so in the report.
- **A second fetch derived from the first**: an oEmbed flow validated URL #1, then parsed the returned
  HTML for `<link type="application/json+oembed" href=…>` and fetched *that* unchecked [#793704].
  Structurally distinct from redirect-follow, and it defeats redirect-aware validators. A later
  report is recorded as a bypass of that fix, mechanism not stated [#815084].

## S3. Blind, stored, and second-order

- **Stored then fetched later** — a webhook/integration/push endpoint saved now, used minutes or
  hours later [#3608558, #243277]; fired when *another user* replies to your topic [#3608558]; on a
  later render [#1628209, #341876]; on PVC creation rather than StorageClass creation [#776017];
  after upload *and* clicking Edit [#237381].
- **Retry the same action** — metadata was blocked on a CI job's first run and returned on an
  identical re-run [#369451]. A single-shot test is a false negative.
- **Staged validation** — the SMTP host is never contacted unless the IMAP credentials in the same
  request are valid first [#1746582]. Prerequisite acquisition is part of the test, not setup noise.
- Correlate by **token**, not timing, and keep the chain: the request that stored the URL, the token,
  and the callback log entry.

## S4. No callback, or an empty result

**A silent listener is not a negative.** Work down this list.

1. **Fetched but filtered to empty.** One sink required a 2xx, a human-readable Content-Type, a
   length under a cap, **and no `{` or `}` in the body** — so a JSON metadata document came back
   empty even though the fetch succeeded [#1108418]. The reporter's own counter-measure: a fixed
   prefix/suffix wrapper (`A{…}B`) that proves expansion happened even when the content is empty.
   (In that sink an unreachable host produced a *visible* marker instead, so empty and unreachable
   were distinguishable — its genuinely ambiguous case was a 3 s timeout blurring open, closed and
   filtered.)
2. **DNS hit, no HTTP hit** — egress filtered. Real, lower severity, and strong evidence the sink
   exists. Say exactly that. One target filtered outbound on exactly **one** port out of 65535
   [#223203], and blocked metadata didn't stop a report being accepted on internal reach alone
   [#689245].
3. **Caching and timing make real bugs look dead** — resolver caching needs ≥15 s between attempts
   and sometimes a CNAME chain [#632101]; a rebinding flip needed a 3-minute wait [#530974]; a
   renderer screenshotted before the redirect fired [#783392]; an endpoint intermittently hung and
   needed reloading [#1960765]; a webhook fired hours later [#243277].
4. **Byte-exact payloads** — an exploit failed until the reporter found his editor had appended
   `\r\n`; check with `hexdump -C` [#1062888].
5. **Locale/OS dependence** — a payload that works only on CJK systems is silently correct elsewhere
   [#2552179, not-applicable].

**Then build a differential oracle — this is how most blind SSRF here was actually proven:**

- **Error strings that name the service.** A raw SSH banner inside a JSON validation error [#158016];
  distinct parse-failure text per protocol (`Unknown mime-type: text/html` for HTTP vs `A valid
  response status line was not found` for MySQL) [#243865]; an internal nginx 404 body pasted into a
  webhook result panel [#301924]; cURL error *names* — `CURLE_RECV_ERROR` = open non-HTTP,
  `CURLE_COULDNT_CONNECT` and `CURLE_OPERATION_TIMEDOUT` both = closed [#50537, informative]; XML-RPC
  `faultCode` 17 vs 16 [#406387]; a three-way UI differential separating wrong-subnet / host-absent /
  port-closed [#222667, informative; admin settings on a public demo instance]; `Invalid url … (404)` vs `Connection timed out`, distinguishing **reachable
  from firewalled** [#643622]; banners printed by an admin settings page [#1018568].
- **Status and length** — `Content-Length: 0` vs `114` [#738553]; a path-existence oracle in a card
  validator's "no metatags found" [#178184]. (A length>3000 oracle also appears, but in a report
  closed **informative** whose own port results look self-contradictory [#2015554].)
- **Timing — consistent direction in the three targets that recorded it**, though the shape varies.
  Where timings exist, **closed is fast and open is slow**: open ≈ 5200 ms vs closed < 100 ms [#1736390, and the same reporter's sibling
  finding #1741525]; closed 450 ms vs open 10,468 ms [#514224]; closed = a fast 200 in 163 ms while
  open = a **504 from the fronting proxy** [#895696], and open = a gateway timeout [#16571]. Note the
  first two figures come from one reporter scanning **his own self-hosted instance**. And a
  drop-filtered port is slow *and* closed, so the direction is a heuristic, not a law — an aggressive
  client timeout will also read "open" as a failure.
- **Status-code polarity is NOT reliable — calibrate it.** `500` meant **closed** in one app
  [#61312, where open was a 302] and **open** in another [#67389, where closed was a 422]. Always
  establish a known-open and a known-closed baseline before reading a status code as a signal.
- **Absence of a signal.** A platform emails you when a webhook fails; `http://localhost` produced a
  failure email and `169.254.169.254` produced **none** — reachability proven without reading
  anything [#243277].
- **Turn the verbosity on yourself** — a "download log / include HTTP / plain text" export on a
  test-run feature returned the whole upstream request *and* response [#1628102], the best exemplar
  in the corpus. Raising a service's own log level does the same where you control the deployment
  (demonstrated on the reporter's own cluster; applicability to a managed one was their hypothesis)
  [#941178].
- **Where the response goes to live**: a stored integration message [#1055823], k8s events and
  controller logs [#776017], a saved non-HTML file [#50537, informative], a preview card [#3393664] and
  specifically its `og:title` [#1960765], `Content-Disposition: attachment` [#2300358], a screenshot
  [#783392], a downloadable asset [#1364797], a created issue [#1092230], a rendered emblem
  [#347139].

## S5. Confirmed — what to reach, and how to stop safely

**Escalate in this order, stopping at the first thing that proves a trust boundary was crossed:**

1. **A short, named list of loopback/link-local ports** on the fetching host — banner or behaviour
   classification. This is the whole demonstrated impact in a large share of blind-SSRF reports
   [#514224, #386292; also #145524 (informative), #1018568 and #1741525 — the last three on the
   reporter's own instance, and two needing admin].
   Note that in several corpus reports the "scan" was aimed at an **external** host the reporter
   controlled [#67389, #1300585] — a legitimate way to establish behaviour before touching loopback.
2. **An internal-only hostname or management port answering**, with the banner as evidence.
3. **Cloud metadata — reachability, evidenced without reading secrets.** Two techniques:
   - **Existence differential**: `/latest/meta-data/iam/security-credentials/` returned an empty body
     while a deliberately misspelled sibling returned `Unable to retrieve …` — proving the credential
     path exists without fetching a key [#514224].
   - **Absence of a failure notification** [#243277].

**Metadata specifics.** GCP `computeMetadata/**v1beta1**/` needs **no** `Metadata-Flavor` header
[#341876] — header-less SSRF is not automatically harmless there. Where a header *is* required, a
sink that also lets you set request headers would defeat it (raised as impact in [#826361], not
demonstrated). Credential paths differ: one report used
`identity-credentials/ec2/security-credentials/ec2-instance` under a dated prefix, **not**
`iam/security-credentials/` [#1624140] — a listing without `iam/` doesn't mean no credentials.
Non-AWS: DigitalOcean `/metadata/v1.json` [#369451, #541169], Alibaba `100.100.100.200` (surfaced by
source review [#1608039]; observed **blocked** — but in the reporter's own dummy PHP harness, not a
live test [#1702864]), and
`https://kubernetes.default.svc/livez?verbose` when the sink is HTTPS-only [#1115139]. GCP's metadata
proxy rejected a hostname-based request outright in one target — hardened environments exist and the
finding was rated low [#382612].

**A root listing alone is often *not* enough impact** — one report obtained it and could go no
further because the instance had no role attached, and said so plainly [#1108418]; another hit a
hardened metadata proxy and was rated low [#382612]. Make the impact argument in prose, backed by the
existence differential.

**The limits:** never fetch or use credential material · never sweep the internal network (one
reporter was IP-blocked mid-assessment [#128685]) · never read other people's data · stop and ask
before anything wider. Reporters who stopped explicitly and said why were still taken seriously —
including at critical [#3165242, #2262382] and at lower ratings where the reach itself was the
limit [#514224 low, #1108418 medium]. Stopping cost them nothing; the severity tracked what was
demonstrably reachable.

## S6. Non-HTTP schemes and host+port sinks

**Config fields that name a server** — no `url` parameter to fuzz, though the fetch itself may be
plain HTTP: Apache Solr `masterUrl` [#1183472] · Kafka Connect connector config [#1547877] ·
Kubernetes `ValidatingWebhookConfiguration.clientConfig.url`, fetched by the **kube-apiserver**
[#941178] · StorageClass `resturl`, fetched by the **vendor's control plane** [#776017] · Phabricator
`notification.servers` JSON [#850114] · Web Push `endpoint`, a **blind POST** carrying a body and an
`Authorization: WebPush` JWT [#3608558] (a related report asserts the outbound push carries
`Crypto-Key`/`Authorization`, without showing the request [#411865]).

**Sinks that aren't HTTP at all** — separate host and port fields speaking another protocol:
IMAP/SMTP settings plus a "send test email" [#222667, informative, #1746582] · ManageSieve, requiring
`sslMode: none` [#1741525] · Jabber/XMPP in an admin panel [#1018568] · `git://` repository
mirroring, which sat outside the HTTP blocker [#441090].

**Schemes observed reaching something:** `file://` [#1189367, #826097] · `gopher://` for line
protocols, reached via a redirect when the parameter itself filters it [#115748, #895696, #811136] ·
`dict://`, `sftp://`, `pop3`, `telnet` [#115748] · `ftp://` [#115748, #223203] · `tftp://` for
arbitrary **UDP** [#115748] · **UNC/SMB `//host/path`** leaking NTLMv2 hashes [#288353] (raised as
*potential* elsewhere [#2585385]) · plain absolute-URI proxying with no `Host` header [#207477] · an
injected git `http.<url>.proxy` setting, demonstrated with an HTTP proxy and speculatively extendable
to SOCKS [#855276] · `ipfs://` path traversal, demonstrated against the reporter's own simulated
proxy rather than a live gateway [#3366484, not-applicable].

**Counter-evidence worth heeding:** one target accepted **only** `http://` and `ftp://` — every other
scheme on the reporter's list failed [#223203]. Enumerate schemes; don't assume the list transfers.

Gopher payloads in one report were **double URL-encoded** to deliver real CRLFs through a redirect
[#895696]. **Do not send state-changing commands** to an internal service: proving the connection is
accepted is the finding.

## S7. Attribution traps

- **The fetcher may not be the target.** A chatbox that fetches a pasted URL may be a link
  previewer rather than the application; one such report was self-rated low by the reporter
  [#1023920 — note the report itself contains no attribution analysis, so treat this as the
  *question* to ask, not a documented case]. A "SSRF" that is really a
  `fetch()` from the victim's browser is XSS mislabelled [#996273]. One callback turned out to be
  `ggpht.com GoogleImageProxy` [#236301]. And a `Referer:` reflected by a static file is nothing at
  all [#1712240, closed **not-applicable** — as it should have been].
- **But source IP is unreliable in the other direction too** — one target's fetches arrived from
  **eight distinct cloud IPs inside nineteen seconds** [#91816, informative]. Corroborate with the User-Agent and
  a reproducible token.
- **"It's an intended proxy" is not automatically a dismissal.** SSRF on a declared-out-of-scope
  image proxy was filed anyway and rated **critical** for what it reached [#395521]; a sibling report
  on the same proxy was rated high [#358119]. The question isn't "is this a proxy" but "what can it
  reach".
- **Useful attributions:** WHOIS/ASN of the callback source [#1057531 (informative), #310036]; leaked tracing
  headers naming an internal service *and its route* [#1832494]; the User-Agent naming the client
  library, which tells you which parser quirks to try [#446593]; the request *path* identifying the
  client where no UA is present — `/info/refs?service=git-upload-pack` means the fetcher is git
  [#191216, duplicate]. An `X-Forwarded-For` on the inbound hit suggests a fronting proxy, though whether the
  address is the target's egress NAT needs corroboration [#2932960].
- **A hard error response does not mean no request** — HTTP 422 "the uploaded image is corrupt" came
  *after* the outbound fetch [#223203].

## S8. Impact & chaining

- **The impact is the sink's network position**, and the **exfil channel decides severity**: the same
  reach was Low as a blind port scan and High once the response came back in an `og:title` [#1741525
  vs #1960765].
- **Credential exfiltration outward** — the outbound request carries the *server's* secrets to your
  listener. The clearest mechanism: control-plane clients following your redirect while sending their
  own `Authorization: Bearer` tokens [#1544133 — though reaching it needs the ability to deploy into
  `kube-system` and hijack an aggregated API server]. Also an edge proxy that replayed cookies and injected
  its own `Authorization: Basic` [#310036], and an OAuth `client_secret` reaching the attacker
  (severity `none`; the reporter judged the preconditions unlikely) [#423437]. **Read the headers
  that arrive**, not just the fact that something arrived.
- **Chains that landed:** SSRF → localhost Jolokia/JMX → agent load → reverse shell [#1547877] ·
  `git://` + CRLF → Redis → Sidekiq deserialization → RCE [#441090] · headless Chrome + rebinding →
  GCP SSH keys and service-account tokens [#530974] · LibreOffice thumbnailer → the converter
  container's AWS credential [#671935] · external proxy → internal renderer → `file://` → the file
  rendered into a returned PNG [#826097] · SVG → ImageMagick → XXE/XInclude file read into the output
  image, or UNC → NTLMv2 hash [#347139, #288353] · full-read proxy → reflected XSS by proxying HTML
  [#1540906] · fetch-and-store → internal `phpinfo()` downloaded as an asset [#1364797].
- **A signed proxy is worth checking for signature verification at all** — one ignored its own
  integrity keys and combined that with a large server-request timeout and no `Content-*` checks,
  raised as a *potential* DoS [#180527].

## S9. Novelty, and hunting fixes

**Hunting the fix is the highest-yield move in this corpus.** Reports that explicitly break a prior
fix: an IP blocklist added but redirects still followed [#891270]; IPv4-mapped IPv6 past a patched
filter [#642675]; a fix reverted [#178184]; a payload past two prior public fixes on the same sink
[#381129]; the same bug reappearing in a successor product [#409701]; a `git://` path outside the
UrlBlocker introduced to fix an earlier SSRF [#441090]; a second-fetch bypass whose mechanism the
report doesn't state [#815084]; a reporter-suspected regression [#223203]; a second finding in a
series against the same library [#3634400]. And when a vulnerable feature is *removed*, ask what
replaced it — Jabber SSRF was deleted and Web Push introduced the same class, now reachable by an
ordinary registered user rather than an admin [#3608558].

**Enumerate every integration separately.** In one product, three distinct import/integration paths
were each independently reachable — a project importer [#709951, duplicate], a third-party integration via
redirect [#446593] — and separately its CI runner could reach metadata with no URL validator in the
picture at all, an egress-control gap rather than a validator gap [#369451]. Central guards are the
exception.

Novelty lives in: renderer/format sinks (**S2**) · non-URL host+port config (**S6**) · second-order
and deferred fetches (**S3**) · the *fetching client's* own parsing and resolution bugs — a lead
worth pursuing, but note every report behind it was **declined**: URL parser
differentials [#704621 (informative), #2814750 (not-applicable)] and `getaddrinfo` hostname truncation in the event-loop library
[#2429894] · the SSRF defence itself [#1580495, #3634400] · vendored third-party demo scripts under
`/vendor/`, unauthenticated [#1595006] · framework auto-routed controller arguments [#895696] ·
known-CVE default endpoints of deployed products [#326040, #300513, #1379080, #482634] — worth
fingerprinting for, though these reports don't record how the host was found.

Log `fix_locus` as the specific fetch call *and* the reason the check failed — "follows redirects
after validating URL #1" and "fails open when resolution raises" are different fixes.

## S10. Worked examples

**A. Full-URL control, synchronous.** *Model:* source = a `url` field, feed = validator then an HTTP
client, sink = the app server, control surface = full URL. *Probe:* unique token → DNS+HTTP hit; then
serve **each of 301/302/303/307/308** — one may be followed when the others aren't [#508459].
*Confirm:* source IP matches the target's egress; reproduce with a second token. *Validate:* a short
named-port probe on loopback, then the metadata existence differential [#514224]. *fix_locus =*
"validates the submitted URL only; follows redirects."

**B. Host+port config, blind.** A mail or notification settings form with a "test" button. *Model:*
control surface is host+port, the protocol isn't HTTP, and the sink may require valid credentials for
an *earlier* stage before it contacts your host [#1746582]. *Oracle:* calibrate first — open vs
closed may be 5 s vs 100 ms, or a 504 vs a fast 200 [#1736390, #895696]. *Validate:* the banner from
the error string [#1018568]. *fix_locus =* the connection call in the settings handler.

**C. Renderer, no URL parameter.** A PDF or screenshot export of content you author. *Model:* source =
your text — including anything that lands in an error message [#2262382]; feed = a headless renderer;
sink = the renderer's HTTP client with its own cloud identity [#671935]. *Test:* reference your
unique-token host inside the document. *Better oracle:* if the fetched content appears **in the
produced artifact**, you have a full read channel — use it instead of a callback [#1628209, #341876].
*fix_locus =* "renderer resolves external references", a different fix from any URL allowlist.
