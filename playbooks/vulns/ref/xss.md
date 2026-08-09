# XSS — reference layer

> **Lookup, not reading.** Open a section when its trigger fires. The method lives in `../xss.md`.
>
> ⚠️ **Deliberate sampling cap — read this first.** The XSS corpus holds **1,756 cached reports**.
> This layer is grounded in a **deterministic sample of 150** — 50 per search bucket for *reflected*,
> *stored* and *DOM*, ranked by **total rendered page length (writeup plus comment thread)**. Three
> consequences, all verified:
> - It is **not** a survey of XSS. Any statement here about what is "common" is a statement about
>   150 long reports, and the ranking biases toward bugs with **long triage discussions** —
>   complex, chained, contested — and away from routine ones.
> - The buckets are **keyword search buckets, not weakness classifications**. By the reports' own
>   `weakness` field the 150 break down as 43 stored / 41 reflected / 30 DOM / 22 generic-XSS and
>   **13 that are not XSS at all**. The "DOM" bucket is only 29/50 genuinely DOM.
> - All 150 were `resolved` — though so is 94% of the whole corpus, so that filter selected for
>   very little.
>
> `[#id]` = hackerone.com/reports/id.
>
> ⚠️ **Access:** many findings need a self-hosted instance, an admin role, a paid tier, a specific
> browser, or a feature toggle. Flagged where known — check the report before treating a technique
> as ordinarily reachable.

| § | trigger |
|---|---|
| **X1** | it reflects but you can't deliver it |
| **X2** | it's stored and you can't see it render |
| **X3** | DOM — sources, sinks, and the trust check |
| **X4** | contexts & encoding failures |
| **X5** | filter / WAF / sanitizer bypasses |
| **X6** | CSP |
| **X7** | proving execution; the artifact problem |
| **X8** | false negatives |
| **X9** | safety & ethics — what this corpus normalises |
| **X10** | novelty |
| **X11** | worked examples |

---

## X1. Delivery — the reflected-XSS bottleneck

**"Self-XSS is not a finding" is the most-refuted rule in this corpus.** Counted across the
50-report reflected slice: **~40% are POST-only reflections**, and **~24% are explicitly rescued by a
missing CSRF token**; a further ~16% are POST reflections the programs simply accepted with no
delivery story at all. (Plain GET-URL reflection is still the single most common shape, at roughly
half.) The correct rule: *self-XSS* means the victim must paste it into their own session; anything
you can drive is a finding.

**Delivery primitives observed:**
- **Cross-site POST from an attacker page** — the most common *deliverable* shape. Genuinely
  auto-submitting (`document.forms[0].submit()`, about half of them adding
  `history.pushState('', '', '/')` to hide the origin): [#3284389, #3284381, #3137200, #1446236,
  #2750977 — note this one is in the DOM slice]. Click-required variants: [#1109544, #177508,
  #1147949], and an XHR-driven CSRF rather than a form post [#95089]. Note a `token` field in the
  form is not necessarily CSRF protection — one PoC hardcoded it and still worked [#1147949].
- **Clickjacking a framable page** [#1149144, #953579, #463915], including a **drag-and-drop**
  variant [#341969 — a proof-of-concept on the reporter's own site, whose own conclusion is that
  nobody would fall for it]. Asserted but not demonstrated in [#1420529].
- **Login-CSRF / cookie stuffing** — log the victim into *the attacker's* account so the attacker's
  stored payload becomes "theirs" [#632017, #422043]. A related move is **cookie tossing** — scoping
  the attacker's session cookie to one path so only that path runs as the attacker; note it needed a
  pre-existing XSS on a sibling subdomain [#3594137].
- **Clipboard** — `navigator.clipboard.writeText()` plus paste bait [#892289], or an attacker page
  setting a custom clipboard MIME type the target's paste handler trusts [#1196958].
- **A delegation feature** — shared access / "act as" lets you write into the victim's own store
  [#1049012].
- **A server-side routing flaw** that delivers your response into another user's stream — turning an
  unreachable reflection into zero-click cross-user [#259100]. Read the caveat there: it is zero-click
  against a *guessed* user, the reporter calls the required channel name a "strong premise" and puts
  the space at ~10^19, and the report is rated low.

**Entry points that aren't the value:** a multipart field **name** [#95089], a JSON property name in
a document the page renders [#418823], a prototype key `?__proto__.innerHTML=` [#986386], a URL
**path segment** [#232320, #716761, #1446236, #47235], an empty **array index** the UI never
populates (`goal[1][Costs]`) [#2353185], framework hidden fields [#499041, #3127147, #3127154],
hidden fields that configure the response page [#3137200], `X-Forwarded-Host` [#882220], and a
`SAMLResponse` body [#1247833].

**Where the reflection hides:** the **error branch** — only on a duplicate-email re-render
[#1814335], an "Unknown field" exception [#177943], a `NumberFormatException` [#232320], a 404 page
[#629745, #716761], a mobile-only OAuth failure renderer [#1216203]. Exception and stack-trace
renderers sit *outside* the view layer's escaping.

**Other high-yield moves:** read the bundle for params the UI never sends [#1518343, #1082847] ·
the app fetches a document **from a path you can traverse** [#125791], or simply **from a host you
supply** [#418823, #1149144], then renders fields out of it · the same app on a **second hostname
with no WAF** [#1850235] · version-fingerprint an embedded component, then locate the input yourself
[#380354, #418823, #3135626] · vendored `examples/` present in the **release artifact** but deleted
from git [#192786] · re-test a fixed report [#716761, a deliberate bypass of #629745] (and watch for
regressions others merely notice [#1147949]).

## X2. Stored — enumerate the consumers

**The heart of stored XSS, and what a one-request model misses entirely: one stored value has N
consuming surfaces, and they encode inconsistently.** The clearest instance literally tabulates five
consumers against an "escaping" column [#3779690]; others diff two or three surfaces [#1083734,
#328210, #247517]. Related: one endpoint sets a protective header and its sibling sets none
[#3594137, #949513].

**Render surfaces that are not the page you injected into:** an HTML **export** opened from `file://`
[#3779690] · a **GDPR/ZIP download** produced by a cron minutes later [#3779690] · an **admin
approval email** opened in a mobile webview [#382666] · a **toast built from an API error string**
[#1132202] · an **admin statistics report** absent from the default menu, which the reporter enabled manually [#3400506] · the **Reply form's
textarea** while the inbox view is safe [#247517] · an **audit-log row** in the admin dashboard
[#127948] · an **autocomplete dropdown** inside an editor [#1578400] · the **MR-creation reviewers
dropdown** [#1342009] · an **inbox preview snippet** [#487081] · a third party's map attribution
[#54327] · a first-party widget rendering for a **different user** [#1083734].

**Why it survived storage:** sanitizer on render but not store (or the reverse) · a **post-sanitization
transform** that re-opens it — a `rel=` rewriter matching inside a `title` [#509930], a serializer
that JSON-parses attributes and `setAttribute`s them back past DOMPurify [#3581911], a redactor that
decodes entities a second time [#836649] — which also chains onto a filename breaking out of an
interpolated `href` [#1212067] — `textContent` decoding a sanitizer's own output
[#65284] · an **import path** writing straight into the post-sanitization column, with a magic
`cached_markdown_version` to stop regeneration [#508184]; and an import that smuggles a value past
the UI's validation [#1693150] · a **type-discriminated
renderer** where only the primary field is escaped [#1379400] · **two parsers composed** — combining an autolinker and Markdown to break out of the current HTML
attribute [#735638] · an **alternate markup engine** (RDoc, not Markdown) whose allowlist permits enough attributes for a
click-intercepting overlay and a fake login modal — note that one is classified as UI redressing and
achieves no script execution [#662287].

**Renders only for a different principal.** One bug fires only on the redaction path, which runs
only for viewers who **lack** permission to read the referenced object [#836649]; another states the
property outright — *"you will not see the alert if you are the person who can access the confidential
issue"* [#2257080]. A single-account test misses these: you need a second account that lacks access.

**The store isn't always the database:** a cookie set cross-origin by a sibling endpoint [#534450] ·
`localStorage` written by the site's own JS [#297968] · a remote page's `og:site_name` consumed by
whoever unfurls it [#309367] · unprotected post meta [#402753] · a **filename** [#1212067] ·
an uploaded file's **body** served with a renderable content type [#949513, #3594137, #3115705,
#231524] · a filesystem directory name [#328210] · a `Referer` laundered through a redirect
[#127948] · a third party's OIDC discovery JSON [#1687410] · a claimed abandoned S3 bucket [#1598347].

**Mass-render objects are worth finding:** an imported smiley pack that renders in every post and
admin page [#2168002], and a shortcode any author can drop in any post [#402753].

## X3. DOM — sources, sinks, and the trust check

**The trust check between source and sink is more often the bug than the sink.** For `postMessage`,
model `event.origin` as a parser and diff it: no check at all [#231053, #691977, #207042, #398054,
#463915, #894518, #1758132]; substring/`indexOf` matching [#381192, #387544]; a *correct* check whose
allowlisted origin is itself XSS-able [#2371019]; a check pinned to the currently logged-in tenant,
which the attacker can make be their own [#422043].

**Sinks beyond `innerHTML`:** a `javascript:` URL assigned to `location.href` [#398054, #422043,
#1238528], an `<a href>` later clicked [#463915, #1184379], an `iframe.src` [#1887917], `window.open`
[#217745] — **note `window.open("javascript:…")` scripts the opener; a new tab is not an escape
hatch**. Also: a template compiler reached via a data-binding attribute [#217790], `Reveal[data.method]`
dispatch [#691977], `$.ajax` options with attacker-set `dataType:"jsonp"` [#207042], `$.get` with no
`dataType` [#88719], jQuery `$()`/`parseHTML` [#241619], a native HTML-like UI framework's
`html="true"` label [#631956], and Android `WebView.loadDataWithBaseURL` [#1455987].

**The sanitizer as the sink:** html-janitor's `clean()` sets `innerHTML` on a live `div`, so the
payload fires *during* sanitization [#308155]; a recursive escaper whose recursion guard is an
attacker-settable property [#246794]; a "safe eval" escaped to the real `Function` constructor
[#809012]; a DOMPurify config that misses one framework attribute [#1579645] or allows
`svg`/`use`/`xlink:href` [#831962].

**Prototype pollution plus a gadget in the same bundle** — `deparam(location.hash)` pollutes, and the
same file has `eval(hookFunction)`; the whole exploit is
`#__proto__[asd]=alert(document.domain)` [#998398]. A source→sink dataflow model never finds this.

**Other routes:** client-side path traversal into an asset loader, plus an open redirect [#1245165] ·
frame-jumping by index when the frame name is randomised [#207042] · a child frame copying the
parent's URL *including fragment* into `window.name` [#1567186] · cookie-value → HTML reflection with
a separate primitive to write the cookie, aided by a server that splits `Cookie` on spaces
[#2010530] · ads, extensions and AV products executing in your origin [#889041, #220494, #463915].

## X4. Contexts & encoding failures

- **`<script>` string literal** — `</script>` inside the string ends the element; the HTML parser
  beats JS quoting [#147196, #935503]. A JSON response the client `eval`s counts too [#259100].
- **RCDATA** — `<title>`, `<textarea>`: raw `<script>` never executes, you must close the host
  element first [#1073780, #177508, #3284381, #3284389].
- **Quoted attribute** — break out, or stay inside and add a handler. Where tag injection is
  impossible, `strip_tags()` leaves `" onfocus=… autofocus="true"` intact [#230029].
- **URL-valued attributes** — no encoding question at all; the only defence is a **scheme
  allowlist**, and its absence is a whole family [#409850, #684268, #1194254, #1887917, #1184379].
- **`<noscript>`** — the same value encoded in one copy and raw in the `<noscript>` copy; the
  differential is verbatim, the reason is not stated [#534450].
- **Template *source*** — input interpolated into the template text, so `\x3cscript\x3e` is inert to
  the HTML escaper and decoded later by the JS engine [#317125].
- **A JS-binding attribute** — lodash HTML-escapes but doesn't JSON-escape into `data-define`, which
  twine runs through `new Function`; `'-alert(document.domain)-'` never leaves the attribute
  [#217790].
- **Response headers as the context** — an upload served `inline`/`text/html` *is* the document; no
  HTML sanitizer is involved [#949513, #3594137, #3115705, #231524].
- **Parser differentials / mXSS** — backend Nokogiri **HTML4** parsing versus the browser's HTML5
  parser, with the payload hidden in `<style>` inside `<svg>` so the browser hoists it out [#2257080];
  a config value coerced to the truthy string `"false"`, which the reporter states outright
  [#1212822]. (A CDATA payload also appears in [#988272], but that report contains no parser analysis
  and its own repro shows CSP blocking the handler.)
- **The wrong encoder entirely** — backslash-style escaping applied to an HTML attribute, so `<`
  and `>` pass untouched [#374100; the mechanism is read off the output, not named in the report].
- **Partial encoding in one response** — one reflection encoded, another raw [#232320, #328210,
  #1083734].

## X5. Bypasses

- **Uppercasing input** → letter-free JS: JSFuck [#1420529], or octal-escaped
  `[]["\146\151\154\164\145\162"]["\143\157\156\163\164\162\165\143\164\157\162"]("\141\154\145\162\164\50\61\51")()`
  [#1167034].
- **Double URL-encoding** past a WAF that blocks `"` — `%2522` [#629745]; and past a filter *for*
  double-encoding, by inserting a byte above `%7f` [#716761].
- **`accesskey='x' onclick='…'`** to give a non-interactive element an activation — demonstrated on
  an injected `<link rel="canonical">` [#629745]; the same technique is used without showing the host
  element in [#716761, #1850235].
- **Backticks instead of parentheses** — `alert\`XSS\`` [#2888784], `print\`\`` [#3284381].
- **Separator and case tricks.** `<ScRipT x>` past a 403 on `<script>` is the one demonstrated
  filter bypass here [#859342]. Slash-as-separator [#3284381, #2444032, #1446236], form feed `%0c`
  [#2741110] and mixed case [#374100] appear as payload style in reports that name no filter — useful
  syntax to know, not evidenced bypasses.
- **Unlisted event names** — `onwebkitplaybacktargetavailabilitychanged` past an event-handler
  signature list [#3135626]; runtime-built `eval` name past a signature [#3135626].
- **Substring-not-prefix URL allowlists** — `javascript:alert(…)//https://allowed.example/`
  [#1518343]; a `Partial<{…}>` schema missing live keys [#1082847].
- **Sanitizer allowlist gaps** — `data-disable-with`, which rails-ujs later writes as HTML
  [#1579645]; `<svg><use xlink:href=…>` pulling an external SVG containing `foreignObject > iframe
  srcdoc` [#831962]; `data-trix-*` smuggled through DOMPurify [#3581911]; an allowlist permitting `class` on an
  anchor, enough for a full-page click hijack — and separately in the same report a fake login modal
  built from the app's own CSS framework [#662287].
- **Attacker-settable guard state** — `"stripping": false` disables a recursive escaper [#246794].
- **Selector-escape gaps** — a regex escaping quotes and `=` but not `\` yields a jQuery selector
  matching everything [#396493].
- **A short length limit** beaten by an external `<script src>` [#472391] or by
  `eval(\`'\`+URL)` with the rest of the payload after `#` [#921635].
- **Cookie-parser differential** — the backend splits `Cookie` on spaces, so one `?canary=` value
  smuggles a second cookie, plus `Max-Age` for persistence [#2010530].
- **Cookie precedence** — a longer `path` outranks the victim's cookie on that path [#422043].
- **Go around the filter** — the same app on a hostname with no WAF [#1850235], or the origin host
  behind the CDN [#168165].
- **Origin-check bypasses** — `iframe.src.indexOf(origin)` accepts `https://foo.my` [#381192,
  #387544]; `a.href="javascript://google.com/%0aalert(document.domain);//"` makes `a.host === "google.com"` —
  Safari only, explicitly stated [#1238528]; an in-place escaper skipped via a non-own property, e.g.
  `new File([""], "<img src=xx: onerror=…>")` [#231053].

## X6. CSP

**CSP is per-endpoint, not per-site — check the header on the exact vulnerable path.** A plain PHP
file that bypasses the framework's response pipeline emits none [#1893186]; an OIDC endpoint carried
its own `default-src 'none'` [#1687410]; Rails emitted no CSP on the SVG response [#949513]; one attachment endpoint sets `script-src 'none'` and its sibling sets nothing
[#3594137]; the generated HTML export carries no CSP meta tag at all [#3779690], and none is visible in the
mail-webview case either [#382666, inferred from the dumped DOM rather than stated].

**Gadgets beat allowlists**, and stored XSS gets gadgets reflected XSS doesn't, because the app hosts
attacker-writable same-origin files: a **CI job artifact** served as `application/javascript`
[#1342009, #1212822, #831962]; a media upload — noted there as a *requirement* the reporter did not demonstrate [#472391]; `<base href>` when `base-uri` is unset, then
recreate the chunk names DevTools reports as 404s [#1481207, #1256777]; a CDN in `script-src` that
hosts a templating framework [#986386]; JSONP with `callback=setTimeout` [#1212067]; rails-ujs
`data-remote` [#836649]; the app's own JS re-rendering an attribute as HTML [#1693150 — mechanism inferred; the report
doesn't analyse it].

**When CSP genuinely blocks script, switch the question to what markup alone achieves** — an
off-origin `<form>` where `form-action` is unset [#605915], a `<meta http-equiv=refresh>` which no
CSP directive covers [#1880896], a `<button formaction>` inside the real authenticated form
inheriting session and CSRF token [#3608199], a full-viewport transparent submit control [#1579645].
Several such reports were accepted with no JS execution at all [#662287 (high), #988272, #1687410,
#472391]. CSP is also simply absent from most of this sample's discussion — only 6 of the 50 DOM-bucket
reports mention it at all.

## X7. Proving execution; the artifact problem

- **Prove the origin**, not just that something ran: `alert(document.domain)` over `alert(1)`
  [#1149144, #1216203, #986386, #1073780].
- **When cookies are `HttpOnly`, pivot to a same-origin action** — scrape the CSRF token and perform
  one privileged request [#472391, #684268, #735638, #3608199]. That is a stronger proof than a
  cookie you couldn't steal.
- **For DOM bugs nothing may hit the server.** What reporters actually attached: the prettified sink
  line with file and line number; a **stack trace** showing source read and sink write [#241619,
  #889041]; a self-contained attacker page [#1758132, #894518]; a console one-liner as a *harness*
  [#422043]; a reproducible lab with `/etc/hosts` instructions for origin-check bugs [#387544,
  #463915]; and best of all, a **server-visible consequence** — the Rails log line and the resulting
  email that the injected form caused [#3608199].
- **State the activation and the browser.** Middle-click, hover, `accesskey`, "reload with DevTools
  open", "Safari only" [#2509022, #629745, #3135626, #1194254, #241619].
- **Blind XSS**: the callback dump *is* the artifact — URL, referer, UA, cookies, serialized DOM
  [#1091118].
- **Declare your ceiling.** Reports were accepted saying plainly "CSP blocks this", "currently not
  exploitable", or "I could not bypass CSP so here is the phishing impact" [#988272, #472391,
  #1687410, #297968, #605915].

## X8. False negatives

- **`<script>` inside `<title>`/`<textarea>` never executes** — close the host element first
  [#1073780].
- **Only one quote type is filtered** — test `'` and `"` independently [#380354].
- **Uppercasing looks like sanitization** [#1420529, #1167034].
- **One decode too many** — only `%2522` reaches the sink [#629745].
- **Only some array indices reflect** — the row the UI leaves blank [#2353185].
- **The sink is behind a flag, a role, a feature toggle, or an error state** [#1216203, #1518343,
  #935503, #1731349, #509930, #487081, #3779690, #1887917, #1184379].
- **First submission doesn't reflect; the duplicate/error re-render does** [#1814335].
- **Renders only for a lower-privileged viewer** [#836649], only in the export [#3779690], only in a
  particular mail client [#382666], only after a second data condition exists [#3400506], only on
  create and not on edit [#1342009], only in a JS widget you must interact with [#1578400].
- **The public page is escaped and the admin/back-office page is not** [#230029].
- **`<img src="data:…svg">` looks inert** until you open it in a new tab [#1276742].
- **Browser-gated** — Safari [#1238528, #1687410, #3135626], Firefox [#831962, #892289], IE
  [#241619, #88719, #231524, #189834, #200753]. Chrome-only testing is a systematic false negative.
- **Needs two loads, or a prior page visit** [#241619, #1049012, #1481207, #297968].
- **Only reachable through a non-UI write path** — GraphQL-only mutation, a raw RPC method, an import
  API, a desktop client, a tampered enum [#1198517, #1379400, #1693150, #508184, #54327, #642281].
- **A patch exists, so you skip the class** — several of these are bypasses of prior fixes
  [#716761, #1693150, #1481207, #735638, #3581911].
- **You tested the endpoint the app gave you, not its sibling** [#949513, #3594137].
- **Grepping the response for your canary** finds nothing for fragment- and postMessage-sourced bugs
  — and nothing at all for `javascript:`-URL sinks, where **execution happens with zero reflection**
  [#398054, #422043, #1238528, #217745, #88719].
- **"There is an origin check, so postMessage is safe"** — `indexOf`/`startsWith` on `iframe.src` is
  not an origin comparison [#387544].
- **"It uses `createElement`/`.text()`/`.attr()`, so it's safe"** — keep reading; the same value hits
  `.html()` two lines later [#953579, #189834].

## X9. Safety & ethics — what this corpus normalises

**These are real reports that did things we will not do.** Named so the pattern is recognisable, not
so it is copied:

- A **blind XSS payload fired in a real third-party administrator's mail client**, with the DOM
  exfiltrated — during an audit of a third party, and the reporter *"did not take note of where
  exactly I submitted the payloads"* [#382666]. Another fired in an unknown third party's browser on
  a live customer-support widget, and the report publishes that person's tokens, User-Agent, referer
  and full DOM [#1091118].
- **Live fake sign-in forms and a click-intercepting overlay left on public wiki pages**, with the
  repro step *"Save and wait for someone to click it"* [#662287]; and a live executing payload on a
  **public** merge request, which the reporter notes makes "all GitLab users vulnerable" [#508184].
- **Claiming a real abandoned S3 bucket** on a cross-customer widget platform, then serving a
  credential-logging fake sign-in page from it — anything published there could have run on other
  customers' sites too [#1598347].
- **Overwriting a production CDN asset** used by a live article and waiting for the cache to roll
  [#2846011] (the JSON half of that chain was simulated locally; the SVG overwrite was not).

**A correction worth stating, because getting this wrong smears people.** An earlier draft of this
section also listed reporters who published *live gitlab.com PoC URLs and invited staff to view
them*. On re-reading those reports that was wrong: the objects were the reporters' **own private
projects**, the markers were inert `alert(document.domain)` boxes, and inviting the vendor's triager
to view your private repro is normal, consented practice. Two of them are closer to model behaviour
than to misconduct. Verify conduct against the report text before naming anyone.

**The good practice in the same corpus, worth copying:** `console.log` instead of `alert`
"so as not to bother real users because I don't know where else it might appear" [#1083734] ·
isolated Docker with an explicit statement of what was *not* done [#3400506, #3779690] · pointing the
payload at your own tenant [#1276742] · private repro projects [#836649, #1212822] ·
replacing a real third party's id with your own object [#632017] · an honest "Boundaries / Honest
Scope" section listing what the bug cannot do [#3779690].

## X10. Novelty

Textbook `<script>alert(1)</script>` in the obvious search box on a mainstream program is the
most-reported thing in security. In this sample the accepted work lived in: **delivery** (turning an
undeliverable reflection into a real one — **X1**) · **the second consumer** of a stored value
(**X2**) · **the trust check** rather than the sink (**X3**) · **error and non-default branches** ·
**non-UI write paths** · **the shipped artifact vs the repo** · **third-party scripts, extensions and
ads running in the origin** · **CSP gadgets built from the app's own same-origin files** (**X6**) ·
and **re-testing prior fixes**. Log `fix_locus` as the specific renderer or sink, so distinct
surfaces count separately.

## X11. Worked examples

**A. Reflected, undeliverable at first.** A value echoes only in a POST response. *Model:* reachable
sink, no delivery. *Don't stop* — check whether the endpoint accepts a cross-site form post
(**X1**). *Confirm:* auto-submitting form on your own page, `alert(document.domain)` proving the
origin, and state the activation. *fix_locus =* the unescaped interpolation **plus** the missing
CSRF control, which is a second finding.

**B. Stored, invisible.** You save a marker and nothing renders. *Model:* the consumer is elsewhere
(**X2**). *Derive:* enumerate every surface that reads this field — export, email, notification,
admin view, another role's page — and check each. *Oracle:* execution in the **other principal's**
context; use two of your own accounts, and an inert marker because you don't yet know every render
site. *fix_locus =* the specific unescaped renderer, not "the field".

**C. DOM, nothing hits the server.** A `postMessage` handler. *Model:* find the sink by reading the
bundle, then examine **the trust check** — is `event.origin` compared, or substring-matched, or
absent (**X3**)? *Confirm:* a self-contained attacker page; the artifact is the sink line, a stack
trace, and any server-visible consequence. *Check the browser* — this class is frequently
engine-specific (**X8**). *fix_locus =* the origin comparison, not the `innerHTML`.
