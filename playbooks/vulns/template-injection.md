# Server-Side Template Injection (SSTI)

> **This is a test of your ability to find server-side template injection** in the endpoint
> the human names — the chain that reaches RCE via the template engine. Work from first
> principles: trace the request to the **template render call**, understand whether the app
> places your input into the template *source* (evaluated) or its *data* (escaped), and find
> where that assumption breaks. Prove the engine *evaluates* your input and identify which
> one — don't paste `{{7*7}}` everywhere and call reflection a bug. Thin class file; work it
> with `playbooks/vulns/_master-vuln-hunting.md`.

## Where it hides
- Anywhere the app builds output by interpolating user input into a **template string**
  server-side: email/notification templates, "customize your message", invoice/report
  generators, subject lines, filename/slug templates, error pages, CMS blocks, admin
  theming, PDF renderers fed by templates.
- **Sink signal**: user input that later appears rendered *and* the stack uses a template
  engine — Jinja2/Twig/Freemarker/Velocity/Thymeleaf/Handlebars/ERB/EJS/Pug/Razor.
- Tech signals from `technologies.md`: Flask/Django (Jinja), Symfony (Twig), Java/Spring
  (Freemarker/Velocity/Thymeleaf), Rails (ERB/Liquid), Node (Handlebars/Pug/EJS).

## How to analyze the function
- Is the input placed into the **template source** (evaluated) or into template **data**
  (escaped and merely displayed)? Only the former is SSTI; the latter is at most XSS.
- Which engine? The evaluation syntax differs (`{{...}}` vs `${...}` vs `#{...}` vs
  `<%= %>`), and so does the escalation path. Fingerprint before escalating.
- What context does the rendered output land in — HTML, email body, PDF, header? That
  affects what you can observe.

## Minimal safe validation
- **Evaluation probe, non-destructive.** Prove server-side computation, not reflection.
  - Send a benign arithmetic/string expression in the engine's syntax and confirm the
    **result** appears, not the literal: `{{7*7}}`→`49`, `${7*7}`→`49`,
    `#{7*7}`, `<%= 7*7 %>`. If `49` renders, the engine evaluated it.
  - Disambiguate the engine with syntax that only one accepts (e.g. `{{7*'7'}}` yields
    `7777` in Jinja but `49` in Twig) — a couple of small differential probes.
  - Keep to arithmetic/string math for confirmation; do **not** jump straight to object
    traversal on a live target.
- **Never** run OS/RCE gadgets to "prove" it (`config.__class__`…→`os.system`, Runtime
  exec, file reads/writes, `sleep`). Confirm evaluation with math; describe the escalation
  path in the report rather than executing it beyond the smallest safe demonstration.
- Save the `expression → evaluated result` request/response as the artifact.

## False-positive traps
- `{{7*7}}` reflected **verbatim** (`7*7` or `{{7*7}}` in the page) = no evaluation = not
  SSTI (likely just XSS/reflection).
- **The inverse trap — `{{7*7}}` returning nothing is not a negative.** Logic-less engines
  (Handlebars, Mustache, Liquid) do not evaluate arithmetic *at all*, so the arithmetic probe
  produces a clean false negative on exactly the stacks people run in Node. Probe those with a
  property walk instead: `{{this}}` → `[Object Object]`, then
  `{{this.__proto__.constructor.name}}` → `Object` tells you a real template context is
  evaluating your input [#423541].
- Client-side framework (Angular/Vue) evaluating `{{ }}` in the browser — that's
  client-side template injection, a different class; confirm the math happens server-side
  (view source / non-JS client).
- A sandboxed/logic-less engine (Handlebars, Liquid, sandboxed Twig) that evaluates simple
  expressions but blocks escalation — real but lower impact; don't overclaim RCE.
- WAF normalizing braces, or the value going through a second render pass.

## Impact & chaining
- Escalates from expression eval to **RCE** on full engines (Jinja2/Freemarker/Velocity/
  ERB/Smarty); on sandboxed engines, often info-disclosure or SSRF/file read instead.
- Chains: SSTI in an email/report template reachable pre-auth → unauthenticated RCE; SSTI
  behind an admin feature → privilege-to-RCE; sandbox-escape gadgets turn "harmless" math
  into code exec. Demonstrate the **minimum** (evaluation) and argue the rest.

## Dedup / novelty angle
- A reflected `{{7*7}}=49` on the most obvious search param of a popular app is frequently
  already reported. Novelty lives in: **non-HTML render paths** (email/PDF/invoice/report
  templates), **stored/second-order** SSTI (name/profile field rendered later in a
  template), admin/theming template editors, and engines the scanner doesn't fingerprint.
  Log `fix_locus` as the specific template render call so distinct sinks count separately.

## Worked example
*Scenario:* `endpoints.md` shows account settings let a user set a `display_name` that later appears
in system-sent notification emails; `technologies.md` is Flask + Jinja2 — a stored/second-order path
into an email template, not the reflected search box everyone probes.
*Analyze:* the discriminator is whether `display_name` is interpolated into the template *source*
(evaluated) or passed as template *data* (escaped, at most XSS). The observation channel is the
rendered email body, and the engine is Jinja, whose `{{...}}` syntax I can disambiguate from Twig.
*Hypothesis:* `display_name` is concatenated into the email template string, so a benign arithmetic
expression will render as its computed result in the delivered email.
*Minimal safe test:* set `display_name` to `{{7*7}}`, trigger the notification, and check whether the
email shows `49` (evaluated) or the literal `{{7*7}}` (reflection only); a follow-up `{{7*'7'}}`→`7777`
confirms Jinja vs Twig. Arithmetic only — no `__class__`/`os.system` gadgets. Save the rendered-email
evidence as the artifact.
*Dedup angle:* reflected `{{7*7}}` on search is heavily reported; a *stored* SSTI in a non-HTML email
render path is novel — log `fix_locus = Jinja render in notification-email builder`.

---

## Grounded in disclosed reports

*Corpus: `knowledge/reports/template-injection/`. **Small** — the upstream index listed only 12
reports and half are gone, leaving 6 (4 with usable technique). Too thin for a separate reference
layer, so the findings are folded in here. `[#id]` = hackerone.com/reports/id; dispositions noted.*

**The corpus confirms this file's central bet: the sink is usually an email or notification
template, not a web page.** Three of the four useful reports:

- A `{{7*7}}` in the **First Name** field at signup rendered in the welcome email's *subject line*:
  `49, welcome to Glovo!` [#1104349, resolved, high].
- A Smarty payload in first/last/nickname, triggered by **inviting a friend**, output in the invite
  email [#164224, resolved].
- Handlebars in an app's **"send me a test email"** template editor [#423541, resolved].

**Practical consequences:**

- **The trigger is part of the test.** Nothing renders until you cause it to — complete a signup,
  invite someone, hit "send test". Plan the trigger before you plant the payload, and remember the
  observation channel is an inbox, not the response.
- **Put the probe in every candidate field at once** when you can't tell which one is interpolated —
  one reporter said plainly "I'm not sure which field is vulnerable" and seeded all three [#164224].
- **HTML escaping is not template escaping.** A vulnerable PoC ran the input through `escapeHTML()`
  and was still injectable, because escaping happens *before* the string becomes template source
  [#904672, informative — a library-usage issue demonstrated on a locally written app].
- **Declaring that you could not exploit it did not sink the report.** One reporter wrote "I am not
  sure if it's exploitable or even valid", showed only the prototype walk, and it was accepted —
  the team later linked the full RCE writeup themselves [#423541].
- **Observed escalation ladder**, as a map of what *not* to run on a live target: arithmetic →
  engine version (`{$smarty.version}`) → an execution primitive (`{php}print{/php}`) → file read
  [#164224]. That reporter went to `/etc/passwd`; our rule stands — confirm with math, argue the
  rest.

**Non-finding shape to recognise:** a report claiming SSTI in `curl -os{...}` — which is the `-o`
output flag plus shell brace-globbing, not a template — was closed **not-applicable**; the reporter
disclosed it was AI-generated [#3584149]. Tool-syntax confusion presented as injection.
