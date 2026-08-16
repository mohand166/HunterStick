# OS Command Injection — the method

> **This is a test of your ability to find OS command injection** in the feature the human names —
> the chain that reaches RCE on the app or worker host. Model the data flow to the **shell/exec
> sink**, work out how the app builds the command line around your input (argv array vs shell
> string) and which metacharacters a shell would actually interpret, then break that assumption with
> one harmless signal. Reason — don't run `id; whoami` to see what sticks. Work this with
> `playbooks/vulns/_master-vuln-hunting.md`.

**Read this file every time.** The technique catalogue lives in **`ref/command-injection.md`** —
open a section only when its trigger fires:

| you observe | open `ref/command-injection.md` § |
|---|---|
| You're hunting for which real binary/interpreter the feature invokes | **C1** the real sink |
| A filter or escaper stands in the way | **C2** filters and escapers that failed |
| No shell metacharacter gets through at all | **C3** argument/flag injection |
| Blind — you need a proof-shape | **C4** blind execution proof-shapes |
| Deciding how far to push a live confirmation | **C5** confirming safely |
| A lesser bug (upload, path traversal, deserialization, XSS) sits nearby | **C6** chains to command execution |
| Judging duplication or picking the next move | **C7** corroboration, dedup, corpus limits |
| Designing the confirmation from scratch | **C8** worked examples |

## 1. Model the flow before you touch anything

**SOURCE** — the field that reaches the command line: filenames, URLs, hostnames/IPs, format/quality
flags, page ranges, arbitrary "options" fields — anything concatenated into a command line. Plus
anything the app *stores* now and shells out with later.

**FEED** — the hops between the request and the exec call: framework binding, an upload handler, a
queue, a cron/webhook dispatcher. Each hop can encode or rewrite your input, and a stored value
crossing one of them is the second-order case.

**SINK** — the exec call itself: `system` / `exec` / `popen` / backticks, `child_process.exec` (vs
`execFile`), `Runtime.exec` with a shell — and from which host and privilege (app server vs worker).

**CONTEXT** — the lexical position your input occupies on the command line. This decides every probe
you write:

| context | how your input sits | what breaks it |
|---|---|---|
| inside a shell string | the app concatenates into one string a shell parses | `;`, `\|`, `&&`, `$()`, backticks, newline |
| an argv array element | passed as a discrete argument, no shell | metacharacters do nothing — but a leading `-` still does |
| an option/flag slot | your value lands where the tool reads switches | **argument injection**: a benign flag changing tool behaviour |

Shell metacharacters only matter when a shell interprets them; argument injection needs no
metacharacter at all. Also settle **reflective vs blind** here: is the command's output returned, or
does only a converted file come back? **Blind is the norm — plan timing/OOB up front.**

**ROOT CAUSE** — one of: the command is built as a shell string instead of an argv array · the value
is a *flag* position the tool will honour · a stored value is re-used in a later shell job · a
wrapper library shells out where the caller assumed it didn't. **That answer is your `fix_locus`** —
the specific exec call site, so distinct sinks count separately.

## 2. Derive the candidates — reason about what must shell out

1. **Ask which features plausibly need an external binary.** PDF/image/thumbnail conversion, media
   transcode, archive extract/compress, DNS/ping/traceroute/whois "network tools", git/svn ops,
   backup/restore, file scanning/AV, `wkhtmltopdf`/ImageMagick/ffmpeg wrappers, SSRF-ish fetchers
   that call `curl`/`wget`.
2. **Within those, enumerate the parameters that become command-line tokens** — filename, URL, host,
   format/quality, page range, options blob.
3. **Non-obvious surfaces:** template/report generators, cron/webhook handlers, and **second-order**
   paths where a stored filename is later used in a shell job — the crawler never reaches those.
4. **Read the tech signals** (`technologies.md`): image/video libs, CLI tools invoked server-side,
   admin/ops utilities. A named binary in the stack is a named sink.

## 3. Determine the context — before you send a payload

Cheap probes whose only job is to locate you; none destructive.

- **Does the feature return command output at all?** If only an artifact comes back, you are blind —
  set up the collaborator host now, not after a failed probe.
- **Argv or shell string?** A value containing a metacharacter that is handled as *literal data*
  (appears verbatim in a filename, error, or output) points at an argv array; one that changes
  parsing points at a shell string.
- **Is this a flag position?** Send a value with a leading `-` and look for a behaviour change rather
  than an error — that locates argument injection without any metacharacter.
- **Baseline the timing** of a normal request over several samples *before* you consider a delay
  probe, so a delta means something.

## 4. Test → Confirm → Validate

**TEST — does anything reach an interpreter?** The cheapest discriminating probe from §3: a
metacharacter handled as syntax rather than data, or a flag that changes behaviour. **Outcome: a
hypothesis.**

**CONFIRM — the default oracle is an out-of-band callback.** Inject a command triggering a **DNS/HTTP
callback** to your collaborator host (a benign `nslookup`/`curl` to a unique subdomain); a hit proves
execution and the exfil channel at once. Where OOB is unavailable, fall back to **timing**: a single
short, bounded delay (`sleep 5` equivalent) against a control request — one probe, repeatable, not a
loop. For argument injection, the oracle is a benign flag producing an observable, harmless
behaviour change. Where the oracle inverts or lies:

- A **timing delay that's really the backend fetching a slow URL / a cold cache**, not your `sleep` —
  always run a control and repeat.
- Your **OOB callback fired from a downstream SSRF fetch** of your payload, not command execution —
  confirm the resolver and user-agent, and that plain SSRF alone wouldn't produce it.
- A **WAF 500/403 on metacharacters** looks like "something happened" but isn't execution.
- **Input echoed into the response** (reflection) mistaken for command output.
- A **sandboxed/stubbed tool** that accepts the arg but never really runs a shell.

**VALIDATE — the least that proves impact.** Direct RCE on the app/worker host → full compromise;
escalate only the **minimum** (one benign OOB, or `id` via a safe channel) to demonstrate it, never a
shell or persistence. Chains: CI/build or webhook worker RCE → supply-chain / secrets; injection
reachable only after an upload or SSRF → chain the primitives; blind CMDi + OOB carries the whole
proof where no output returns.

## 5. Safety, artifact, and PoC handoff

- **Never** destructive or DoS: no `rm`, no `:(){ :|:& };:`, no `sleep 300`, no fork bombs, no
  spawning heavy processes, no writing or overwriting files. **One short sleep or one DNS ping is the
  whole proof.**
- Stop at reachability. Do not take a shell, plant persistence, or read beyond the one benign signal.
- **Store the artifact:** the injected request + the callback log or the timing delta with its
  control. **No artifact → HYPOTHESIS, not FACT.** Redact anything the proof doesn't need.
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): the request to **Burp Repeater**, or a
  copy-pasteable `curl` **with its control request** so the differential (callback vs no callback,
  delayed vs baseline) is visible in one glance.
- Respect the program's rate limit, and where it mandates an identifier put it in the payload so your
  traffic is attributable in their logs.

## 6. Log it

`targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with `result`, `coverage`, and the
`fix_locus` from §1 — the exec call site is the dedup key. Log negatives *with the oracle used*
("OOB silent, timing baselined and flat"), because a silent callback is not by itself a negative.

**Novelty:** the obvious `ping`/`nslookup` "network tools" box on a mature program is reported to
death — assume dup/hardened. Novelty lives in **conversion/transcode pipelines**
(ImageMagick/ffmpeg/wkhtmltopdf option and filename injection), **argument injection** (no
metacharacters needed), **second-order** via stored filenames, and worker/cron paths the crawler
never reaches.

## 7. Worked example — the spine in one pass

*Model:* `endpoints.md` has `POST /api/documents/convert` accepting an uploaded file plus a
`filename` field; `technologies.md` lists ImageMagick + `wkhtmltopdf` and a Node worker — a
conversion pipeline that very plausibly builds a shell string around the output filename.
*Derive:* conversion needs an external binary, and `filename` is the parameter most likely to become
a command-line token.
*Context:* the question is argv-array vs shell-string, and `filename` may be arg-injectable even
without metacharacters (a leading `-`). Output is blind — only the converted file returns — so I plan
OOB up front.
*Hypothesis:* `filename` is interpolated into a `convert ... <filename>` shell command, so a
metacharacter-triggered subshell will make an outbound DNS lookup.
*Confirm:* set `filename` to a value appending a single benign `nslookup <unique>.collab` subshell to
a unique collaborator subdomain; one DNS hit is the oracle firing, proving execution and channel at
once. One probe — no `sleep 300`, no `rm`, no file writes.
*PoC / fix_locus:* save the request + collaborator log. The `ping` network-tools box is reported to
death; this is a filename sink in a transcode worker the crawler never reached —
`fix_locus = child_process exec in convert worker`.
