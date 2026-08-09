# File Upload — the method

> **This is a test of your ability to find a file-upload flaw** in the upload feature the human
> names — the chain that reaches RCE, stored XSS, or SSRF. Model the file's journey from the upload
> sink through server-side processing to where it is **stored and served**, understand how the app
> validates and transforms it, then find where that assumption breaks. The upload itself is rarely
> the bug — the bug is *what the server does with the file and where it serves it from*; don't
> blast web-shells. Work this with `playbooks/vulns/_master-vuln-hunting.md`.

## 1. Model the flow before you touch anything

**SOURCE** — the accept-a-file feature and every field around it: the bytes, the filename, the
declared content-type, the multipart part names, any metadata, and (for fetch-by-URL uploads) the
URL itself.

**FEED** — the validation layers and every transformer between them: extension check, content-type
check, magic-byte check, image re-encode, AV/quarantine scan, then server-side *processing* (image
libs, `ffmpeg`, PDF/SVG/office renderers, XML metadata parsers) and finally storage.

**SINK** — where the stored artifact is *served from* or *interpreted*. A directory the web server
executes (`.php`, `.jsp`, `.aspx`), a template, an image processor, a renderer — or simply an HTTP
response that hands your bytes back with a script-executing MIME.

**CONTEXT — what part of the stored artifact you control, and its path and type.** This decides
technique:

| you control | how it lands | what it opens |
|---|---|---|
| the bytes only (name/type fixed) | stored, maybe re-encoded | processor sinks: SSRF/XXE/RCE in the lib |
| the extension / declared type | stored *as* a dangerous type | execution or script-executing MIME |
| the filename or a metadata field | reflected later, or used in a path | second-order use → `path-traversal.md` |
| the storage path | file lands outside the upload dir | overwrite / write into the web root |
| a fetch URL | server makes the request | → `ssrf.md` |

Serving origin is part of the context: the app's own origin (XSS/RCE risk) versus an isolated
CDN/bucket with `Content-Disposition: attachment` on a sandbox origin (much safer).

**ROOT CAUSE** — which control is missing or desyncable: the checks disagree (content-type says
image, magic bytes say image, extension says `.php`), validation happens at a different layer than
storage, the file is served inline same-origin, or a processor is handed untrusted bytes. **That
answer is your `fix_locus`** — distinct validation-or-serving paths count separately.

## 2. Derive the candidates — reason about the pipeline, not the file types

1. **Enumerate every accept-a-file feature**: avatars/profile images, document/CSV/attachment
   upload, import features, resume/KYC uploads, ticket attachments, logo/branding, bulk import,
   signature/SVG, video/media (transcoded server-side).
2. **Go straight for the non-obvious surface, where dups are rare** — the **serving path** (which
   origin, which MIME, inline vs attachment, auth on read); **server-side processing** sinks
   (ImageMagick/`ffmpeg`/GhostScript, PDF/SVG parsers, XML metadata → XXE); **second-order** use of
   a filename/metadata field; files fetched **by URL**; a path/filename controlling storage location.
3. **Ask what layer each check lives at**, and whether it can be desynced from another. The gap
   between two honest checks is the bug.
4. **Uploads aren't only `multipart/form-data`.** The GraphQL multipart-request spec, a gRPC
   client-streaming method, a base64 blob in a JSON body, and a WebSocket binary frame are all
   upload paths — and they frequently reach the *same* storage and processing sinks through
   *different* validation. Where the web form is hardened, the programmatic path is the candidate.

## 3. Determine the context — before you send a payload

Trace the whole pipeline with cheap, benign uploads whose only job is to locate you:

- What's validated — extension? content-type? magic bytes? image re-encode?
- How it's stored — original name? random ID? user-controlled path?
- **How it's served back** — origin, MIME sent, inline vs attachment, auth on read. Is the serving
  origin the same as the app session origin (stored-XSS reachable) or sandboxed?
- Where does the stored file's URL point, and can you predict or reach other users' files?
- Is the file *interpreted* anywhere — an executing directory, a template, an image processor, an
  office/PDF renderer?

## 4. Test → Confirm → Validate

**TEST — does the file get accepted and stored?** A single small benign file. **Outcome: a
hypothesis** — acceptance alone proves nothing.

**CONFIRM — prove the weakest true fact first, benignly.** The default oracle is **what comes back
from the stored URL**, not what you sent: fetch it yourself and read the served bytes, the MIME,
and the disposition. Establish *which* control is missing before attempting impact:

- **Extension / content-type / magic-byte bypass:** upload a file that passes as an image by magic
  bytes but carries a disallowed extension, or a polyglot; confirm it's stored and served *as* the
  dangerous type. A GIF/PNG header + benign trailing bytes is enough to show the check is
  byte-shallow — no shell needed to prove the gap.
- **Stored XSS:** only if files are served **same-origin** with a script-executing MIME
  (`.html`/`.svg`/sniffable). Upload an SVG/HTML with a harmless `alert(document.domain)` or a
  DNS-callback marker; open it yourself and observe execution. Don't target other users.
- **SSRF / XXE via processing:** apply `ssrf.md` / deserialization / XXE method with *their* OOB
  proof (SVG `<image href>`, XML external entity → callback to your listener).

**Where the oracle inverts or lies:**

- File *accepted* ≠ exploitable — served from a sandboxed CDN as `attachment`/`text/plain` with no
  execution means no XSS/RCE.
- Your `.svg`/`.html` "executing" on a *direct* browser open but served
  `Content-Disposition: attachment` in real flows → not stored XSS in context.
- Magic-byte bypass that is re-encoded server-side (the image library strips your payload) — check
  what's actually *stored*, not what you sent.
- A reflected filename that's HTML-encoded on output isn't XSS.
- 200 on upload but the file 404s on read (quarantined / AV-scanned / never served).
- CDN caching making your file appear where it won't for others.

**VALIDATE — the minimum evidence that proves impact.** Reserve the actual code-exec proof for when
the pipeline plausibly executes uploads, and prove it with a *benign* command — an OOB DNS/HTTP
callback, `id`-style output to your own view. Not "how far can I go".

**Impact & chaining.** RCE (executed upload dir), stored XSS (same-origin serve) →
session/account takeover, SSRF/XXE via processors → internal reach, path traversal via filename →
overwrite/read, client-side malware distribution from a trusted domain. Chains: SVG upload → stored
XSS → admin session theft; image-lib upload → ImageMagick/GhostScript RCE; upload-by-URL → SSRF →
metadata; filename traversal → write outside the upload dir → web-root code exec.

## 5. Safety, artifact, and PoC handoff

- **Never** upload malware, host attack tooling, plant a persistent shell or leave a reverse shell
  running, use a destructive payload, or fill storage (no size/DoS floods). Upload **one small
  proof file; delete it after**, and remove any artifact you placed.
- **Store the artifact**: the upload request, the stored URL, and the served response — MIME plus
  execution evidence or the OOB log. **No artifact → HYPOTHESIS, not FACT.** Redact what the proof
  doesn't need.
- **Ship a runnable PoC, never a prose description** (`playbooks/system/mcp-tooling.md`): the upload
  request in Burp Repeater or a copy-pasteable `curl`, **with the control request** (the benign
  upload that was correctly rejected or correctly served) so the gap is visible in one glance.
- Respect the program's rate limit; bulk uploading is a loud activity — budget and announce it.

## 6. Log it

`targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with the `fix_locus` from §1 — the
specific validation-or-serving code path, so distinct gaps count separately. Log negatives *with
the oracle used* (what the stored URL actually served). **Novelty:** "I uploaded an SVG and it
popped alert on a CDN sandbox" and content-type-only bypasses are frequent dups / N/A. Novelty
lives in **same-origin serving** that makes stored XSS real, **server-side processing** sinks
(image/PDF/XML libs), **second-order** use of filename/metadata, **layer-desync** bypasses (magic
vs extension vs stored path), and execution in an **acquired/legacy** upload handler.

## 7. Worked example

*Model:* `endpoints.md` lists `POST /profile/avatar`; the stored image URL in the response resolves
to the *app's own origin* (`app.target`), not a sandboxed CDN — confirmed against `dns.md`. SINK =
the serving path; CONTEXT = I control the bytes and the declared type, and the serving origin equals
the session origin, so a script-executing MIME served inline is the real risk.
*Derive:* not the upload validator everyone pokes — the serving path is the under-tested surface here.
*Context probe:* the discriminator is whether an uploaded `.svg` is stored and served back as
`image/svg+xml` inline (script runs in `app.target`) versus re-encoded or forced to `attachment`.
*Hypothesis:* avatar upload accepts SVG and serves it same-origin inline, giving stored XSS in the
app origin.
*Test → confirm:* upload one small SVG containing a harmless `alert(document.domain)` (or a
DNS-callback marker), fetch the stored URL yourself, and read the served MIME and disposition —
never target other users; delete the file after.
*Artifact:* upload request, stored URL, served MIME, execution evidence.
*Dedup:* SVG-on-a-CDN-sandbox pops are dups/N-A; same-origin serving is what makes this real —
`fix_locus = avatar serving origin + MIME handling`.
