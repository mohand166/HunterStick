# Path Traversal — the method

> **This is a test of your ability to find path traversal** in the file-path parameter the human
> names — the chain that reaches arbitrary file read. Model the request down to the
> **file-resolution sink**: what root directory your input is joined to, what normalization sits
> in front of it, and what the app then *does* with the resolved path — then find where that
> containment assumption breaks. The value is a named bypass of a named filter, not a payload
> spray; prove the escape by reading **one** benign known file. Work this with
> `playbooks/vulns/_master-vuln-hunting.md`.

---

## 1. Model the path resolution before you touch anything

**SOURCE** — the parameter that names a file or a path. It may arrive in the query string, the body,
a header, a filename inside an uploaded archive, or a value stored earlier and opened later
(second-order).

**FEED** — everything between the parameter and the filesystem call: the framework's decoder, a
reverse proxy or WAF that rewrites or rejects, an application-level sanitiser, and any
concatenation that builds the final path.

**SINK** — the file-resolution site, **and what it does with the result**: does it *read* it, stream
it, *include/execute* it, or *write* to it? Read-traversal ≠ write-traversal (far worse) ≠ inclusion
(that's `lfi-rfi.md`).

**CONTEXT — where in the resolved path you sit, and what normalization runs in front of you.** This
is the discriminator that picks the technique. Answer three questions before sending anything:

1. **What root are you joined to, and where in the resolved path does your input land?** Prefix
   (you are the whole path — try an absolute path), middle (a directory root is prepended — you
   need `../` to climb), or suffix-constrained (the app appends an extension — you need a
   truncation or a matching suffix).
2. **What normalization sits in front?** Does it strip `../`, decode once or twice, block on `/`,
   enforce an extension suffix, or `realpath`-check containment? Each answer suggests a different
   encoding: `..%2f` for a single decode, `..%252f` for a double decode, `....//` for a
   single-pass strip, an absolute path where the join is naive, NUL / `?` / `#` truncation where a
   suffix is appended.
3. **Is the file returned in the response (reflective) or blind** (status and size only)? That
   decides whether your oracle is content or behaviour.

**ROOT CAUSE** — one of: the path is joined to a root with no containment check at all · the
sanitiser is single-pass and its own output is traversable · decoding happens after validation ·
the suffix check is satisfiable without constraining the directory · the path comes from stored data
never re-validated at open time · the archive extractor trusts the entry name. **That answer is your
`fix_locus`** — the specific file-resolution site, so distinct sinks count separately.

## 2. Derive the candidates — reason about which features must name a file

Parameters that name a file or path are the obvious start (`file`, `path`, `name`, `filename`,
`doc`, `download`, `attachment`, `template`, `img`/`image`, `page`, `lang`/`locale`, `theme`,
`folder`, `dir`) — but derive them from the feature, not from the list:

1. **Any feature that must hand a user a file off disk**: download and export endpoints, file
   preview and thumbnails, avatar and attachment fetch, "export as", static-asset proxies, log and
   report viewers.
2. **Any feature that must select a resource by name**: i18n/locale loaders, theme loaders,
   template selectors — these take a *name* that becomes a path, and get far less scrutiny than
   `?file=`.
3. **Any feature that writes a path you supplied**: ZIP and upload extractors, where a path inside
   the archive becomes a traversal **on write**.
4. **Paths carried outside the query string** — in headers, or stored at one step and opened later
   (second-order).
5. **Tech signals from `technologies.md`**: apps serving user files from disk, reverse proxies,
   legacy CGI, `.aspx`/PHP file handlers, and S3-fronting file APIs with a **local-disk fallback** —
   the fallback is the interesting half.

## 3. Determine the context — cheap probes that locate you

One request each, none destructive, all read-only:

- **An in-root control**: request a file you are legitimately allowed to see. This is the baseline
  every later comparison needs, and it shows the response shape for a *successful* read.
- **A single `../`**: does it come back stripped, rejected, or honoured? A 403 from a proxy tells
  you a filter exists; a response identical to the control tells you the dots were removed.
- **One encoding step up** from whatever the last probe implied — single-encoded, then
  double-encoded, then a self-regenerating form. You are locating the decoder relative to the
  validator, not trying to hit a file yet.
- **A suffix probe**: append and remove the extension the app seems to expect.

## 4. Test → Confirm → Validate

**TEST — does the containment break?** Send the traversal variant your §3 context selected, aimed
at **one benign, known-stable file** — on Linux `/etc/hostname`, or a known app-bundled static
file, or simply a traversal back to a file you already had access to. **Outcome: a hypothesis.**

**CONFIRM — the default oracle is a differential against the in-root control: the traversed request
must return *different, known* content.** `file=welcome.txt` (in-dir) vs
`file=../../<known benign file>` — a successful response whose body matches the out-of-root file and
differs from the control is the proof; the control is what rules out coincidence. On a blind sink
the oracle degrades to status/size differentials and is correspondingly weaker — say so. **The
oracle lies in these ways:**

- A `200` carrying an error page, or the app's default file, for *any* path — confirm the returned
  content actually matches the out-of-root file you targeted.
- The app returning the same in-directory file regardless of `../` (dots stripped) — the traversal
  didn't take; verify the content *changed*.
- A WAF or proxy `403` on `../` is a block, not a finding; a reflected filename inside an error
  message is not file contents; and it may "work" only because the file also exists in the root.

**VALIDATE — one benign file is the whole proof.** Confirm the escape, then **stop**. Do not read a
second file to size the impact; read the *minimum* needed to show severity.

## 5. Safety, artifact, and PoC handoff

- **Never** read `/etc/shadow`, private keys, application secrets or config carrying live
  credentials, or other users' data to "prove" the bug. Reading `/etc/passwd` is common, but if a
  truly benign file proves the escape, prefer it.
- **Never** use **write**-traversal to overwrite a file — an overwrite is not reversible, and on an
  extractor it can break the application for everyone. **Never mass-pull directories**: one file
  proves it, a harvest is an incident.
- **Store the artifact**: the in-dir request/response and the traversed request/response as a pair.
  **No artifact → HYPOTHESIS, not FACT.** Redact any content the proof doesn't need.
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): the request in Burp Repeater or a
  copy-pasteable `curl` **with its control request**, reproducible in one action.

## 6. Log it

Every probe goes to `targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with the
`fix_locus` from §1 — the specific file-resolution site, so two sinks behind the same sanitiser
are two rows. Log negatives *with the oracle used* (content differential, or status/size on a
blind sink), so the next session knows how hard you looked.

**Novelty.** `?file=../../../../etc/passwd` on an obvious download param of a mature program is the
most-reported instance in this class — assume dup or hardened. Novelty lives in
**encoding/normalization bypasses of an existing partial filter**, **archive/upload
write-traversal**, path injection via **headers or second-order** (a stored filename opened later),
i18n and theme loaders, and file APIs with a local-disk fallback. Impact: arbitrary file **read**
(source, config, tokens) is often the pivot to something bigger; write-traversal via unzip/upload →
file overwrite → code execution. Chains: read app config or secrets → auth bypass, SSRF
credentials, cloud keys; leaked source → whitebox hunting for more bugs; if the file you read is
then *executed or included*, it is LFI — pivot to `lfi-rfi.md`.

**Worked example.** `endpoints.md` has `GET /download?file=invoice.pdf`; `technologies.md` shows a
Java service streaming user files from disk behind a proxy that strips a single `../`. *Model:* the
input is joined to a docs root and **read/streamed** — not executed, not written, so this is path
traversal, not LFI or write-traversal. *Context:* the partial filter is the tell; a single-pass
strip suggests a doubled or encoded variant, and the output is reflective, so content comparison is
available. *Hypothesis:* `....//` survives the strip (it collapses to `../` after removal), so a
traversal to one known benign file returns content different from the in-root control.
*Test/confirm:* `file=invoice.pdf` (control) vs `file=....//....//etc/hostname` (or a known
app-bundled static file); a successful, *different*, known-content response proves the escape. Read
that one file and stop — no `/etc/shadow`, no keys, no directory pulls. Save the control-vs-traversed
pair. *Novelty:* bare `../../etc/passwd` is dup or hardened here; the finding is the `....//` bypass
of *this specific existing filter* — `fix_locus = file resolver in /download`.
