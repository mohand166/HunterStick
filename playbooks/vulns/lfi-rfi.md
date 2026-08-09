# Local / Remote File Inclusion (LFI / RFI) — the method

> **This is a test of your ability to find local/remote file inclusion** in the endpoint the human
> names — the chain that reaches file read escalating to code execution. Model the request to the
> **include/require sink**, work out how the app resolves your input to a path and whether the
> result is *interpreted/run* rather than just streamed back, then find where that assumption
> breaks. The distinction from path-traversal is **execution**: here the included file is
> interpreted, not merely read. Prove inclusion with a benign, non-executing signal first. Thin
> class file; work it with `playbooks/vulns/_master-vuln-hunting.md`.

## 1. Model the flow before you touch anything

**SOURCE** — a parameter that selects a module/page/template to **include**, not just serve: `page`,
`include`, `module`, `template`, `view`, `action`, `lang`/`locale`, `theme`, `skin`, and `file` when
the result is rendered as code.

**FEED** — the resolver between the parameter and the filesystem: a front-controller router, a
plugin/theme loader, a template framework that maps names to files. Each may prepend a directory,
append a suffix, or allowlist the value.

**SINK** — the construct that *interprets* the resolved path: PHP `include`/`require`/`require_once`
with a user-influenced path, dynamic template selection, plugin/theme loaders, `require()` or
dynamic `import()` in Node, Python `importlib`/dynamic module load, JSP/`.NET` dynamic includes.

**CONTEXT — the path position at the include, and what the resolver does to it.** This decides
technique:

| context | the question | what it opens |
|---|---|---|
| interpreted vs streamed | is the resolved file *run*, or handed back verbatim? | verbatim → this is `path-traversal.md`, not LFI |
| local vs remote | does the include accept a URL scheme? | RFI needs a remote fetch allowed (`allow_url_include`) and `http(s)://`/`ftp://` in the include path |
| suffix appended | is `.php` (or similar) glued on? | forces a wrapper or truncation trick |
| wrappers enabled | `php://filter`, `data://`, `expect://`, `phar://`, `zip://` | `php://filter` reads source **without executing** — the safest confirmation channel |

Also ask, without acting on it: what log/session files could an attacker later poison for code exec?

**ROOT CAUSE** — the specific `include`/`require` call that resolves user input to a path.
**That is your `fix_locus`**, so distinct sinks count separately.

## 2. Derive the candidates — reason about what must resolve a name to a file

1. **Enumerate the features that select code, not data**: page/module routing, template and theme
   selection, plugin loading, locale files. Anything that turns a user-supplied *name* into a file
   the app then runs.
2. **Read the tech signals**: legacy PHP, front-controller routers, plugin architectures, template
   frameworks that resolve names to files.
3. **Separate the include sinks from the download sinks.** A parameter that streams bytes belongs to
   `path-traversal.md`; only the interpreted ones are candidates here.

## 3. Determine the context — before you send a payload

- **Is the resolved path executed or streamed?** Execution is the whole difference; establish it
  before choosing a probe.
- **Local or remote?** Does the include allow a URL scheme, or only local paths?
- **Is a suffix appended?** That silently defeats naive paths and points you at a wrapper channel.
- **Are wrappers enabled?** `php://filter` is the safest confirmation channel precisely because it
  discloses source without running attacker code.

## 4. Test → Confirm → Validate

**TEST — does my value reach a real filesystem path?** A benign resolvable name that isn't the
default, and a name that shouldn't resolve, to see whether resolution is happening at all rather
than being allowlisted. **Outcome: a hypothesis.**

**CONFIRM — is the file actually being *included*?** The default oracle is **known content coming
back through a channel that only inclusion could produce**:

- **LFI, read-only:** `php://filter/convert.base64-encode/resource=<a known app file>` returns that
  file's source base64 — it decodes to content you can verify, proves inclusion, and runs no
  attacker code. Or include a **known-benign local static file** and confirm its content.
- **RFI:** point the include at **your own** benign, inert file on a collaborator host and confirm
  it was fetched (a server-side callback) — a harmless marker, not a shell.

Confirm the inclusion primitive, then stop. Where the oracle inverts or lies:
- A file **read back verbatim** with no interpretation is path-traversal, not LFI — don't overclaim
  execution.
- `php://filter` returning nothing means wrappers are disabled or the path is wrong — it is **not**
  proof of absence.
- RFI "working" that's actually plain SSRF (the server fetched the URL but didn't *include* it) —
  confirm the content was interpreted, not just requested.
- An appended `.php` suffix silently defeating your path, which looks like a block.
- Allowlisted page names, where your value never reaches a real filesystem path.

**VALIDATE — the least that proves impact.** Source disclosure via `php://filter`, or an inert
remote marker, is the whole proof. Describe the RCE path in the report rather than walking it.

**Impact & chaining.** LFI → source/secret disclosure and, via **log/session poisoning** or
wrappers, **RCE**; RFI → direct RCE by including attacker-hosted code. Chains: `php://filter` source
read → find hardcoded creds or more bugs (whitebox pivot); LFI plus a place you can write
attacker-controlled bytes (an upload, a log entry) → code exec; LFI reading config → onward
auth/SSRF/cloud-key access. Demonstrate the **minimum**.

## 5. Safety, artifact, and PoC handoff

- **Never** poison logs, `/proc/self/environ`, or sessions and include them to get a shell; **never**
  host or include a real webshell; **never** use `data://` or `expect://` to execute code; **never**
  read live-secret files. These are the destructive primitives of this class and they stay off the
  table — the inclusion primitive is the finding.
- **Store the artifact**: the wrapper or remote-marker request plus the evidence (the decoded base64
  source, or the callback log). **No artifact → HYPOTHESIS, not FACT.** Redact any real secret that
  appears in disclosed source — the proof needs the fact of disclosure, not the credential.
- **Ship a runnable PoC, never prose** (`playbooks/system/mcp-tooling.md`): the request to Burp
  Repeater or a copy-pasteable `curl` **with its control request** (the benign page name) so the
  difference is visible in one glance. Respect the program's rate limit.

## 6. Log it

`targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with the `fix_locus` from §1 — the
specific `include`/`require` call. Log negatives *with the oracle used*, and record whether wrappers
were enabled and whether a suffix was appended, so the next session doesn't re-derive it. **Novelty:**
`?page=../../etc/passwd` and bare `php://filter` on an obvious `page` param of a known legacy app are
heavily reported — assume dup. Novelty lives in **wrapper/suffix-bypass chains**, **poisoning vectors
unique to this app** (a log/notes field you can write then include), template/plugin loaders resolving
user names to files, RFI on modern stacks that unexpectedly fetch remote includes, and second-order
inclusion.

## 7. Worked example

*Model:* `endpoints.md` shows `GET /index.php?page=home` on a legacy front-controller;
`technologies.md` is PHP with a plugin/theme loader that resolves `page` to a file and `include`s it.
Because the result is *interpreted*, this is LFI territory, not plain path-traversal — SINK = that
`include()`, and it's the `fix_locus`.
*Derive:* `page` selects code, not data, which is what put it on the candidate list.
*Context probe:* the key discriminator is execution vs streaming — `page` reaches an `include`, so a
raw read-back wouldn't prove it. A `.php` suffix may be appended, which points at a wrapper channel;
`php://filter` is ideal because it discloses source *without running attacker code*.
*Hypothesis:* `page` feeds `include("<val>.php")` with wrappers enabled, so a `php://filter` resource
will return a known app file's source as base64.
*Test → confirm:* request `page=php://filter/convert.base64-encode/resource=index` and check the
response decodes to `index.php`'s known source; that proves inclusion with zero code execution. No
log poisoning, no webshell, no `data://`/`expect://`.
*Artifact:* the wrapper request + decoded-source evidence.
*Dedup:* bare `?page=../../etc/passwd` and vanilla `php://filter` are heavily reported; note the
suffix-bypass wrapper chain and any app-specific writable field to poison later —
`fix_locus = include() in front-controller page resolver`.
