# Cloud Misconfiguration — the method

> **This is a test of your ability to find exposed data or keys in cloud storage** the human names —
> the chain that reaches sensitive objects or credentials. Model the bucket/blob/IAM binding from
> where it is referenced to who can actually read it, name the ACL/policy the app assumes protects
> it, and find where that assumption breaks. You are reasoning about *exposure* and proving it
> **read-only** — never delete, overwrite, or write to resources you don't own; a directory listing
> or one benign object read is the proof. Work it with `playbooks/vulns/_master-vuln-hunting.md`.

## 1. Model the exposure before you touch anything

**SOURCE** — the reference that names the resource: `recon/cloud.md` (cloud-asset
discovery), `recon/dns.md`, a JS or mobile bundle, a CDN origin, a leaked access key
(`repository-and-secret-recon`), or an SSRF-reachable metadata role.

**FEED** — how a request reaches it: directly at the storage endpoint, through a CDN that is supposed
to gate it (signed URLs / auth), or through a credential you hold.

**SINK** — the resource and the operation the provider will actually perform: a bucket **list**, an
object **read**, an object **write**, an IAM call.

**CONTEXT** — the discriminator is **which principal, doing which operation, on a resource that was
meant to be what**. Decide the exact claim *before* touching anything:

- *Principal*: anonymous, a leaked key, an assumed metadata role, or a CDN-bypassing direct hit on
  the origin.
- *Operation*: anonymous **read**? anonymous **write/list**? A signed-URL scheme the origin bypasses?
- *Intent*: who was meant to access it. A public asset bucket (images/CSS) being world-readable is
  usually *intended* — the bug is **sensitive** data being readable, or **write/list** where only
  read was meant.
- *For IAM/keys*: reachability and scope — an SSRF→metadata role (defer to `ssrf.md` for the safe
  metadata proof), or a leaked key whose permissions you can infer from documentation without
  exercising destructive calls.

**ROOT CAUSE** — the specific ACL / bucket policy / IAM binding / CDN-origin config that is wrong.
**That answer is your `fix_locus`** — the specific bucket/policy/key/origin, so distinct
misconfigurations count separately.

## 2. Derive the candidates — reason from references, not a bucket-name spray

1. **Start from `recon/cloud.md` and `recon/dns.md`**: buckets/blobs/containers already tied to the
   target, CDN origins, storage hostnames.
2. **Cover the providers**: S3 (`*.s3.amazonaws.com`, `s3://`), GCS (`storage.googleapis.com`),
   Azure Blob (`*.blob.core.windows.net`), DigitalOcean Spaces, Backblaze — bucket names guessable
   from the org/app naming.
3. **Non-obvious surface (where dups are rare):** a bucket **referenced in JS/mobile** but never
   linked in the UI; **misconfigured CDN/storage ACLs** (CloudFront/Fastly origin readable directly,
   bypassing signed-URL auth); **over-permissive IAM signals** — a leaked access key or an
   SSRF-reachable metadata role; **exposed metadata/config** (`.env`, `terraform.tfstate`, backups,
   `/.git`, actuator/metadata endpoints); public snapshots/AMIs/registries.
4. **Let the name tell you the sensitivity.** A `*-backups`, `*-config` or `*-dumps` bucket implies
   sensitive content; an asset/image bucket usually doesn't. That judgement precedes the request.

## 3. Determine the context — before you claim exposure

Cheap, read-only, one request each:

- **Attribute the resource.** Does the name actually belong to the target, or is it a collision with
  someone else's bucket? Confirm before claiming.
- **Get to a clean context** — unauthenticated, no target cookies, no ambient cloud credentials, so
  "anonymous" means anonymous.
- **Probe the boundary shape.** Bucket root vs a specific object: `403 AccessDenied` on the root with
  an object readable is a per-object ACL, a different claim from full-bucket public.
- **Trace CDN → origin.** Does hitting the origin host directly serve content the CDN gates behind
  signing/auth? For a key: establish it is live, and whose, before anything else.

## 4. Test → Confirm → Validate

**TEST — does the least-privileged principal get anything?** One anonymous `GET` of the bucket root
(list response) or a HEAD/GET of *one* benign object. **Outcome: a hypothesis.**

**CONFIRM — the default oracle is a successful response from a genuinely clean, unauthenticated
context** (or, for a key, an identity returned by a read-only identity call). Where that oracle
inverts or lies:

- A **public asset bucket by design** (static site images/JS) is not a vuln — world-read is intended;
  the bug is *sensitive* content or unexpected write/list.
- **`403 AccessDenied` on the bucket root but a *specific* object readable** = per-object ACL, not
  full-bucket public. Scope the claim precisely.
- A bucket name that resolves but is **owned by someone else / not the target** — naming collisions
  are common; confirm attribution before claiming it's theirs.
- **Your own authenticated session** making it *look* anonymous — retest from a clean context.
- A leaked key that's already **rotated/revoked** — `get-caller-identity` failing means no finding;
  don't overclaim.
- A **CDN 200 that's actually cached public content**, not an origin-auth bypass.

**VALIDATE — the least that proves impact, always read-only.**

- **Public read/list:** read the smallest thing that shows the content is sensitive — e.g. a
  config/backup *filename* in the listing. Don't bulk-download.
- **Public write (higher severity, prove gently):** demonstrate write capability with a single object
  **in a namespace you control or a clearly-marked harmless key** (`bugbounty-poc-<token>.txt`) —
  **never overwrite or delete an existing object**, never touch another user's data. Delete your
  proof object afterward. If writing risks clobbering anything, stop at the ACL/permission evidence
  and report as HYPOTHESIS pending human go-ahead.
- **Leaked key / IAM:** confirm scope with the *least* intrusive read-only call
  (`sts get-caller-identity`, a list-your-own-permissions call) — do **not** enumerate or touch other
  tenants' resources or run state-changing actions. Identity + inferred scope is the finding.
- **Metadata via SSRF:** use `ssrf.md`'s method — one benign metadata path, never pull or use
  credential material.

Impact: sensitive data exposure (PII, secrets, backups, source), and if writable → **stored-XSS /
content injection / supply-chain** by planting assets a trusted app serves; leaked IAM → cloud
account compromise; exposed `tfstate`/`.env`/`.git` → secrets → lateral movement. Chains: SSRF →
metadata role → over-permissive IAM → account takeover; leaked key in JS → writable bucket →
app-served malicious asset; public backup → creds → auth bypass.

## 5. Safety, artifact, and PoC handoff

- **Never** delete or write to others' buckets, mass-download, run destructive API calls, or exercise
  a key beyond a read-only identity check. Footprint = one request where possible.
- Any write proof is a marked, disposable object in a namespace you control — and you remove it.
- **Store the artifact:** the exact request + response (listing / object / identity) **with the
  anonymous-or-key context recorded**. **No artifact → HYPOTHESIS, not FACT.** Redact object contents
  to the filenames or single field that prove sensitivity.
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): the request to **Burp Repeater**, or a
  copy-pasteable `curl` / provider CLI invocation stating the principal used — plus, where relevant,
  the **control** showing the CDN-gated path denying what the origin serves.
- Respect the program's rate limit; bucket-name enumeration is a loud activity — budget and announce
  it before running it.

## 6. Log it

`targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` where the entrypoint is the
bucket/origin/key and the principal is "anonymous", "leaked key", or "metadata role". Record the
`fix_locus` from §1. Log negatives *with the oracle used* — "403 from clean context", "key revoked",
"CDN cache, not origin".

**Novelty:** "Public S3 bucket" on a big program is a classic dup / often the intended asset host.
Novelty lives in buckets/origins referenced only in **JS/mobile** the crowd never enumerated,
**write/list** (not just read) exposure, **CDN-origin auth bypass**, **sensitive** artifacts
(`tfstate`/backups/secrets) rather than public images, and cloud reach demonstrated as a **chain**
(SSRF→IAM).

## 7. Worked example — the spine in one pass

*Model:* `recon/cloud.md` and a JS bundle reference an S3 bucket `target-app-backups` (named from the
org, never linked in the UI); `dns.md` ties it to the target's asset naming.
*Context:* an asset/image bucket being world-readable is usually intended, but a `*-backups` bucket
implies *sensitive* content. The discriminator — decided before touching an object — is whether
anonymous list/read works **and** whether what's exposed is sensitive (backup/config filenames).
*Hypothesis:* `target-app-backups` allows anonymous listing, exposing sensitive backup artifacts.
*Confirm:* from a clean unauthenticated context, one anonymous `GET` on the bucket root; a listing
returned there, where a session-authenticated request would be ambiguous, is the oracle firing. Read
only the *listing* (filenames) to show sensitivity; if an object is needed, HEAD/GET one smallest
benign file — no bulk download, no write, no delete.
*PoC / fix_locus:* save the exact anonymous request + listing response. "Public S3 bucket" on the
flagship is a classic dup / intended asset host; a JS-only `*-backups` bucket with sensitive
artifacts is the novelty — `fix_locus = target-app-backups bucket ACL`.
