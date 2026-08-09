# Insecure Deserialization — the method

> **This is a test of your ability to find insecure deserialization** in the blob or flow the human
> names — the chain that reaches RCE on the deserializing host. Model the request down to the
> **deserialization call**: recognize the serialized blob crossing a trust boundary, work out which
> deserializer consumes it and whether it's the unsafe API, then break that assumption. Prove it with
> an out-of-band callback — reason, don't fire a live RCE gadget. Thin class file; work it with
> `playbooks/vulns/_master-vuln-hunting.md`.

## 1. Model the flow before you touch anything

**SOURCE** — an opaque blob the client can influence: cookies/session tokens, `viewstate`, hidden
form fields, cache/queue messages, `Remember-Me` tokens, API params holding encoded objects, file
uploads processed by an object parser.

**FEED** — the hops that carry it: base64/URL decoding, a cookie jar, a cache or queue, a worker
picking the message up later. A blob that reaches an internal consumer through a queue is the
second-order case.

**SINK** — the deserialization call and the host it runs on:
`ObjectInputStream.readObject`, `unserialize`, `pickle.loads`, `yaml.load`, `BinaryFormatter`,
`Marshal.load` — the unsafe APIs — versus a safe loader / type allowlist in front (`yaml.safe_load`,
`JsonSerializer` without `$type`).

**CONTEXT** — the discriminator is **which format the blob is, which deserializer eats it, and under
what protection**:

- **Format fingerprint:** Java `rO0` / `AC ED 00 05` (base64 `rO0AB...`); PHP `O:8:"..."` /
  `a:2:{...}` (`unserialize`); Python pickle `\x80` opcodes / `gASV`; .NET
  `BinaryFormatter`/`ObjectStateFormatter` (`/wEP...` viewstate), `Json.NET` with `$type`; Node
  `_$$ND_FUNC$$_`/`node-serialize`, YAML `!!python/`, `!ruby/object:`.
- **Pre- or post-auth:** does the server deserialize it *before* authenticating/validating?
  Pre-auth deserialization is the high-value case.
- **Integrity:** is the blob HMAC'd/signed? If you can't forge without the key, note the signing —
  don't claim exploitability.
- **Gadget availability:** are known chains present on the classpath/dependencies? Recognize the
  format first; gadget availability decides exploitability.

**ROOT CAUSE** — the specific unsafe deserialization call reached with attacker-influenced bytes, and
what was missing: no type allowlist, no signature, or a signature you can bypass. **That answer is
your `fix_locus`** — the specific deserialization call site, so distinct sinks count separately.

## 2. Derive the candidates — reason about what must round-trip an object

1. **Enumerate the opaque blobs the client holds or influences** (the SOURCE list above) — anything
   the server hands you and expects back unchanged is a candidate.
2. **Fingerprint each one** against the format table in §1 before deciding it's uninteresting;
   base64 that isn't JSON is worth a decode.
3. **Read the tech signals** (`technologies.md`): Java stacks (`ysoserial` targets), PHP apps with
   magic methods, Python pickle/PyYAML `load`, .NET `BinaryFormatter`, Ruby Marshal,
   `node-serialize`. The stack tells you which format to expect and which sink exists.
4. **Include the non-obvious channels:** cache/queue messages and second-order stored objects, which
   the crawler and the scanner never reach.
5. **A binary transport is already a deserializer.** gRPC/protobuf, MessagePack and CBOR endpoints
   parse attacker bytes into live objects by design — the question is what happens to an
   **unexpected field, type, or `oneof` branch**, and whether the message is handed to a
   *second*, weaker deserializer after the wire format is decoded. Recover the descriptor first
   (`playbooks/workflows/investigate-grpc.md`); fuzzing an unaligned binary stream produces
   encoding errors that look like findings and aren't.

## 3. Determine the context — before you build a gadget

Cheap probes whose only job is to locate you:

- **Decode and fingerprint** the blob offline — no traffic at all.
- **Tamper-detection:** minimally mutate the blob and observe a **different** server behavior (parse
  error / stack trace / changed handling) vs the untouched blob. That shows it's parsed server-side,
  not just echoed — and whether an integrity check rejects it first.
- **Check reachability without a session** — does the endpoint accept the blob unauthenticated?
- **Set up the collaborator host now.** Output is normally blind, so plan the OOB channel before you
  send anything.

## 4. Test → Confirm → Validate

**TEST — is the blob parsed server-side at all?** The mutation differential from §3. **Outcome: a
hypothesis** — a changed response is parsing, not yet deserialization of your object graph.

**CONFIRM — the default oracle is a DNS/HTTP callback triggered by the blob alone.** Use a
**callback-only** gadget (e.g. a URLDNS-style chain in Java, or a benign network touch) so a hit on
your collaborator proves deserialization with no command execution.

**Be precise about what the callback proved.** A URLDNS hit proves two things: the sink
deserializes attacker-controlled data, and *that one* gadget is on the classpath. It does **not**
prove RCE — URLDNS reaches the network by design and exists in the JDK; a command-execution chain
needs gadgets (Commons-Collections, Spring, etc.) that may simply not be there. Write it as
**"deserialization of untrusted input confirmed; RCE not demonstrated"** and let the impact
argument rest on that. Claiming RCE from a DNS lookup is the most common way a real
deserialization finding gets downgraded on triage.

Escalate no further than the callback. Where the
oracle inverts or lies:

- **Base64 that decodes to JSON/plain data the app parses safely** (typed/allowlisted) —
  recognizable format ≠ unsafe deserializer.
- **A parse error on mutation that's just input validation**, not object instantiation.
- **Your OOB callback firing from an unrelated SSRF/URL fetch in the request**, not from the gadget —
  isolate the blob as the only trigger.
- **HMAC/signed session blobs** where you can't forge without the key (integrity-protected) — note
  the signing, don't claim exploitability.
- **WAF blocking known `ysoserial` bytes** → a generic error, not proof.

**VALIDATE — the least that proves impact.** Show the **minimum** (OOB reachability) and argue the
rest: typically **RCE** on the deserializing host (Java/PHP/.NET/Ruby/Python/Node), sometimes file
write / SSRF / auth bypass depending on available gadgets. Describe the RCE chain in the report
rather than running it. Chains: pre-auth deserialization → unauthenticated RCE; a leaked signing key
(from LFI/source disclosure) → forge a trusted blob → RCE; deserialization on an internal queue/cache
worker reached via another bug → deep pivot.

## 5. Safety, artifact, and PoC handoff

- **Never** fire a full RCE/`exec` gadget, drop a shell, or run destructive/`sleep`-flood chains on a
  live target. **A single DNS callback (or a controlled parse-error differential) is the whole
  proof.**
- Stop at reachability — no persistence, no post-exploitation, nothing that changes server state.
- **Store the artifact:** the tampered blob + the callback log or the differential response. **No
  artifact → HYPOTHESIS, not FACT.** Redact anything the proof doesn't need.
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): the request carrying the blob to
  **Burp Repeater**, or a copy-pasteable `curl` **with its control request** (the untouched blob) so
  the differential — and the fact that only the blob triggered the callback — reads in one glance.
- Respect the program's rate limit, and where it mandates an identifier make your traffic
  attributable in their logs.

## 6. Log it

`targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with the `fix_locus` from §1 — the
specific deserialization call site is the dedup key. Log negatives *with the oracle used*: "mutation
rejected by HMAC", "callback silent with collaborator confirmed reachable", "format fingerprinted but
safe loader".

**Novelty:** a default `ysoserial` payload against a well-known vulnerable endpoint/product version is
almost certainly already reported or scanner-found. Novelty lives in **custom app gadget chains**
(app-specific classes with dangerous magic methods), blobs in **non-obvious channels** (cache/queue
messages, second-order stored objects), formats the scanner didn't fingerprint, and integrity checks
that are present-but-bypassable.

## 7. Worked example — the spine in one pass

*Model / derive:* the app sets a `Remember-Me` cookie that base64-decodes to bytes starting `rO0AB`;
`technologies.md` confirms a Java/Spring stack. That fingerprint says Java native serialization on a
client-influenceable, pre-auth blob — the high-value case.
*Context:* the first question is whether the server deserializes it *before* auth via
`ObjectInputStream.readObject` (unsafe) and whether the blob is integrity-protected. If unsigned,
tampering should change parse behavior. Output is blind and I must avoid any command execution, so
the safe reachability probe is a callback-only gadget.
*Hypothesis:* the cookie is `readObject`-deserialized unauthenticated with no HMAC, so a
DNS-callback-only chain (URLDNS-style) will trigger an outbound lookup during parsing.
*Confirm:* first minimally mutate one byte and confirm a *different* server response (parse
error/stack trace) vs untouched — server-side parsing, not echo. Then submit a URLDNS-style blob
pointing at a unique collaborator host; a single DNS hit is the oracle firing, proving
deserialization + gadget reachability. No `exec` gadget, no shell, no `sleep` flood. Save tampered
blob + callback log.
*Dedup:* a default ysoserial payload on a known CVE endpoint is scanner-found; the novelty is this
custom Remember-Me channel — `fix_locus = readObject in Remember-Me token handler`.
