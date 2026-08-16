# Insecure Deserialization — reference layer

> **Lookup, not reading.** Open a section when its trigger fires; don't read this end to end.
> The method lives in `../deserialization.md` — that one you read every time.
>
> Grounded in **12 reports read in full** out of the 220 cached in `knowledge/reports/deserialization/`
> — a directed sample by ecosystem, not a corpus-wide review like SSRF's 128/219. `[#id]` =
> hackerone.com/reports/id. **Corpus bias:** skews Java (Telerik ×3, Tomcat, Kafka Connect,
> Hyperledger) and Ruby (RubyGems.org, twice); one PHP, one Python/YAML, one .NET. No Node, gRPC, or
> PHP `phar://` trigger — reason from the model in `../deserialization.md` §1 for those.

| § | trigger |
|---|---|
| **D1** | format + gadget, per ecosystem |
| **D2** | the composite pattern — a file-write primitive feeding the sink |
| **D3** | how these were actually proven |
| **D4** | same CVE, three DoD hosts, three reports |
| **D5** | attribution and disposition traps |
| **D6** | novelty, dedup, and hunting fixes |

---

## D1. Format + gadget, per ecosystem

- **PHP:** `unserialize()` on a base64 cookie, `O:37:"Monolog\Handler\FingersCrossedHandler"...` — the
  gadget was reachable only because a WordPress plugin shipping Monolog was installed on the target;
  the vulnerability *is* whatever's on the box [#2248328]. SwiftMailer's
  `Swift_Transport_SendmailTransport`+`Swift_ByteStream_FileByteStream` (bundled with ownCloud) wrote
  an arbitrary PHP file from a serialized object in an *uploaded file*, not a cookie [#562335]. Both
  hand-built the object graph rather than using a generic tool.
- **Ruby:** one **public, reusable universal gadget** (`Gem::SpecFetcher`/`Gem::Installer`/
  `Gem::RequestSet`/`Net::WriteAdapter` → `Kernel.system`, from an external "Universal Deserialisation
  Gadget for Ruby 2.x–3.x" writeup) fired against **two different sinks on the same target, two years
  apart**: RubyGems.org's checksum-file `YAML.load`→`Marshal.load` pivot [#274990, 2017] and Bundler's
  own `format.marshal` dependency-API response variant sitting next to its JSON one [#1119120, 2021].
- **Java:** `ysoserial`'s `CommonsCollections7` via a JNDI/LDAP reference returned to a
  `JndiLoginModule` config lookup, reached only through a **custom** `System.setProperty` gadget in the
  Scala standard library to defeat a JDK JNDI restriction — "took way too much time" per the reporter
  [#1529790]. Two more Java sinks are plain YAML, no gadget needed: SnakeYAML's default `Constructor`
  in an SDK's config parser [#801370], and (title only — see D3) Tomcat's file-based session
  persistence [#3031518].
- **.NET:** `ysoserial.net`'s `ExpandedWrapper`/`ObjectDataProvider` in a `DNNPersonalization` cookie,
  naming `FileSystemUtils.WriteFile` — arbitrary file read/write shown, not pushed into a shell
  [#876708].
- **Python/Java YAML — no gadget chain at all.** `yaml.load()` and SnakeYAML's default loader natively
  instantiate arbitrary types; that *is* the bug in both [#2467232, #801370], argued from source review
  with no fired payload shown.

## D2. The composite pattern: a file-write primitive feeding the sink

**Three ecosystems here show the identical two-step shape** — an arbitrary or path-traversal file
write, then the app's own deserializer reading that planted file back. **.NET/Telerik:**
CVE-2017-11317 (encrypted-upload write) chained into CVE-2019-18935 (the handler later deserializing
the uploaded file into a loaded .NET assembly) [#838196, #1174185, #913695]. **Java/Tomcat:** a
partial `PUT` writes attacker content into Tomcat's default file-based session-persistence directory;
a later request deserializes it as a session [#3031518] — asserted only, no live PoC in the report.
**PHP/ownCloud:** an admin uploads `structure.xml`+`data.dump` via the normal Files UI, then a
path-traversal in `restore-tables`' `tables[]` (`../../admin/files`) points the restore routine at the
uploaded `data.dump` instead of a real table [#562335]. Hunt for this shape on sight — an upload/write
primitive plus *any* deserializer elsewhere in the app, even if unrelated-looking; the write is
delivery, not the vulnerability. Confirm with a benign marker file before attempting anything that
executes, and log `fix_locus` as the deserializing **read**, not the write — different bugs, different
owners, even when chained in one report.

## D3. How these were actually proven

- **Sleep-DLL timing side channel** (Telerik): a DLL whose `DllMain` calls `Sleep(10000)`, uploaded
  and triggered; response time jumps to ~12s. Reporters stopped there — "I feel the sleep PoC is good
  enough to prove RCE... I didn't upload a reverse shell" [#913695, #838196] — the cleanest corpus
  match for "prove with a callback, don't fire the gadget."
- **Not blind**: Nextcloud/WordPress ran `system('id')` and read the output straight out of the HTTP
  response [#2248328] — real, accepted, critical, but not the callback-only pattern the method file
  recommends; cite it as what triage accepts in practice, not as a template.
- **Blind OOB beacon**: RubyGems.org's PoC just made the server `wget` the reporter's own host, twice
  [#274990]. **File-write differential**: ownCloud's payload wrote `/tmp/pwned.php`, confirmed by
  requesting it directly [#562335].
- **A partial, honest confirm**: Bundler's gadget *did* fire — the `bundle install` error trace shows
  it attempting `sh -c date` — but the command itself failed (`sh: reading: command not found`);
  reported as-is [#1119120]. A misfiring gadget that visibly perturbs behavior is still evidence.
- **No oracle at all**: Tomcat [#3031518], SnakeYAML/Hyperledger [#801370], and PyYAML/Liberapay
  [#2467232] are source-review findings asserting the unsafe call without a fired payload — a title
  claiming "leads to remote code execution" doesn't mean the report proves it did.

## D4. Same CVE, three DoD hosts, three reports

The Telerik CVE pair from D2 appears **three times** here, all against the DoD VDP, all resolved
critical, none flagged duplicate: [#838196], and roughly a month apart, [#1174185] and [#913695] (same
reporter, z32). `#913695` lists `#838196` in its References — a public disclosure used to
fingerprint-sweep the rest of the program's inventory (the `WebResource.axd?type=rau` "handler is
registered" response is the cheap tell). `#1174185` shows the messier reality: upload confirmed, sleep
DLL never fired, reporter left mid-attempt with no resolved end state in the cached text. **A known CVE
fingerprint is a sweep target across a whole program; each vulnerable host is its own report, not a
duplicate of the technique.**

## D5. Attribution and disposition traps

**[#562335] (ownCloud OwnBackup) closed *informative* despite a self-rated critical.** The cached text
has no team rationale, so the reason is an **ASSUMPTION**: the chain needs an *administrator* to
install a specific marketplace app and feed it a crafted file through that app's own restore feature —
plausibly judged as admin-only functionality working as designed. Don't assume a critical self-rating
survives triage when the precondition is "you're already an admin." Severity tracked what was
demonstrated, not the class's reputation: RCE-by-title reports with no fired payload scored low/$0
[#2467232] or a token $200 [#801370]; a working timing or execution oracle scored critical regardless
of ecosystem.

## D6. Novelty, dedup, and hunting fixes

A gadget you already have for a language is a finding-generator, not a one-off — RubyGems.org's
universal gadget hit two structurally different sinks two years apart [#274990, #1119120]; audit
*every* endpoint returning or accepting a non-JSON serialized format, and every call site of an unsafe
loader (RubyGems patched every YAML entry point except the checksum one [#274990]), not just the
already-reported case. Novelty in Java costs real time — a stock `ysoserial` payload needed a
hand-built gadget just to get past a JDK JNDI restriction [#1529790]; don't budget it as free.
Unusual channels are undervalued — a dependency-resolution API quietly offering a `format.marshal`
response variant beside its JSON one is the kind of sink a scanner never touches [#1119120].
Config-file YAML sinks (D1) are real but modest — legitimate, but non-web and not
network-reachable by default, so don't expect Telerik-tier severity from one [#801370].

---

## Grounded in disclosed reports

*Corpus: `knowledge/reports/deserialization/` holds 220 cached files; this ref layer is grounded in
the 12 the task named and we read in full — a directed sample, not a survey of the directory, and
smaller than SSRF's 128/219 or XSS's. **Treat this as per-ecosystem technique coverage, not
exhaustive.** Two of the twelve (Tomcat, PyYAML) are source-review assertions with no fired payload in
the report text; one (Hyperledger) is a small library bounty; one (ownCloud) closed informative despite
a critical self-rating; three are the same underlying CVE against different hosts in one program. No
node-serialize, no protobuf/gRPC, no `.NET BinaryFormatter`-via-ViewState example turned up in the
reports we were pointed at — if one becomes relevant, it needs its own sourcing, not an extrapolation
from what's here.*
