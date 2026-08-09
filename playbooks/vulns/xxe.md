# XXE — XML External Entity — the method

> **This is a test of your ability to find XXE** in the endpoint the human names — the chain that
> reaches file read or SSRF. Model the request down to the **XML parser sink**, understand whether
> the app parses your input as XML with external-entity/DTD processing enabled, and find where that
> assumption breaks. Recognize the XML sink and prove entity resolution with an **out-of-band
> callback** — don't spray DOCTYPE payloads at every endpoint. This class reads local files and
> reaches internal networks; the value is one clean proof of resolution, not a file dump. Work this
> with `playbooks/vulns/_master-vuln-hunting.md`.

---

## 1. Model the parser before you touch anything

**SOURCE** — the body or file you supply: an XML document, or a file format that *contains* XML.

**FEED** — what carries it to the parser: the `Content-Type` the endpoint honours, an upload handler,
a document converter, an import pipeline. Each hop is a chance the parser you reach is not the one
the endpoint advertises.

**SINK** — the XML parser itself, and the position it runs from: what filesystem it can read and what
network it sits on.

**CONTEXT** — the discriminator is **whether the parser resolves entities, and whether output comes
back to you**. Answer both; they select the technique independently:

| question | what to establish | what it selects |
|---|---|---|
| is there a real XML parser here at all? | does the endpoint parse an XML body or an XML-bearing file, even if it advertises JSON? | whether the class applies |
| is external-entity / DTD processing enabled? | the old default in many Java parsers | whether it is a bug or a hardened parser |
| does the response reflect parsed values? | in-band (values echoed) versus blind (nothing returns) | in-band entity expansion **vs** an out-of-band callback |
| blind, and you need a channel? | parameter entities and the OOB exfil path | how you prove resolution with no data leaving |

**Billion-laughs / entity expansion is OFF the table** — that is DoS, and it is out of bounds
regardless of what it would prove.

**Tech signals from `technologies.md`:** Java (heavy XML history), .NET, PHP `libxml`, legacy SOAP
stacks, enterprise integrations.

**ROOT CAUSE** — the parser was constructed with DTD and external-entity processing left enabled (or
an XML-bearing format is handed to such a parser). **That answer is your `fix_locus`** — the specific
parser/endpoint, so distinct parsers count separately.

## 2. Derive the candidates — find where XML is parsed, not where it's advertised

1. **Anywhere XML is parsed server-side:** SOAP endpoints, `Content-Type: application/xml` or
   `text/xml` bodies, XML file uploads (SVG, DOCX/XLSX/PPTX, SAML, RSS, GPX, `.xml` configs), SAML
   responses, XML-RPC, sitemap and feed ingestion.
2. **Prefer the non-obvious surface:** endpoints that *accept* JSON but also parse XML if you switch
   the `Content-Type`; SVG uploads rendered or processed server-side; document converters
   (docx→pdf); "import" features taking XML.
3. **Reason from the format, not the route name** — any feature that must read a structured document
   the user supplies is a candidate for whichever parser the stack reaches for.
4. **Read `technologies.md`** for the stack tells above, which predict both the parser and its
   defaults.

## 3. Determine the context — before you send an entity

Cheap probes, one request each, nothing resolved yet.

- **Establish that XML is parsed at all** — send a well-formed XML body (or file) with no DOCTYPE and
  see whether the endpoint processes it rather than rejecting it. On a JSON endpoint, this is where
  you switch the `Content-Type` and watch whether it still parses.
- **Establish whether output returns** — does the response echo any parsed value? That single answer
  decides in-band versus blind before you write an entity.
- **Establish whether a DOCTYPE is accepted at all**, so you can tell a parser that rejects DTDs from
  a WAF that strips them (§4).
- **Stand up your listener first** for the blind case, so the first entity you send has somewhere to
  call.

## 4. Test → Confirm → Validate

**TEST — does the parser accept a DTD?** The DOCTYPE is not rejected. **Outcome: a hypothesis** —
acceptance says nothing yet about resolution.

**CONFIRM — did the parser *resolve* the entity?** Two oracles, and you pick by the §1 context:

- **Blind — an out-of-band callback is the default and the preferred proof.** An external entity
  pointing to **your own listener** (OOB HTTP/DNS via interactsh): a single hit proves resolution
  with **zero data exfiltration**. Prefer this even when in-band would work.
- **In-band — a benign internal entity expanding in the echoed response** (an entity resolving to a
  static string you control), or a *harmless, non-sensitive* file read purely to prove file access.

The oracle inverts or lies here — rule each out:

- **DOCTYPE accepted + no callback is INCONCLUSIVE, not a negative.** Acceptance is not
  resolution — but silence is not proof of non-resolution either. At least four things produce it:
  egress is filtered at the network edge · DNS is filtered or the resolver is internal-only · the
  parser resolves the entity and discards the result · your collaborator host is blocked.
  Before recording `not-vuln`, try a channel that does not leave the network:
  **error-based** (point the entity at a nonexistent local path and read the parser error),
  **timing** (a slow-responding host you control vs a closed port), **local file** into a reflected
  field, or a **parameter-entity DTD fetched over a protocol the egress filter may not cover**.
  Only after those is the honest result `not-vuln`; otherwise it is `inconclusive` with the reason
  recorded.
- **A WAF stripping `<!DOCTYPE` returns a generic error — that's a block, not a result.** Run the
  WAF-escalation ladder in the master loop before recording a negative.
- **A reflected entity value that is actually just your input echoed**, not parser-expanded. Make the
  expanded value distinguishable from the literal you sent.

**VALIDATE — the least that proves impact.** One internal callback, or one benign file, is enough.
Impact: file read (config, credentials), **SSRF** to internal services and cloud metadata (chain with
`ssrf.md`), OOB data exfiltration, and sometimes RCE via `expect://` or deserialization gadgets.
Chains: SVG-upload XXE → internal SSRF → cloud metadata; SAML XXE → auth bypass. Escalate the
*minimum* needed to show severity, then stop and say what you did not do.

## 5. Safety, artifact, and PoC handoff

- **Never run billion-laughs or entity-expansion DoS.** It is denial of service, not evidence.
- **Never exfiltrate large or sensitive files.** A harmless, non-sensitive file proves file access;
  dumping secrets or keys wholesale is an incident, not a proof.
- **Never hammer internal services via XXE-SSRF** beyond a **single reachability probe**. This class
  reaches networks the program did not expose to you — one probe, then stop.
- **Prefer the callback over the file read** wherever both would confirm: it proves the same bug with
  no data crossing.
- **Store the artifact** under `targets/<t>/raw/`: the request, plus the OOB hit from your listener or
  the echoed expanded entity. **No artifact → HYPOTHESIS, not FACT.** Redact anything the proof
  doesn't need.
- **Ship a runnable PoC** (`playbooks/system/mcp-tooling.md`): the request to **Burp Repeater**, or a
  copy-pasteable `curl` with the exact body and every required header including the program's
  mandated bug-bounty header — **with the no-entity control request** so the difference is visible in
  one glance. Reproducible in one action from a clean session.
- Respect the rate limit; announce anything loud before running it.

## 6. Log it

Every probe goes to `targets/<t>/tested.md` as `(entrypoint × class × principal × variant)` with `result`,
`coverage` and the **`fix_locus` from §1** — the specific parser/endpoint. Log negatives *with the
oracle used*: "DOCTYPE accepted, no callback" and "DOCTYPE stripped by WAF" are different negatives
and only one of them means the parser is safe.

**Novelty.** The obvious classic XXE on a plain XML API on a popular program is often already
reported or patched. Novelty lives in **file-format XXE** (SVG/DOCX/SAML), the **JSON→XML
content-type switch**, **blind XXE via parameter entities** on an endpoint no scanner ever sent XML
to, and XXE on **acquisition or legacy SOAP hosts**.

## 7. Worked example — the spine in one pass

*Model / derive:* an "import contacts" feature accepts `application/json`, but `endpoints.md` and
`technologies.md` say it is a Java service — a candidate from asking which parser an import feature
must reach, not from the route name. Switching to `Content-Type: application/xml` with an XML body
still parses, so the parser sink is reachable from a route that advertises JSON. No reflected output,
so the context is **blind**.
*Context:* Java + XML parse + no reflected output means the safe discriminator is an out-of-band
callback, not file reading. Listener stood up first.
*Hypothesis:* the parser resolves external entities; an entity pointing to my listener will call back.
*Confirm:* define an external entity resolving to `http://<interactsh-id>/xxe` and reference it
**once**. A single DNS/HTTP hit at my listener proves resolution — no file read, no internal scan.
Artifact = the request plus the callback log, with the no-entity control.
*Novelty:* nobody sent XML to a JSON endpoint — `fix_locus = XML parser on /import`, distinct from
any JSON-side bug.
