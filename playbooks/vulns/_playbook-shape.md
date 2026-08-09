# The standard shape of a vuln-class playbook

Every file in `playbooks/vulns/` follows this spine. It exists so a class file is *readable in one
pass* and so the same six questions get asked whatever the class. It was derived from the four
corpus-grounded classes (`sql-injection`, `ssrf`, `idor-bola`, `workflow-abuse`, plus
`template-injection` and `xss`) and then applied back to the rest.

**One file per class by default.** A second file at `ref/<class>.md` is added **only when a class
has been mined against real disclosed reports** and the evidence is genuinely lookup-shaped —
payload catalogues, per-report technique, citations. A reference layer with no corpus behind it just
becomes a container for confident-sounding assertions; `template-injection` was mined and
deliberately *not* split, because 6 reports don't justify a second file.

---

## The spine

```
# <Class> — the method

> Framing blockquote: what this is a test of, the one-sentence method, and a pointer to
> _master-vuln-hunting.md. Say what the *value* is (the reasoned finding) versus what it isn't
> (a payload spray).

[If a ref/ layer exists: a trigger table mapping "you observe X" → "open ref/<class>.md §Y".]

## 1. Model the flow before you touch anything
   The class's own version of: SOURCE → FEED → SINK → CONTEXT → ROOT CAUSE.
   - SOURCE       where attacker-controlled data enters
   - FEED         what carries it, and what parses/transforms it on the way
   - SINK         what finally acts on it, and from what position/privilege
   - CONTEXT      the class-specific discriminator that decides technique. Adapt it:
                    injection classes  → lexical position at the sink
                    SSRF               → how much of the outbound request you control
                    authz classes      → which principal, in which role, under which parent
                    logic classes      → where the rule lives
   - ROOT CAUSE   *why* the defence couldn't hold. **This is the `fix_locus`** — write it
                  down before testing. Two endpoints failing the same way are two findings.

## 2. Derive the candidates — reason, don't fuzz a list
   How to find the entrypoints *for this class* by reasoning about what the feature must do,
   plus the app's own artifacts (HTML, JS bundle, spec, recon/parameters.txt).
   **Never a hardcoded parameter-name list.**

## 3. Determine the context — before you send a payload
   The cheap, safe probes whose only job is to locate you: what shape am I in, what engine /
   parser / principal / rule am I facing. One request each, none destructive.

## 4. Test → Confirm → Validate
   Three steps, three bars — most false reports come from treating step 1 as step 3.
   - TEST      cheapest signal that something is reachable. Outcome: a HYPOTHESIS.
   - CONFIRM   a signal that cannot be coincidence. Name the class's **default oracle** and
               say when it inverts. State any gate here (e.g. authz classes need ≥2 principals;
               without them the honest result is `coverage = blocked (needs-account)`).
   - VALIDATE  the minimum evidence that proves impact. Not "how far can I go".

## 5. Safety, artifact, and PoC handoff
   - The class's specific destructive risks and hard limits.
   - Store the artifact; **no artifact → HYPOTHESIS, not FACT**. Redact what the proof doesn't need.
   - Ship a runnable PoC — Burp Repeater via MCP, or a copy-pasteable curl **with its control
     request** — never a prose description. See playbooks/system/mcp-tooling.md.
   - Respect the program's rate limit; loud activities get budgeted and announced first.

## 6. Log it
   `tested.md` row as (entrypoint × class × principal × variant) with the `fix_locus` from §1.
   Log negatives *with the oracle used*. Note the class's novelty/dedup angle here or in a
   short §7.
```

## Rules when restructuring an existing file

1. **Extend, never replace.** Every technique, sink, trap, and worked example in the old file must
   survive somewhere. Restructuring is a re-ordering, not a rewrite.
2. **No invented facts.** No new payloads, CVEs, product names, statistics or citations. If the old
   file didn't say it, it doesn't go in.
3. **No `[#id]` citations** unless the class has a real corpus — those belong in a `ref/` layer.
4. **Keep the false-positive/false-negative material** — it's the highest-value content in most of
   these files. Fold it into §4 (confirm) or keep it as a short standalone section.
5. **Keep the worked example.** Re-cast it to walk the spine (model → derive → context → confirm →
   PoC → fix_locus).
6. **Similar length.** These are single files; a restructure that doubles the length has gone wrong.
