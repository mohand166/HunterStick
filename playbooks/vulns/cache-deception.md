# Web Cache Deception → merged

**This playbook has been merged into [`cache-poisoning.md`](cache-poisoning.md)** ("Web-Cache
Abuse").

Read that. Deception and poisoning turned out to be the same bug with the arrow reversed — in both,
**the cache key and the response body are computed from different things**:

- **Poisoning** — the key omits an input the body depends on, so *your* content lands in
  *everyone's* entry.
- **Deception** — the key says "static and public" while the body is *someone's authenticated page*,
  so *their* data lands under *your* key.

They also share the same probes (`X-Cache` / `Age` / `CF-Cache-Status`, MISS→HIT), the same
false-positive trap (your own browser cache faking a HIT), the same safety control (a unique token so
the entry you create is addressable only by you), and the same hard rule: **never touch a key real
users are served.**

**Where the deception material went:**

| you wanted | now at |
|---|---|
| Suffix/prefix cache rules vs origin routing | `cache-poisoning.md` §1 CONTEXT (the direction table) |
| Path-normalization and delimiter gaps (`;`, `%2f`, `//`, `%00`, `..;/`) | §1 ROOT CAUSE · §2.5 · §3 |
| Starting from authenticated, personalized responses | §2.3 |
| The cookieless-re-request oracle and its inversions | §4 CONFIRM |
| Never targeting a real user's resource | §5 |
| The worked example | §7 example **B** |
