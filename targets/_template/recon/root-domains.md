# <TARGET> — Root Domains

> **`organization-and-roots`.** One row per apex, and every row carries its own evidence. The same skill supplies unproven *seeds* in `target.md`; an apex reaches this file only once the ownership pivots have been run. A domain is not a
> root because it has the company's name in it — `example.net` can be owned and out of scope while
> an unrelated-looking CDN apex is authorised.
>
> **`ownership` and `scope_status` are different questions.** The program's scope table decides
> what may be touched; it says nothing about who owns the domain, and ownership says nothing about
> authorisation. Answer both, separately, for every row.
>
> `evidence` names the source **and the date**. An undated source is not evidence: ownership
> expires, and marketing pages lag divestitures by months. Where sources disagree, set
> `ownership` to `unresolved` and put the check that would settle it in `notes` — never average
> two sources, and never drop the row.
>
> Column order is fixed by `playbooks/system/target-schema.md` — later skills parse it.

| apex | ownership | scope_status | evidence (source + date) | proves | confidence | notes |
|---|---|---|---|---|---|---|

<!-- ownership:    owned | divested | third-party | unresolved
     scope_status: in-scope | out-of-scope | not-listed | unknown
     confidence:   observed (you checked WHOIS/TLS yourself) | reported (a source said so) | inferred
     proves:       say what the source actually establishes — "authorisation, not ownership",
                   "registration control", "ownership on that date" — they are not the same claim -->

## Unresolved — do not touch

> Every apex where sources conflicted or nothing was found, each with the specific check that
> would settle it. An omitted apex looks examined; an unresolved one is honest.

- &lt;apex · what conflicts · what would settle it&gt;

## Excluded

> Divested, third-party, or named out of scope. Kept, not deleted — this is what stops the same
> apex being re-investigated next month.

- &lt;apex · why · source + date&gt;
