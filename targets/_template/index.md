# <TARGET> — Index / Manifest

> Read this first, every session. It is the map to everything below and the live
> state of the engagement. Every phase updates it. Keep it current.

## Status
- **Program:** <platform / program name / URL>
- **Scope type:** <wildcard *.site.com | specific hosts | ...>
- **Archetype:** <single-app | huge-wildcard | auth-heavy | api-spec | unknown> → routes via `playbooks/system/phase-routing.md`
- **Last activity:** <what actually happened, e.g. "R-004 · subdomain-enumeration on *.acme.com">
- **Suggested next:** <derived from the scope shape — a suggestion, not a queue>
- **Last updated:** <YYYY-MM-DD>
- **Engagement started:** <YYYY-MM-DD>

> **There is no "current phase".** A phase is a skill on a dependency graph, not a position in a
> queue, and it is never globally *done* — a **run** completes for its selector, its sources and
> its date. `runs.tsv` is the record; `tools/kb.py runs <target>` reads it. Writing
> "03 done → 04 pending" tells a future reader that subdomain discovery is finished, which it
> never is: a new root domain, a new source, or a new acquisition all make it worth running again.

## Rules of engagement (quick card — `scope.md` is the authority)
- **Required header:** <e.g. `X-Bug-Bounty: <handle>` | none>
- **Rate limit:** <max req/s the program allows>
- **Accounts:** <self-register allowed | provided | none — none blocks authz/IDOR/tenant testing>
- **Scope recorded:** <YYYY-MM-DD> · evidence: `scope-evidence.md`

## Execution
> Connection, credentials and researcher identity are **machine-level** and live in `config.json`
> at the workspace root — never here. A target brain is engagement data; it must stay free of
> anything machine-specific so it can be archived, moved, or handed over.
> `tools/config.py check` shows what is set. `tools/config.py ssh` prints the connection string.
- **Working dir on VPS:** `<vps.workdir>/<target>/`
- **Tools installed:** <yes/no — see playbooks/system/vps-setup.md>   **Nuclei templates:** <date>
- **Program rate limit:** <from scope.md — overrides `defaults.rate_limit_rps` when stricter>


## Where the derived data lives

This file holds **decisions and state**, not counts. Two tables used to be mirrored in here and
both are gone: they were regenerated copies of files that already existed, and a regenerated copy
is a thing that goes stale while still reading as current.

| you want | ask |
|---|---|
| what has been run, with selectors and limitations | `tools/kb.py runs <target>` — reads `runs.tsv`, the authority |
| how many hosts / urls / params exist | `wc -l` the file, or `tools/coverage.py <target>` |
| what the target has shown you | `tools/kb.py reassess <target>` · `patterns` · `chains` |
| which skill can run right now | `tools/preflight.py <target> --list` |
| what produces what | `tools/graph.py` |

## Raw data (on VPS)
> Base path is `vps.workdir` from `config.json` — shown here as `<vps.workdir>`.
- Subdomains: `<vps.workdir>/<target>/raw/subdomains/`
- DNS: `<vps.workdir>/<target>/raw/dns/`
- Ports: `<vps.workdir>/<target>/raw/ports/`
- HTTP: `<vps.workdir>/<target>/raw/http/`
- URLs: `<vps.workdir>/<target>/raw/urls/`
- Content: `<vps.workdir>/<target>/raw/content/`
- JS: `<vps.workdir>/<target>/raw/js/`
- Nuclei: `<vps.workdir>/<target>/raw/nuclei/`
- Snapshots (for diff): `<vps.workdir>/<target>/raw/snapshots/`
- Job scripts: `<vps.workdir>/<target>/jobs/`   Logs: `<vps.workdir>/<target>/logs/`


## Blocking / TBD
- <every `TBD — blocking: X` left by init lives here until resolved>

## Open threads / next actions
- <what the human should consider running next>
