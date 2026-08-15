# <host> — Application Map

> `application-mapping`. Create this app brain with
> `tools/app-context.py ensure targets/<t> <host-or-url>` when you deep-map an app; do not copy or
> name it by hand. Chrome-MCP first (see `playbooks/system/mcp-tooling.md`); map per role.

## What the app does
- <business function — this is what business-logic bugs are built from>

## Roles / principals
| role | how obtained | can see | can do |
|---|---|---|---|

## Trust boundaries
- <where user-controlled data crosses into a privileged context; tenant separation; admin split>

## Auth flow
- <login → session/token → refresh → logout; MFA; SSO/OAuth hops>

## Features / user journeys
| feature | entrypoint | state-changing? | roles | notes |
|---|---|---|---|---|

## Open questions
- <what you could not determine without an account / more access>
