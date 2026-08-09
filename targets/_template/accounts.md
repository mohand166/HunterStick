# <TARGET> — Test Accounts

> Authenticated recon and authorization testing require controlled principals. A row counts as
> usable only when `status = ready` and its credential reference resolves. Role names and planned
> email addresses are not accounts.
>
> Prefer `password-manager:<item>` or `env:<VARIABLE>` references. If a live session must be stored
> locally, keep it only in this gitignored target directory and replace it with a pointer in every
> artifact, PoC, log, and finding. Never place credentials on the VPS unless a specific authorized
> task requires it.

## Registration policy

- **Policy:** <self-register allowed | provided accounts | none | unknown>
- **Consequence:** <what authenticated work is possible or blocked>

## Accounts

`status` = pending | ready | expired | unavailable.

| label | role | username / email | credential_ref | tenant/org | status | notes |
|---|---|---|---|---|---|---|
| user-a | standard | <> | <> | <> | pending | primary controlled account |
| user-b | standard | <> | <> | <> | pending | second controlled account for authorization diffs |
| admin | elevated | <> | <> | <> | unavailable | only when explicitly provided or self-created lawfully |

## How to authenticate

- **Login URL:** <>
- **Auth mechanism:** <cookie / bearer JWT / OAuth / other>
- **Session capture:** <manual browser / Burp / command using credential_ref>
- **Session lifetime / refresh:** <>

## MFA

- <enabled? approved automation path? backup-code handling?>
