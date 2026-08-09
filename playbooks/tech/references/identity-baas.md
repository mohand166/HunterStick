# Identity and backend-as-a-service lens

Identity providers and client-accessible backends move critical authorization outside the
application controller. Analyze the protocol/configuration boundary and the downstream consumer,
not just the hosted login page or public project identifier.

## Identity stack graph

```text
browser/app → relying client → IdP/broker → upstream IdP
                    ↓ tokens/claims
             API/gateway/service
```

Record issuer/realm/tenant, client identifier, client type, redirect/logout URIs, flow, scopes,
claims/audience, token consumer and session relationship. Do not store secrets.

## Identity product routing

| product | distinctive surfaces and questions |
|---|---|
| Keycloak | realms, clients, OIDC/SAML endpoints, account console, identity brokering, required actions, client scopes/mappers, redirect and web-origin patterns |
| Auth0 / Okta | tenant/custom domain, applications/connections, Universal/hosted login, Actions/hooks, organizations, management versus audience APIs |
| AWS Cognito | user pool versus identity pool, app clients, hosted UI, callback/logout URLs, groups/claims, AWS role mapping |
| Microsoft Entra ID | tenant/common/organizations endpoints, app registration, redirect URI type, scopes/app roles, consent, multi-tenant issuer validation |
| Firebase Auth | project identity, authorized domains, OAuth providers, custom claims, action-code links and downstream Firestore/Storage rules |
| Ping / WSO2 / FusionAuth / OneLogin / Shibboleth / CAS | OIDC/SAML/CAS protocol roles, clients/service providers, brokers, claim mapping, ACS/redirect/logout endpoints and deployment ownership |
| Clerk / WorkOS and similar identity APIs | frontend SDK versus backend verification, organizations/tenants, invitations, redirect flows, webhooks and management API credentials |

Public discovery metadata, client IDs, project IDs and publishable keys are normally identifiers,
not secrets. Ask what privilege a value grants before classifying exposure.

## Identity hypothesis transforms

| observed mechanism | canonical classes |
|---|---|
| permissive or mismatched redirect/logout URI | `oauth-oidc`, possibly `open-redirect` when the application itself redirects |
| authorization response bound to wrong session/client/tenant | `oauth-oidc`, `authentication-bypass` |
| account linking/brokering joins identities on weak attribute | `oauth-oidc`, `registration`, `authentication-bypass` |
| claims/roles accepted by an API under wrong issuer/audience/client | `authentication-bypass`, `privilege-escalation`, `multi-tenant-isolation` |
| login/MFA/reset required action can be skipped or replayed | `mfa`, `password-reset`, `workflow-abuse`, `session-management` as the invariant dictates |
| logout/revocation fails across linked sessions | `session-management` |
| client scope/consent grants unintended capability | `oauth-oidc`, `privilege-escalation` |

Use a browser/proxy capture and the normal OAuth workflow. Do not brute-force accounts, tokens or
codes.

## BaaS/data plane routing

| product | real authorization boundary |
|---|---|
| Supabase / PostgREST | Postgres grants + RLS per exposed table/view; function execution and `SECURITY DEFINER`; Storage/Realtime/Edge Functions have separate paths |
| Firebase Firestore/Realtime DB/Storage | product-specific Security Rules; server/Admin SDKs bypass those rules and rely on IAM/application checks |
| Hasura | role/session variables plus permissions by schema/table/operation/row/column; admin secret bypasses normal authorization |
| Appwrite | document/bucket/function permissions, teams and API-key scopes |
| PocketBase | collection API rules, superuser/admin surfaces and hooks |

### Supabase

- A publishable/anon key in a client is expected. Test the effective grants/RLS policies as `anon`
  and named principals; never report the key alone.
- Tables created through SQL may not inherit the dashboard's safer RLS behavior. Establish the
  actual exposed schema and policy.
- `service_role`/secret credentials bypass RLS and must never be in client artifacts.
- Data API pre-request checks do not automatically protect Storage, Realtime or other products.
- Functions and privileged edge code are separate capabilities from row selection.

### Firebase

- Evaluate Firestore, Realtime Database and Storage independently; rules are product/path specific.
- Queries are not filters: the requested query must satisfy rule constraints.
- Server client libraries/Admin SDK bypass Security Rules and rely on IAM plus application logic.
- Public configuration (`apiKey`, project ID, auth domain) identifies the project; effective rules
  and enabled APIs determine impact.

### Hasura

- Compare anonymous, user-selected/default and authenticated roles.
- Trace which JWT/webhook claims become `X-Hasura-*` session variables and whether the client can
  influence them.
- Test permissions across select/insert/update/delete, relationships, remote schemas, actions and
  event-trigger boundaries; an admin secret is a separate privileged path.

## Canonical BaaS classes

Use `baas-rls` for browser-to-database policy failures. Add `idor-bola`,
`multi-tenant-isolation`, `mass-assignment`, `function-level-authorization`, `file-upload` or
`privilege-escalation` when the observed operation supports those invariants. A public key alone
creates no coverage cell.

## Current official sources

- Keycloak administration and release/security fixes: <https://www.keycloak.org/docs/latest/server_admin/>
  and <https://www.keycloak.org/blog>
- Auth0 security guidance: <https://auth0.com/docs/secure>
- Okta security advisories: <https://trust.okta.com/security-advisories/>
- Microsoft identity platform: <https://learn.microsoft.com/entra/identity-platform/>
- Cognito security: <https://docs.aws.amazon.com/cognito/latest/developerguide/security.html>
- Firebase Security Rules: <https://firebase.google.com/docs/rules>
- Supabase RLS and API security: <https://supabase.com/docs/guides/database/postgres/row-level-security>
  and <https://supabase.com/docs/guides/api/securing-your-api>
- Hasura authorization: <https://hasura.io/docs/latest/auth/authorization/>

Use [`live-research.md`](live-research.md) for version/advisory questions.
