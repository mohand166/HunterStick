# API, realtime and edge lens

Load this for API engines, gateways, reverse proxies, caches and realtime transports. These layers
often create the most valuable **parser and policy disagreements** in a composite stack.

## Build the hop graph

```text
client → CDN/WAF → gateway/proxy → framework router → resolver/controller → service/data
```

For each hop record:

- which host/path/method/content type it sees after normalization;
- which identity and forwarding headers it creates, strips or trusts;
- which authentication/authorization decision it performs;
- whether it caches, retries, transforms or batches;
- which upstream/downstream error becomes the external oracle.

Do not test parser disagreement aggressively. Establish the architecture and use the smallest
non-destructive discriminator authorized by the program.

## Product and protocol routing

| family | products | distinctive questions |
|---|---|---|
| GraphQL libraries | Apollo Server, Yoga, Mercurius, GraphQL Java, Hot Chocolate | endpoint/schema discovery, resolver authz, object ownership, aliases/batching, custom scalars, subscriptions, persisted operations |
| GraphQL data engines | Hasura, PostGraphile, Supabase GraphQL | role/session-variable or database-policy enforcement per table/field/row/function; admin/privileged secret separation |
| REST/OpenAPI | Swagger UI, springdoc, FastAPI, API Platform | contract versus deployed routes, alternate content types, generated binders, undocumented operations and auth scheme application |
| SOAP/OData/RPC | WSDL/SOAP actions, OData, JSON-RPC, tRPC | operation discovery, parser/entity behavior, method dispatch, object/property authorization, batching and alternate representations |
| gRPC/gRPC-web | Envoy transcoding, grpc-gateway, native services | reflection/proto recovery, HTTP↔RPC transcoding differences, metadata authz, streaming and per-message authorization |
| realtime | WebSocket, Socket.IO, SSE, GraphQL subscriptions | handshake identity, origin, namespace/topic authorization, message-level object/function authz and reconnect/token refresh |
| self-hosted gateways | Kong, Envoy, NGINX, HAProxy, Traefik | route/plugin order, prefix stripping, normalization, trusted forwarded headers, admin/control plane, cache/retry behavior |
| managed gateways | AWS API Gateway, Azure APIM, Apigee, Cloudflare | stage/version/custom-domain routing, authorizers/policies, transformations, origin exposure, cache keys and provider ownership |

Use the existing GraphQL, gRPC and API investigation workflows to recover contracts. Transport is a
lens; it does not replace vulnerability classes.

## Hypothesis transforms

| evidence-backed disagreement | canonical classes |
|---|---|
| page/gateway authorizes but resolver/service does not | `function-level-authorization`, `idor-bola` |
| role/tenant header or claim changes between hops | `multi-tenant-isolation`, `privilege-escalation`, `authentication-bypass` |
| HTTP and RPC/alternate content type bind different fields | `mass-assignment`, relevant injection class if a sink exists |
| proxy and application normalize path/host differently | `function-level-authorization`, `host-header-attacks` |
| response varies on identity/header/query absent from cache key | `cache-poisoning` |
| gateway hides an origin that remains directly reachable | `origin-exposure` |
| URL rewrite/proxy/import lets caller influence destination | `ssrf` |
| two HTTP parsers disagree about message boundaries | `request-smuggling` only after confirming `http-hop+ambiguous-framing` |
| subscriptions/topics expose another object/tenant | `websocket`, `idor-bola`, `multi-tenant-isolation` |
| aliases/batching evade a per-request control | `limit-bypass`, possibly `race-conditions` |

## GraphQL-specific guardrails

- Introspection being enabled is surface information, not a vulnerability.
- Disabling introspection does not authorize fields or rows.
- Recover schema from legitimate traffic, errors and client artifacts when introspection is absent;
  do not brute-force enormous name lists.
- Compare the same field/resolver as distinct principals and through nested relationship paths.
- Treat query cost/depth issues as availability concerns; do not validate DoS.

## Gateway/edge guardrails

- A product header may belong to a managed edge, not the target-controlled origin.
- Never trust `X-Forwarded-*` behavior without identifying which hop appends versus accepts it.
- A management API path is not proof the control plane is exposed; identify port/host and ownership.
- Cache hits, misses and age must be calibrated before drawing conclusions.
- Follow redirects only inside scope and prefer host-restricted behavior.

## Current official sources

- GraphQL specification: <https://spec.graphql.org/>
- Apollo Server security guidance: <https://www.apollographql.com/docs/apollo-server/security>
- Hasura authorization documentation: <https://hasura.io/docs/latest/auth/authorization/>
- gRPC authentication: <https://grpc.io/docs/guides/auth/>
- Kong security advisories: <https://github.com/Kong/kong/security/advisories>
- Envoy security advisories: <https://github.com/envoyproxy/envoy/security/advisories>
- NGINX security advisories: <https://nginx.org/en/security_advisories.html>
- Cloudflare security centre: <https://www.cloudflare.com/trust-hub/security-and-compliance/>

Use [`live-research.md`](live-research.md) for current versions and advisories.
