# Frontend and meta-framework lens

Load this for browser frameworks, SSR/meta-frameworks and bundler-generated applications. Also load
a deep profile from `../` when one exists.

## First split: where does trusted code run?

| mode | evidence | security consequence |
|---|---|---|
| client-only SPA | static shell, client router, API calls from browser | bundle reveals surface; authorization must exist behind the UI |
| SSR/hydration | per-request HTML plus serialized state | server data can cross into HTML/state; cache and user variation matter |
| server components/functions | RSC/action protocol, server-only modules | public server entrypoints may not have conventional routes; input/authz remains server responsibility |
| static generation | build-time pages, immutable assets | origin logic may be absent, but preview, revalidation and data endpoints can still be dynamic |
| edge/serverless | platform headers, edge middleware/functions | header/path normalization and deployment-specific caches become another control layer |

Never call an application “React” and stop. Establish whether React is client-only, SSR, Server
Components or embedded inside another framework.

## Product routing

| product/family | distinctive surface to confirm | target-specific questions |
|---|---|---|
| React client | root + React bundle/source map | hidden lazy routes, API base URLs, unsafe DOM escape hatches, `postMessage`; public build variables are not secrets by name alone |
| Next.js | Pages vs App Router, `/_next/`, RSC/Server Actions | page/API/action authorization parity, server-to-client data, image/rewrites, middleware versus route-level controls, cache variation |
| React Router / Remix | route manifests, loaders/actions, framework data requests | loader/action authorization, nested route data, mutation CSRF/origin controls, cache and error boundaries |
| Gatsby | static assets, page-data JSON, build metadata | page-data leakage, preview/build hooks, source maps; distinguish static site from backing APIs |
| Vue client | Vue runtime/compiler markers and chunks | `v-html`, runtime templates, router guards versus API authz, public `VITE_`/Vue CLI variables |
| Nuxt | `__NUXT__`/payload data, `/_nuxt/`, Nitro server behavior | `/api` and server routes, route middleware not covering server handlers, runtime config public/private split, hybrid route-rule caching |
| Angular client/SSR | Angular bootstrap/chunks, `ng-version` when retained | `bypassSecurityTrust*`, direct DOM APIs, JIT/dynamic templates, XSRF client/server agreement, SSR trusted proxy/host configuration |
| Svelte/SvelteKit | Svelte chunks plus `__data.json`/form-action behavior | server `load` data crossing to client, form actions, hooks versus endpoint authz, SSR cache variation |
| Astro | islands and framework-specific asset layout | static versus server output, actions/API routes, server-rendered islands, integrations that add a backend unexpectedly |
| SolidStart / Qwik | resumability/server-function artifacts | serialized state, server functions, action authorization and cache behavior |
| Ember / Backbone / jQuery | recognizable runtime/bundle, client router | legacy APIs, template/HTML escape hatches, route discovery, outdated plugins and direct DOM sinks |
| HTMX / Alpine / Lit / Web Components | request attributes, custom elements, small reactive runtime | server-returned fragments, attribute/HTML sinks, event/message boundaries, API authorization behind declarative UI |

## Evidence extraction

Inspect existing artifacts before requesting more:

- route/build/asset manifests and lazy chunk names;
- source maps and `sourcesContent`;
- serialized hydration/SSR/RSC payloads on pages with different principals;
- public runtime configuration and API/identity endpoints;
- client code calling actions, loaders, API routes, WebSockets and `postMessage`;
- cache headers while identity, locale, device and query/header inputs change;
- lockfiles/package metadata only when actually exposed.

Do not report public client configuration merely because it contains `PUBLIC`, `VITE_`,
`REACT_APP_` or equivalent. Determine what privilege the value grants.

## Hypothesis transforms

| observed mechanism | investigate | canonical classes |
|---|---|---|
| UI/router hides a route or operation | call the backing entrypoint with a lower/different principal | `function-level-authorization`, `idor-bola` |
| server data serialized to client | compare fields across page/data channels and principals; identify the missing ownership, tenant, cache or authorization boundary | `idor-bola`, `multi-tenant-isolation`, `cache-poisoning` or `function-level-authorization` only when that invariant fits; otherwise keep it as an unclassified disclosure hypothesis |
| raw HTML/trusted-value escape hatch fed by controllable data | trace source to rendering context and declare a safe oracle | `xss`, `dom-clobbering` |
| message listener or embedded OAuth popup | origin/source validation and capability of messages | `postmessage`, `oauth-oidc` |
| server action/function endpoint | input validation, re-authorization, object binding, CSRF/origin model | `function-level-authorization`, `mass-assignment`, `csrf` |
| image/proxy/preview/import accepts a URL | destination policy, redirects and DNS behavior | `ssrf` |
| personalized SSR response is cached | compare cache key to response-varying identity/input | `cache-poisoning` |
| client-only security control | identify the real server enforcement point | the class implied by the protected operation, usually access control or workflow |

An observed disclosure can remain a hypothesis without a class. Do not force it into the closest
catalogue entry merely to make coverage tooling count it.

## Lower priority only with evidence

- Escaped template interpolation lowers ordinary reflected XSS only when the value stays inside the
  framework renderer; direct DOM APIs and trust-bypass functions restore priority.
- A static deployment lowers server-side classes only after confirming there is no backing
  function, preview, image optimizer, revalidation or separate API.
- Client routing never lowers API authorization priority.
- A source map missing at one guessed path proves nothing; prefer manifest/chunk evidence.

## Current official sources

- React security notices and release posts: <https://react.dev/blog>
- Next.js security/data guidance and advisories: <https://nextjs.org/docs/app/guides/data-security>
  and <https://github.com/vercel/next.js/security/advisories>
- Angular security guide: <https://angular.dev/best-practices/security>
- Vue security guide: <https://vuejs.org/guide/best-practices/security.html>
- Nuxt server/routing documentation: <https://nuxt.com/docs/4.x/directory-structure/server>
- SvelteKit documentation: <https://svelte.dev/docs/kit>

Use [`live-research.md`](live-research.md) before making version- or release-dependent claims.
