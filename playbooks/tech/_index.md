# Technology analysis router

> A fingerprint is not a vulnerability and a framework name is not a test plan. This library turns
> observed technology into **target-specific questions about trust boundaries, configuration,
> composition and reachable components**.

Read [`_analysis.md`](_analysis.md) first. Then load only the deep profile and family reference that
match the observed stack. Never preload the whole directory.

## Routing rule

| evidence | load |
|---|---|
| a deep profile exists below | `_analysis.md` + that profile + its family reference |
| the product is in the coverage map | `_analysis.md` + the named family reference |
| the product is unknown, forked or proprietary | `_analysis.md` + [`live-research.md`](references/live-research.md) |
| several technologies compose one app | one row per layer; load every relevant family, then analyze the seams |
| a versioned package/component is present | this skill for reachability + `research-component` for current advisories |
| the hunter asked to **actively probe** the stack's known misconfigs | that profile's `## Checks` catalog via the `component-hunt` skill — analysis files record hypotheses; only that skill sends the catalog's requests |

The profiles are **seeds, not limits**. Target behavior and current official documentation outrank
them. A missing deep profile is not a blind spot because every product routes through a family lens
and the live-research fallback.

## Deep profiles

| file | positive fingerprint | family |
|---|---|---|
| [`nextjs.md`](nextjs.md) | `__NEXT_DATA__`, `/_next/`, RSC/Server Action traffic | [frontend/meta](references/frontend-meta.md) |
| [`react.md`](react.md) | React root/bundle evidence; **client-only mode** | [frontend/meta](references/frontend-meta.md) |
| [`wordpress.md`](wordpress.md) | `/wp-content/`, `/wp-json/`, WordPress cookies | [CMS/commerce](references/cms-commerce.md) |
| [`laravel.md`](laravel.md) | `laravel_session`, `XSRF-TOKEN`, Laravel error behavior | [backend frameworks](references/backend-frameworks.md) |
| [`spring-boot.md`](spring-boot.md) | Actuator links or Spring Boot error shape | [backend frameworks](references/backend-frameworks.md) |

## Broad coverage map

These are mechanism lenses, not claims that every deployment exposes every feature.

| family reference | technologies covered |
|---|---|
| [Frontend and meta-frameworks](references/frontend-meta.md) | React, Next.js, React Router/Remix, Gatsby, Vue, Nuxt, Angular/Angular SSR, Svelte/SvelteKit, Astro, SolidStart, Qwik, Ember, Backbone, jQuery, HTMX, Alpine, Lit/Web Components, Vite/Webpack applications |
| [Backend frameworks](references/backend-frameworks.md) | Express, NestJS, Fastify, Koa, Hapi, AdonisJS, Meteor; Django, Flask, FastAPI/Starlette, Tornado/aiohttp; Rails, Sinatra; Laravel, Symfony, CodeIgniter, Yii, CakePHP; Spring, Struts, JSF, Quarkus, Micronaut, Grails/Play; ASP.NET Core/MVC, Blazor and legacy ASP.NET; Gin, Echo, Fiber; Phoenix; Actix, Axum, Rocket; ColdFusion/CFML |
| [CMS and commerce](references/cms-commerce.md) | WordPress/WooCommerce, Drupal, Joomla, TYPO3, Craft CMS, Wagtail, Adobe Commerce/Magento, AEM, Sitecore, Umbraco, Shopware, PrestaShop, Ghost, Strapi, Directus, Contentful, Sanity, Shopify/headless storefronts |
| [API, realtime and edge](references/api-edge.md) | Apollo, GraphQL Yoga, GraphQL Java, Hot Chocolate, Hasura; REST/OpenAPI, SOAP/WSDL, OData, JSON-RPC/tRPC, gRPC-web, WebSocket/Socket.IO; Kong, Envoy, NGINX, HAProxy, Traefik, Apigee, AWS API Gateway, Azure API Management, Cloudflare |
| [Identity and BaaS](references/identity-baas.md) | Keycloak, Auth0, Okta, Cognito, Entra ID, Ping, WSO2, FusionAuth, OneLogin, Shibboleth/CAS, Clerk, WorkOS, Firebase Auth; Firebase, Supabase/PostgREST, Hasura, Appwrite, PocketBase |
| [Enterprise and infrastructure](references/enterprise-infra.md) | Jenkins, GitLab, Jira/Confluence, SharePoint, Exchange/OWA, Grafana, Kibana/Elastic, Kubernetes dashboards, Argo CD, Airflow, Jupyter, SonarQube, Nexus/Artifactory, Harbor, Tomcat, Jetty, WebLogic, WildFly/JBoss, vCenter, Citrix NetScaler, Fortinet, Ivanti, Zimbra; nginx, Apache HTTP Server, IIS, Caddy |

If a technology is absent from the written names, classify it by **what it does** rather than by
language:

```text
renders in the browser          → frontend/meta
routes/binds/serializes server  → backend framework
installs extensions/content     → CMS/commerce
brokers or transforms traffic   → API/edge
issues identity or exposes data → identity/BaaS
administers code/infrastructure → enterprise/infra
```

## Components the framework name hides

Do not stop at “Django,” “Java” or “React.” Check artifacts for the components performing these
jobs; they often have a more actionable version and attack surface than the top-level framework:

| job | examples to identify, not assume |
|---|---|
| authentication/session | Passport, Devise, Spring Security, NextAuth/Auth.js, Keycloak adapters |
| serialization/parsing | Jackson, SnakeYAML, XStream, Newtonsoft.Json, PyYAML, XML parsers |
| file/media processing | ImageMagick, Sharp/libvips, Ghostscript, FFmpeg, PDF generators |
| templates/rendering | Blade, Twig, Jinja, ERB, Thymeleaf, Razor |
| data access | Eloquent, Doctrine, Active Record, Hibernate, Entity Framework, Prisma, Mongoose |
| API engines | Apollo, Hasura, GraphQL Java, Hot Chocolate, PostgREST |
| queues/jobs | Celery, Sidekiq, BullMQ, Horizon, Hangfire |
| editors/upload widgets | CKEditor, TinyMCE, file managers and archive extractors |
| edge/cache | Varnish, nginx cache, Cloudflare, Fastly, framework data caches |
| observability/admin | Grafana, Kibana, Sentry, APM agents, debug toolbars and health/metrics consoles |
| protocol/identity clients | OAuth/OIDC/SAML libraries, JWT validators, webhook signature middleware, GraphQL/gRPC engines |

`component-inventory` records exact/bounded/unknown versions. `research-component` checks current upstream
advisories. Presence alone remains a hypothesis until an in-scope entrypoint reaches the component.

## Composite stacks: analyze seams first

Real applications are graphs, not labels. Examples:

- **Next.js → Auth0 → GraphQL → Rails**: compare authorization at the page, Server Action, gateway
  and resolver; do not assume middleware protects all four.
- **React → Supabase**: the publishable key is expected in the bundle; RLS, grants, storage rules and
  privileged edge functions are the boundary.
- **Cloudflare → nginx → Spring Boot**: compare normalization, cache keys, forwarded headers and
  access rules at every hop.
- **WordPress → plugin → external webhook**: core defaults say little about the plugin route or the
  outbound trust boundary.

The highest-value hypothesis is often the disagreement between layers, not a famous bug in one
layer.

## Currentness

No CVE list lives here. Versions, defaults and security behavior change. When the conclusion depends
on a release line, deployment mode or advisory, use [live research](references/live-research.md),
record the retrieval date and preserve the official source URL. A deep profile that conflicts with
current upstream documentation is stale; follow upstream and note the library gap.
