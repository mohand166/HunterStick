# Backend framework lens

Load this for application servers that route requests, bind parameters, render templates or expose
management endpoints. A language fingerprint alone is insufficient; identify the framework,
middleware and deployment mode.

## Control map by ecosystem

| ecosystem | products covered | distinctive mechanisms to locate |
|---|---|---|
| Node.js | Express, NestJS, Fastify, Koa, Hapi, AdonisJS, Meteor | middleware/route order, `trust proxy`, body parsers, static roots, template engine, decorators/guards, plugin registration, realtime methods |
| Python | Django, Flask, FastAPI/Starlette, Pyramid, Tornado, aiohttp | URL converters, middleware/dependencies, ORM/raw queries, signed sessions, debug/error mode, admin/docs, schema binding, async/WebSocket handlers |
| Ruby | Rails, Sinatra | routes/formats, controller callbacks, strong parameters, Active Record/raw SQL, encrypted cookies, Active Storage, jobs |
| PHP | Laravel, Symfony, CodeIgniter, Yii, CakePHP | front controller/docroot, middleware/firewalls, route-model conversion, forms/serializers, debug toolbars, Composer packages |
| JVM | Spring Boot/MVC/Security, Struts, JSF, Quarkus, Micronaut, Grails, Play | servlet filters, controller binding, expression/template engines, management ports, serialization libraries, reverse-proxy path handling |
| .NET | ASP.NET Core/MVC, Minimal APIs, Blazor Server, legacy ASP.NET | middleware/modules order, endpoint routing, auth schemes/policies, model binding, Data Protection/machine keys, SignalR, forwarded headers |
| Go | `net/http`, Gin, Echo, Fiber | router groups/middleware inheritance, proxy headers, binder behavior, static/file helpers, custom auth wrappers |
| Elixir | Phoenix/LiveView | plugs/pipelines, signed session, LiveView events, channels, Ecto changesets and scopes |
| Rust | Actix, Axum, Rocket | extractors, middleware/layers, route nesting, state sharing, templating and file responders |
| CFML | Adobe ColdFusion, Lucee | component/remote methods, mappings, administrator surface, serialization, file/template includes and Java interop |

## Framework-specific questions

### Node.js

- Does `trust proxy` cause client-controlled forwarding headers to influence scheme, IP, host or
  secure-cookie logic?
- Do nested routers or framework guards cover every method/content type and generated endpoint?
- Which body parsers run before signature verification, and do raw-body webhooks take a different
  path?
- Are static files, source maps, package manifests or development endpoints served by a separate
  middleware order?
- For NestJS, compare global/controller/method guards and pipes; decorators are not proof that the
  runtime path uses them.

### Django / Flask / FastAPI

- Django: distinguish `DEBUG`, admin exposure, `ALLOWED_HOSTS`, CSRF middleware, object lookup
  scoping and raw SQL. ORM use lowers ordinary SQLi only for the observed query path.
- Flask: identify session signing, proxy middleware, blueprint prefixes, debug mode and whichever
  extensions supply auth/ORM/CSRF—Flask core intentionally leaves these choices open.
- FastAPI/Starlette: use OpenAPI as a contract, then check dependencies at router and operation
  level, Pydantic coercion/extra fields, file/background tasks and trusted-host/proxy middleware.

### Rails

- Compare resource lookup (`Model.find(params[:id])`) with principal-scoped lookup.
- Trace `permit`/strong-parameter decisions and nested attributes rather than assuming mass
  assignment is open or closed.
- Check route format variants, mounted engines, Active Storage variants/direct uploads, job
  processors and redirects/file sends.
- Encrypted cookies and CSRF are defaults, not evidence that this target preserved them.

### PHP frameworks

- Confirm the web document root; exposed project root makes `.env`, Composer files, storage/logs and
  vendor metadata relevant.
- Identify automatic object/model conversion separately from authorization voters/policies.
- Find raw-query, raw-template and serializer escape hatches rather than spraying injection tests at
  ORM-backed paths.
- Treat dev toolbars, profilers, Telescope/Horizon/Ignition and cache/admin consoles as
  configuration-dependent surfaces.

### JVM frameworks

- Map edge → servlet container → filter chain → dispatcher/controller. Path decoding and matrix
  parameters can differ at each hop.
- Separate Spring Boot management endpoints from application endpoints and check management base
  path, port, exposure and security independently.
- Inventory Jackson, SnakeYAML, XML parsers, template/expression engines and logging packages;
  reachability matters more than the top-level framework label.
- For Struts/JSF or legacy containers, establish exact versions before advisory research; banners
  are frequently proxy or container claims.

### ASP.NET Core

- Reconstruct middleware order: forwarded headers, path base, routing, authentication,
  authorization, static files and endpoints.
- Identify active authentication schemes; a cookie, JWT bearer and external OIDC handler can apply
  to different routes.
- Compare controller authorization attributes, fallback policies and Minimal API endpoint metadata.
- Inspect model binding/JSON options, Razor rendering, SignalR hubs, Data Protection key sharing and
  development exception endpoints where evidence exposes them.

### Go, Phoenix and Rust

- Frameworks are small enough that custom middleware is often the real security architecture.
- Compare parent router/group protections with separately registered routes and method variants.
- Inspect binders/extractors for alternate content types and field coercion.
- Phoenix LiveView/channel events and WebSocket messages need the same object/function
  authorization as HTTP controllers.

## Cross-framework hypothesis transforms

| mechanism | candidate classes |
|---|---|
| automatic object lookup separate from policy/ownership | `idor-bola`, `function-level-authorization` |
| request body bound to model/schema with permissive fields | `mass-assignment`, `privilege-escalation` |
| raw query/template/command escape hatch | the matching injection class only when the sink is evidenced |
| proxy/application path or host disagreement | `function-level-authorization`, `host-header-attacks`, `request-smuggling` |
| debug/management surface with sensitive state | record disclosure/management hypotheses; map to a class only when its invariant fits |
| signed/encrypted client state using shared or leaked key | `session-management`, possibly `privilege-escalation` |
| parser or processing component reachable from an upload/import | `file-upload`, `xxe`, `deserialization`, `path-traversal` as evidence supports |

## Lower priority only with evidence

- ORM-backed operations lower generic SQLi only after proving the specific sink stays parameterized;
  raw query APIs restore it.
- Default CSRF middleware lowers CSRF only on routes actually inside that middleware and using an
  ambient credential.
- Framework escaping lowers template-output XSS only until an unsafe/raw rendering API appears.
- Packaged deployments lower writable-webroot attacks, not arbitrary file read/write through
  application features.

## Current official sources

- Django security and release notes: <https://docs.djangoproject.com/en/dev/topics/security/>
- Rails security guide and security policy: <https://guides.rubyonrails.org/security.html>
- Express security practices: <https://expressjs.com/en/advanced/best-practice-security.html>
- FastAPI security reference: <https://fastapi.tiangolo.com/tutorial/security/>
- Laravel documentation and advisories: <https://laravel.com/docs> and
  <https://github.com/laravel/framework/security/advisories>
- Spring Boot Actuator endpoints: <https://docs.spring.io/spring-boot/reference/actuator/endpoints.html>
- ASP.NET Core security: <https://learn.microsoft.com/aspnet/core/security/>
- Phoenix security guide: <https://hexdocs.pm/phoenix/security.html>

Use [`live-research.md`](live-research.md) for supported versions, changed defaults and advisories.
