# Laravel

> Laravel's effective security model depends on route groups/middleware, policies, model binding,
> session driver, serialization and deployed first/third-party packages. Strong defaults and severe
> deployment mistakes can coexist; establish the target path rather than assuming either.

## 1 · Identity and deployment modes

Record web/session application versus token API, first-party SPA/Sanctum use, queue workers, file
storage, broadcast/WebSocket features, and whether Telescope, Horizon, Ignition or another package
is deployed. Confirm the actual web document root and reverse-proxy layer.

## 2 · Fingerprint and disambiguation

- **Confirms:** multiple consistent Laravel artifacts such as `laravel_session` + `XSRF-TOKEN`,
  Laravel/Ignition error metadata, or Composer/source evidence.
- **Corroborates:** Laravel-specific status/error conventions and first-party package routes.
- **Suggests only:** a `419`, an `XSRF-TOKEN` cookie, PHP headers or generic Composer paths.
- **Negative case:** other frameworks use the same CSRF cookie name or PHP ecosystem packages.

## 3 · Version and component identity

Composer lock/package evidence can pin framework and dependencies; exposed debug metadata may only
bound them and may be stale. Identify Laravel, PHP, Symfony components, Ignition, Sanctum/Passport,
Telescope, Horizon and other relevant packages separately. Without version-bearing evidence record
`unknown`; never infer a framework release solely from UI appearance.

## 4 · Native surface

| observed mechanism | what it changes |
|---|---|
| route groups and `web`/`api` middleware | session, CSRF, rate and authentication controls may differ by route registration |
| implicit/explicit route-model binding | object resolution is separate from policy/ownership authorization |
| form-method spoofing (`_method`) | edge, middleware and route may reason about different apparent methods |
| Eloquent fill/guard and API resources | input binding and output serialization have explicit allow/deny controls plus escape hatches |
| signed/encrypted cookies or URLs | key use and verification depend on application/session configuration |
| Telescope/Horizon/Ignition/debug routes | separate operational packages and authorization boundaries may exist |
| queues/jobs/events/webhooks | user input can cross into delayed processors outside the request middleware chain |
| storage disks and temporary URLs | upload, local/cloud storage, visibility and delivery controls compose |

Do not probe development or writable operational actions merely because a historic path is known.
First establish that the package/route exists and what non-state-changing oracle is permitted.

## 5 · Security controls and trust boundaries

For each route record middleware, credential model, policy/gate, model scope, validation/form
request, mass-assignment allowlist, serializer/resource and rate limit. Determine whether a proxy
and Laravel agree on host, scheme, path and effective method. If application keys are exposed,
identify exactly which target data they protect and whether the current session driver/client state
uses them before deriving impact.

## 6 · Target-specific hypothesis transforms

| observed feature | boundary and oracle | canonical class |
|---|---|---|
| bound model is not principal-scoped or policy-covered | owner versus non-owner object under same route | `idor-bola` |
| action exists outside expected middleware/policy group | authorized versus lower principal, same operation | `function-level-authorization`, `privilege-escalation` |
| validated request feeds permissive fill/update fields | harmless protected field versus allowed control field | `mass-assignment` |
| controllable value reaches `whereRaw`, `DB::raw` or equivalent sink | safe paired oracle on the evidenced query | `sql-injection` |
| serialized/unserialized client or job data reaches object handling | benign type/class discriminator with parser reachability | `deserialization` |
| proxy/origin disagree about effective method or trusted host/scheme | smallest safe request pair, same route and principal | class implied by the bypassed control |
| key or debug data is exposed | prove the specific session, signing, storage or authorization capability it enables | `session-management` or applicable class; exposure alone may remain unclassified |

## 7 · Lower-priority paths

- A valid CSRF rejection lowers CSRF only for the exact route/method/credential path observed.
- Eloquent lowers ordinary SQL injection only where the evidenced query remains parameterized; raw
  expressions and custom repositories restore priority.
- Fillable/guarded configuration lowers mass assignment only for the observed write path.
- A correctly configured public document root lowers direct project-file exposure; alternate file
  reads, backups and application download features remain separate.

## 8 · Live research entrypoints

- Laravel security and general documentation: <https://laravel.com/docs>
- Framework repository advisories: <https://github.com/laravel/framework/security/advisories>
- Eloquent mass-assignment behavior: <https://laravel.com/docs/12.x/eloquent#mass-assignment>
- Routing and method spoofing: <https://laravel.com/docs/12.x/routing>

Use [`references/live-research.md`](references/live-research.md) for package/release questions and
`playbooks/workflows/research-component.md` for a pinned reachable component.

## 9 · Noise, ownership and stop conditions

A `419`, framework cookie, authenticated dashboard or blocked dotfile is not a finding. A failed
request to one remembered debug path does not prove the package absent. Stop an advisory path when
package identity/version/mode is unresolved, and stop any operational check before it executes a
solution, changes queue/log state or accesses unrelated user data.

## 10 · Checks — the `component-hunt` catalog

> Executed by `skills/vulnerability-testing/component-hunt.md` on a hunter-named host whose
> fingerprint matches this profile. One request per check, read-only. Ignition/exploitation
> chains and known CVEs stay with `n-day-sweep` once the version is pinned.

| check | precondition | probe | a hit is | safety | on hit → class | fix_locus |
|---|---|---|---|---|---|---|
| env file exposure | Laravel fingerprint (§2) | `GET /.env` | `KEY=VALUE` ini-style body — not the framework HTML error page | **presence-only** — store the response with values masked; key names + count is the proof | `origin-exposure` (`cloud-misconfiguration` when cloud creds) | web-server dotfile serving / docroot |
| application log | Laravel fingerprint | `GET /storage/logs/laravel.log` | log-shaped text (timestamps, levels, stack traces) | read | `origin-exposure` | storage path exposure |
| dev tooling | Telescope in stack (composer lock, bundle refs) | `GET /telescope` | Telescope UI markup/JSON (not auth redirect to login) | read | unauthenticated debug console → `function-level-authorization` | Telescope gate config / route middleware |
| Ignition present | Laravel + debug mode suspected | `GET /_ignition/health-check` | the Ignition health JSON shape | **presence-only** | version-gated chain → `n-day-sweep` once version known | debug mode (`APP_DEBUG`) |
| session cookie shape | Laravel fingerprint | read the `Set-Cookie: laravel_session` attributes | missing `Secure`/`HttpOnly`/`SameSite` | passive | `session-management` hypothesis | cookie config |

APP_KEY-derived deserialization chains are version- and config-gated: record the key's
exposure as `origin-exposure` evidence and route exploitation to `vuln-hunt` with the
`deserialization` class file.
