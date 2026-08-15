# WordPress

> Analyze WordPress as core + plugins + theme/custom code + hosting/cache + integrations. Core is
> not automatically safe and plugins are not automatically vulnerable; component identity,
> reachability and the target's controls decide priority.

## 1 · Identity and deployment modes

Distinguish classic site, multisite, WooCommerce, headless backend, managed hosting and a site where
WordPress sits behind a cache/WAF. Record whether REST, XML-RPC, authoring, media and scheduled jobs
are used. A headless frontend may hide the WordPress origin on another in-scope host.

## 2 · Fingerprint and disambiguation

- **Confirms:** consistent `/wp-content/` or `/wp-includes/` assets, WordPress REST index behavior,
  or WordPress-specific cookie/runtime evidence.
- **Corroborates:** `X-Pingback`, generator metadata and canonical WordPress endpoint behavior.
- **Suggests only:** `wp-` strings or a theme appearance copied by a static mirror.
- **Negative case:** a CDN copy of WordPress assets does not prove the responding origin runs PHP.

## 3 · Version and component identity

Treat generator tags and core asset query versions as claims or bounds; caches, themes and asset
pipelines may preserve stale values. Identify every relevant plugin/theme by canonical slug and seek
its own version evidence. A deployed `readme.txt` may describe a package release but does not alone
prove the active code matches it. Record core and each extension separately as `exact`, `bounded`
or `unknown`.

## 4 · Native surface

| observed mechanism | what it changes |
|---|---|
| `/wp-json/` route index | core and plugin REST namespaces/operations can be mapped from deployed behavior |
| `admin-ajax.php` / `admin-post.php` with `action=` | the action selects a registered plugin/theme handler |
| `wp_ajax_nopriv_*` behavior | that specific action is intentionally callable without login; its operation still needs appropriate controls |
| nonces + capability checks | request intent and authorization are separate controls |
| media/uploads and transform endpoints | web delivery, metadata, processor and storage boundaries compose |
| XML-RPC | a legacy integration/publishing surface exists; presence alone has no impact |
| WooCommerce/store APIs | cart, account, order, coupon, payment and webhook state machines exist |
| multisite | network, site, tenant and role boundaries may differ |

Derive routes and action names from the REST index, legitimate traffic and deployed JS/PHP
artifacts—not a generic action wordlist.

## 5 · Security controls and trust boundaries

For each plugin/core operation, locate authentication, nonce verification, capability check, object
ownership and sanitization separately. Compare path-based REST and supported alternative routing
only when captured behavior shows both. Map upload permission, file validation, processor, storage
and public delivery as distinct controls. For cached pages, record role, login, locale and cart
variation. Treat the plugin that registers the handler as the likely fix locus.

## 6 · Target-specific hypothesis transforms

| observed feature | boundary and oracle | canonical class |
|---|---|---|
| plugin action checks nonce but not capability/role | same action with two controlled principals | `function-level-authorization`, `privilege-escalation` |
| REST/action handler accepts an object ID | owner versus non-owner object with identical operation | `idor-bola` |
| handler builds a raw query from controllable fields | safe true/false or type oracle at the evidenced sink | `sql-injection` |
| upload/import reaches a named processor or public path | accepted safe control versus minimally discriminating file/metadata case | `file-upload`, or parser class supported by evidence |
| personalized/admin/draft content reaches shared cache | paired principals with calibrated cache behavior | `cache-poisoning` |
| cart/order/coupon/payment transition violates ownership or state | model the business invariant and use the matching business-logic class | applicable canonical business-logic class |
| exact reachable extension falls in an upstream affected range | advisory AND gate, then hand off to `research-component` | class defined by the advisory mechanism |

## 7 · Lower-priority paths

- Supported, patched core lowers a known-core-advisory path only after version/support evidence;
  custom code and extensions remain separate.
- Nonce rejection lowers CSRF for that exact operation but says nothing about authorization.
- Managed hosting lowers platform configuration testing only where the provider owns the control.
- Public author/content metadata is lower priority when program policy and content intent confirm it.

## 8 · Live research entrypoints

- WordPress security APIs and developer guidance: <https://developer.wordpress.org/apis/security/>
- WordPress core security releases: <https://wordpress.org/news/category/security/>
- WordPress plugin directory/repository: <https://wordpress.org/plugins/>
- WooCommerce security policy/advisories: <https://github.com/woocommerce/woocommerce/security>

Use upstream repositories and [`references/live-research.md`](references/live-research.md) for core,
plugin and theme version applicability. Third-party vulnerability databases are correlation aids,
not proof of active version or reachability.

## 9 · Noise, ownership and stop conditions

REST indexes, XML-RPC, login pages, published authors and predictable media URLs are usually
surface facts. Do not brute-force users or credentials. Stop an extension advisory path when the
slug, active version, affected feature or route reachability remains unproved. A cache/WAF response
may fingerprint an old deployment; preserve the conflict instead of choosing the exciting version.

## 10 · Checks — the `component-hunt` catalog

> Executed by `skills/vulnerability-testing/component-hunt.md` on a hunter-named host whose
> fingerprint matches this profile. One request per check, read-only. Behavioral abuse
> (XML-RPC methods, plugin CVEs) is deliberately not probed here — presence is recorded, the
> abuse is a `vuln-hunt`/`n-day-sweep` decision.

| check | precondition | probe | a hit is | safety | on hit → class | fix_locus |
|---|---|---|---|---|---|---|
| REST user listing | WordPress fingerprint (§2) | `GET /wp-json/wp/v2/users` | JSON array of objects with `slug` fields — 401/403/redirect is *restricted*, record that | read | `user-enumeration`; slugs feed credential worklists | REST filter on sensitive controller fields |
| REST namespaces | WordPress fingerprint | `GET /wp-json/` | JSON with non-default `namespaces` — custom plugin APIs | read | surface fact → `@endpoints`/`@components` | — (recon, not a finding) |
| core version file | WordPress fingerprint | `GET /readme.html` | WordPress-branded readme naming the version | read | version → `@components` (feeds cohort + tech-watch) | informational; not a report |
| debug log | `WP_DEBUG` suspected (verbose errors seen) | `GET /wp-content/debug.log` | non-HTML text with PHP notices/warnings/deprecations | read | `origin-exposure` (paths, queries, sometimes keys) | `WP_DEBUG` display/log config |
| XML-RPC presence | WordPress fingerprint | `GET /xmlrpc.php` | XML-RPC fault or method-list response (not the theme 404) | read | presence only → hypothesis for `ssrf` (pingback) / `limit-bypass` (multicall) — both need ACT-mode confirmation | `XMLRPC`/`.htaccess` restrictions |
| plugin inventory | WordPress fingerprint | `GET /wp-content/plugins/<slug>/readme.txt` for slugs already evidenced (bundles, page source) — never brute-forced | stable-tag + plugin name/version | read | versions → `@components` → n-day cohort | — (recon) |
| login surface | WordPress fingerprint | `GET /wp-login.php` | 200 login form | read | surface fact → `login` class entrypoint | — (recon) |

Do not extend this table with brute-forced plugin slugs or theme guesses; that is
content-discovery's discipline, not this catalog's.
