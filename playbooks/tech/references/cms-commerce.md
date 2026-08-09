# CMS and commerce lens

CMS and commerce products are **platform + extensions + theme/custom code + operational consoles**.
The product name alone is rarely the most actionable component.

## Decompose before testing

| layer | identify |
|---|---|
| core/product | exact or bounded version, supported release line, managed versus self-hosted |
| extensions | plugin/module/package name, slug, version and public entrypoints |
| theme/template | custom rendering, upload/static roots and source maps |
| content API | REST/GraphQL/JSON:API routes, preview/draft behavior, localization and roles |
| admin/author | login, authoring, import/export, scheduled jobs and privileged consoles |
| media pipeline | upload, transforms, archives, SVG, PDF/image/video processors and public delivery |
| cache/search | full-page cache, Varnish/CDN, indexes and per-user variation |
| integrations | webhooks, feed import, SSO, payment, shipping and marketplace extensions |

## Product routing

| product | distinctive surface and focus |
|---|---|
| WordPress / WooCommerce | REST route index, `admin-ajax` actions, plugins/themes, uploads, XML-RPC, WooCommerce account/order/cart workflows |
| Drupal | core versus contributed modules, `/user` and JSON:API/REST surfaces, files/styles, trusted-host config, cache contexts/tags, update status |
| Joomla | components/modules/plugins and task routing, API/admin surfaces, media/templates and extension versions |
| TYPO3 / Craft CMS / Wagtail | plugin/module packages, control panel, preview/draft APIs, media transforms, template behavior and framework underneath |
| Adobe Commerce / Magento | storefront REST/GraphQL, customer/admin areas, modules, media/imports, cache/Varnish, asynchronous consumers, patch-level version |
| AEM | author versus publish, Sling resource resolution/selectors/extensions, content repository paths, dispatch/cache layer, packages and replication |
| Sitecore / Umbraco | content APIs, authoring/admin surfaces, serialization/packages, media handlers and custom modules |
| Shopware / PrestaShop | plugins/modules, storefront/admin APIs, cart/order/discount state machines, media/import/export and webhooks |
| Ghost | Content API versus Admin API, themes, integrations/webhooks, preview/members/newsletters |
| Strapi / Directus | generated content APIs, roles/permissions, admin/plugin surfaces, media providers and custom controllers/hooks |
| Contentful / Sanity | public delivery/preview APIs versus management APIs, tokens by role, drafts, webhooks and asset pipelines |
| Shopify/headless | hosted platform versus merchant-owned app/theme, Storefront/Admin APIs, app proxies, webhooks, checkout/cart extensions |

For hosted SaaS, determine what the program owns. A platform behavior may be out of scope while the
merchant's app, theme, webhook or exposed token is in scope.

## High-yield reasoning patterns

### Extension routes

Extract the installed extension and its routes/actions from manifests, assets and API indexes. Test
the extension's own authentication and object/function authorization; do not assume core middleware
protects a separately registered handler.

### Content lifecycle

Model draft → preview → publish → cache → archive. Compare principals and alternate delivery APIs.
Preview and headless APIs frequently expose a different representation from the public page.

### Media and import pipelines

Identify the actual processor and storage/delivery boundary before selecting `file-upload`, `ssrf`,
`xxe`, `path-traversal` or `deserialization`. Filename/extension behavior alone does not identify the
sink.

### Commerce state

Use canonical business-logic classes for cart ownership, price/currency, coupons, inventory,
shipping, payment callbacks, refund/return and order transitions. Framework technology supplies the
entrypoints; the violated business invariant supplies the class.

### Cache context

CMS caches may vary by role, language, route, device or query/header context. Compare declared cache
variation to content that changes; do not assume “CMS + cache” means poisoning.

## Lower priority only with evidence

- Heavily reviewed core lowers core-bug priority only when exact version is supported and patched.
  Extensions and custom code remain separate.
- A managed platform lowers server configuration testing only for platform-owned infrastructure.
- An API index or login page is not a finding.
- Public author/content metadata may be intentional; confirm policy and impact.

## Current official sources

- WordPress developer security documentation: <https://developer.wordpress.org/apis/security/>
- Drupal advisories, core and contributed projects: <https://www.drupal.org/security/home>
- Joomla security centre: <https://developer.joomla.org/security-centre.html>
- Adobe security bulletins for Commerce and AEM: <https://helpx.adobe.com/security/security-bulletin.html>
- Shopware security updates: <https://docs.shopware.com/en/shopware-6-en/security-updates>
- Strapi security advisories: <https://github.com/strapi/strapi/security/advisories>
- Directus security advisories: <https://github.com/directus/directus/security/advisories>

Extension advisories require canonical package identity, version and reachability. Use
[`live-research.md`](live-research.md), never a frozen “top vulnerable plugins” list.
