# Next.js

> Next.js can be a static exporter, Pages Router server, App Router/RSC application, Server Action
> host, edge deployment or a mixture. Establish the deployed mode before deriving a security
> question.

## 1 · Identity and deployment modes

Record Pages Router versus App Router, static versus dynamic rendering, self-hosted versus managed
platform, middleware/proxy use, and whether Server Actions, route handlers, image optimization,
rewrites or revalidation are actually present. These mechanisms do not share one authorization or
cache boundary.

## 2 · Fingerprint and disambiguation

- **Confirms:** `__NEXT_DATA__`, `/_next/static/` assets, a captured RSC/Next framework request, or
  several mutually consistent Next response artifacts.
- **Corroborates:** Pages build manifests and `x-nextjs-*` headers. Record the emitting layer.
- **Suggests only:** `X-Powered-By: Next.js` or Vercel headers. Vercel hosts non-Next applications.
- **Negative case:** React by itself proves neither Next.js nor a server-side React mode.

Use a second independent signal before treating a header or scanner label as confirmed.

## 3 · Version and component identity

A `buildId` identifies a deployment, not a Next.js version. Exact versions normally require
package/lock metadata, a source map or another version-bearing artifact. Router features may only
bound a release line. Record `exact`, `bounded` or `unknown`, and identify related RSC packages
separately when an advisory concerns them.

## 4 · Native surface

| observed mechanism | what it changes |
|---|---|
| `/_next/static/` chunks/manifests | route, action, API and component evidence may exist in client artifacts |
| `__NEXT_DATA__` or Pages data requests | server-selected data crosses a separate serialization channel |
| RSC/framework requests | server-rendered component data may differ from visible HTML and client navigation |
| captured Server Action request | a public server entrypoint exists without a conventional hand-written route |
| `/api/*` or route handlers | server endpoints have authorization and binding separate from page visibility |
| `/_next/image` | the server may fetch and transform a configured remote image source |
| rewrites, middleware/proxy, preview or revalidation | another routing, trust or cache boundary exists |

Do not guess action identifiers, internal request bodies or manifest paths. Derive them from this
deployment's traffic and assets.

## 5 · Security controls and trust boundaries

Locate authorization in the action/handler/data loader, not merely in UI routing. Compare page,
client navigation, Pages data, RSC and action entry modes. Record which props are intentionally
serialized to the client. At every active cache layer, compare the cache key with identity, locale,
headers, cookies and query values that change the response. For image/rewrites, establish the
actual destination allow policy and which layer follows redirects.

Middleware may participate in control enforcement, but official guidance still requires
authentication and authorization inside Server Actions. Target behavior determines whether other
generated or custom entrypoints receive equivalent checks.

## 6 · Target-specific hypothesis transforms

| observed feature | boundary and oracle | canonical class |
|---|---|---|
| action/handler reachable by a principal that cannot see its UI | compare the same operation and side-effect with authorized and lower principals | `function-level-authorization` |
| object operation exists through page/data/action variants | same object and operation, controlled owner versus non-owner | `idor-bola` |
| image, preview, rewrite or custom server fetch accepts a caller-controlled URL | permitted destination versus a safe denied destination; account for redirects | `ssrf` |
| personalized server response reaches a shared cache key | paired identities with calibrated hit/age behavior | `cache-poisoning` |
| serialized server data crosses principals or tenants | identify the missing object, tenant, function or cache invariant before assigning its canonical class | class implied by the violated invariant |
| edge and application normalize path/method/identity differently | compare the smallest safe pair at both control layers | access-control class supported by the operation |

## 7 · Lower-priority paths

- React-escaped text lowers ordinary reflected XSS only while the value remains in that renderer;
  raw HTML, script serialization and direct DOM sinks restore priority.
- A confirmed static export lowers server-side Next mechanisms only after excluding separate APIs,
  preview/revalidation, image optimization and platform functions.
- Manifest-backed static assets lower generic filesystem traversal; custom file/download handlers
  remain separate.

## 8 · Live research entrypoints

- Data security and Server Action guidance: <https://nextjs.org/docs/app/guides/data-security>
- Next.js repository advisories: <https://github.com/vercel/next.js/security/advisories>
- Next.js release notes: <https://nextjs.org/blog>
- React security posts for RSC packages: <https://react.dev/blog>

Use [`references/live-research.md`](references/live-research.md) whenever a conclusion depends on a
release, hosting mode, changed default or advisory.

## 9 · Noise, ownership and stop conditions

Framework plumbing—`__NEXT_DATA__`, RSC traffic, action identifiers and public build data—is not a
finding. A Vercel edge may be provider-owned. A method-specific 404/405 can be route evidence but
not impact. Stop an advisory path when product/package identity, affected range, deployment mode or
reachable feature cannot be established.
