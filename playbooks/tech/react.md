# React (client-side mode)

> This profile is for a client-only React application. If SSR, React Server Components/Functions
> or a meta-framework is present, also load the frontend/meta lens and that server product's
> profile. React is then only one layer of the stack.

## 1 · Identity and deployment modes

Confirm client-only SPA, embedded widget/microfrontend, or browser layer of a server-rendered app.
Record router, build system, API origins, identity SDK and whether other frameworks own the server.
The absence of server behavior on the SPA host does not prove the application has no backend.

## 2 · Fingerprint and disambiguation

- **Confirms:** runtime/DevTools detection of a React root or source-map/package evidence for
  `react` and `react-dom`.
- **Corroborates:** React-specific bundle symbols or legacy root markers.
- **Suggests only:** an empty HTML shell with hashed chunks; Vue, Svelte and other SPAs look alike.
- **Negative case:** a React-looking UI does not establish which technology serves its APIs.

## 3 · Version and component identity

Exact versions may appear in a lockfile, source map or unminified vendor chunk; otherwise record
`unknown`. Inventory router, authentication SDK, state/rendering libraries, editors and parsers
separately. If RSC packages are evidenced, determine their exact versions and server reachability
rather than extrapolating from the browser `react` package.

## 4 · Native surface

| observed artifact/mechanism | what it changes |
|---|---|
| route and lazy-chunk manifests | hidden UI routes, operations and role-specific features become discoverable |
| source maps / `sourcesContent` | original source, API clients and trust assumptions may be recoverable |
| public build variables | API/IdP/project identifiers are expected; privilege, not the name, determines sensitivity |
| unsafe HTML or direct DOM APIs | React's normal text escaping may be bypassed on that path |
| `postMessage`, iframe or popup code | origin, source and message-capability boundaries exist |
| API/WebSocket clients | the real authorization boundary is behind the browser route |

Do not rely on fixed CRA/Vite paths. Start from assets referenced by this deployment, then follow
manifests and imports.

## 5 · Security controls and trust boundaries

Treat router guards, disabled buttons, feature flags and hidden menu items as presentation. Locate
server enforcement for each operation. Trace attacker-controlled values from URL, storage,
messages, API responses and third-party content into React escape hatches, browser DOM APIs and
dependency sinks. Identify which window/frame is trusted and what each message can cause.

## 6 · Target-specific hypothesis transforms

| observed feature | boundary and oracle | canonical class |
|---|---|---|
| hidden route/operation with a backing API | same API operation under authorized and lower principal | `function-level-authorization` |
| object IDs moved directly between UI and API | controlled owner object versus another principal's object | `idor-bola` |
| controllable data reaches raw HTML/direct DOM sink | safe context-aware marker proving execution without destructive impact | `xss` |
| message listener trusts weak origin/source or powerful data | controlled allowed source versus disallowed source, with one benign capability | `postmessage` |
| attacker input reaches a merge plus a demonstrated gadget | polluted and non-polluted control with a harmless property/oracle | `prototype-pollution` |
| client-side role/tenant value influences a server operation | compare server outcome after changing only the untrusted selector | `privilege-escalation`, `multi-tenant-isolation` or the applicable access-control class |

## 7 · Lower-priority paths

- Server template injection is lower priority only after confirming this host is static/client-only
  and no server renderer handles the input.
- React-rendered text lowers XSS only for the observed render path; raw HTML, refs, third-party DOM
  libraries, markdown/editors and direct browser APIs restore it.
- A static CDN lowers filesystem assumptions on that host, not file handling in backing APIs.

## 8 · Live research entrypoints

- React security/release posts: <https://react.dev/blog>
- React repository advisories: <https://github.com/facebook/react/security/advisories>
- React DOM escaping and raw HTML API: <https://react.dev/reference/react-dom/components/common>

Use [`references/live-research.md`](references/live-research.md) for server-component packages,
dependency advisories and release-sensitive behavior.

## 9 · Noise, ownership and stop conditions

`REACT_APP_*`, `VITE_*`, project IDs and OAuth client IDs are public by design unless the value
grants unintended privilege. SPA fallback can return the same shell with 200 for nonexistent paths;
calibrate the body before counting routes. Stop attributing an API weakness to React once another
server/control layer is identified—retain React only as the evidence source that revealed it.
