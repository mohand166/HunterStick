# <TARGET> — JS Findings

> `javascript-analysis`. Secrets, routes, endpoints, internal hosts pulled from JS bundles.
> `finding_type` = api-endpoint | secret | token | internal-host | cloud-key | comment | route.
> **Redact the secret value** — keep only enough to prove it, and point to the artifact.
> Column order is fixed by `playbooks/system/target-schema.md` — later skills parse it.

| js_url | finding_type | value | severity_hint | verified | source |
|---|---|---|---|---|---|
