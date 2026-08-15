# Shape of a deep technology profile

> Answer: **what does this product or deployment mode change that is not true of web applications
> generally?** Generic testing belongs in vulnerability class playbooks. A profile is a mechanism
> map and question generator, never a promise that the target has a known bug.

Copy this shape only when a product has enough distinctive behavior to justify a deep profile.
Otherwise add it to the appropriate family reference.

## Required sections

### 1 · Identity and deployment modes

Separate client-only, SSR/server, managed/self-hosted, core/plugin and gateway/origin variants.
These often have different trust boundaries despite sharing a product name.

### 2 · Fingerprint and disambiguation

Rank signals as `confirms`, `corroborates` or `suggests`. Include a negative case and record which
layer emitted the signal. A header from a proxy is not proof of the origin framework.

### 3 · Version and component identity

Name evidence yielding `exact`, `bounded` or `unknown`. Distinguish a build/deploy identifier from a
package version, and upstream from vendored/forked code.

### 4 · Native surface

List product-specific paths, protocols, files, headers and behaviors. Explain the mechanism and
deployment prerequisite; do not create a wordlist of unqualified paths.

### 5 · Security controls and trust boundaries

State where the stack normally performs routing, authentication, authorization, binding,
serialization, caching, file handling and administration. Mark controls as defaults only when
upstream documentation says so, and never infer the target kept the default.

### 6 · Target-specific hypothesis transforms

Map an **observed feature** to canonical vulnerability classes and explain the code path:

```text
observed feature → attacker-controlled value → trust boundary/sink → expected oracle → class
```

Include composition seams where another layer can normalize, cache or authorize differently.

### 7 · Lower-priority paths

Explain what becomes less likely **only after a control is observed**. Framework reputation or a
secure default does not rule out custom code. State the exception that would restore priority.

### 8 · Live research entrypoints

Point to official security policy/advisories, supported-version policy and release notes. Do not
freeze a CVE list into the profile.

### 9 · Noise, ownership and stop conditions

Name defaults that are not findings, third-party/CDN behavior the target does not own, soft-404s,
and the evidence that should stop a dead line of testing.

### 10 · Checks — the `component-hunt` catalog

The stack's **behavioral** misconfigurations and exposures, as rows `component-hunt` executes
verbatim. One request each, read-only (GET/HEAD/OPTIONS). Fixed columns, no exceptions:

`check · precondition · probe · a hit is (the discriminator, never "status 200") · safety
(read, or **presence-only** for anything bulky or secret-bearing) · on hit → class (canonical
class name from `playbooks/vulns/_index.md`) · fix_locus`.

What does **not** belong in a row: version-gated CVEs (the n-day sweep owns those — a catalog
row would rot and duplicate its cohort list), anything that mutates, downloads a secret, or
invokes a management operation. A framework with no meaningful catalog says so in one row and
routes to the skill that owns the surface (`react.md` is the pattern) — an explicit "not here"
beats a silent gap or an invented spray.

## Quality rules

- Use canonical class names from `playbooks/vulns/_index.md`.
- Treat configuration-dependent and version-dependent statements as conditional.
- Treat public client identifiers and framework metadata according to their documented purpose.
- Do not include payload dumps, destructive checks, credential attacks or generic parameter lists.
- Do not turn advisory applicability into a finding; require version, reachability and a minimal
  target-specific probe.
- Prefer upstream documentation, repository security advisories and release notes over blogs.
- Keep the main profile concise. Put broad ecosystem variation in `references/`.
- Mark uncertainty. `reported` is not `observed`, and a detector label is not a fact.
