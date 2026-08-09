# Live technology research protocol

Use this when no deep profile exists, a product is unfamiliar, or a conclusion depends on current
defaults, supported versions or security advisories. This is bounded research, not an invitation to
collect every CVE ever assigned to a product.

## State the research question and bound

Choose one question:

- What deployment mode and control model does this product use?
- How can this observed build/component be versioned precisely?
- Which current advisories include this exact version and reachable feature?
- Did a default or protocol behavior change between these release lines?

Default bound: one product/component, 3–6 primary sources, and one pass through the steps below.
State omissions if the bound is reached.

## Source order

1. Official product documentation for architecture, routes, defaults and configuration.
2. Maintainer `SECURITY.md` or repository/vendor security advisories.
3. Official release notes/changelog and supported-version policy.
4. Fix commit/PR or regression test when the advisory mechanism is unclear.
5. GitHub Advisory Database/OSV/NVD for identifier correlation—not as a substitute for upstream.
6. CISA KEV only for evidence of known exploitation and prioritization.

Community posts may suggest a question. They do not establish affected ranges or target behavior
when upstream is available.

## Search by canonical identity

Resolve ecosystem and package/product identity first:

| artifact | useful identity |
|---|---|
| npm/yarn/pnpm | package name such as `next`, `@nestjs/core`, `react-server-dom-webpack` |
| Python | PyPI/distribution name, which may differ from import name |
| Ruby | gem name from `Gemfile.lock` |
| PHP | Composer `vendor/package` |
| JVM | Maven `groupId:artifactId` plus container/framework distinction |
| .NET | NuGet package/product and runtime line |
| Go/Rust | module/crate path and vendored/fork status |
| CMS/CI | core product plus each plugin/module slug and version |
| appliance/SaaS | vendor product, edition, exact build and managed/self-hosted status |

Search templates:

```text
site:<official-domain> <product> security advisory
site:<official-domain> <product> supported versions
site:<official-domain> <feature/config-key> security
site:github.com/<maintainer>/<repo>/security/advisories <package>
<package> <observed-version> fixed in official
```

Use the current date and record the retrieval date; “latest” is not durable evidence.

## Establish applicability as an AND gate

An advisory-derived hypothesis requires every relevant column:

| condition | evidence |
|---|---|
| canonical product/package matches | manifest, artifact or positive fingerprint |
| version is in affected range | exact/bounded evidence; account for backports and forks |
| vulnerable deployment mode/configuration applies | observed mode or documented target behavior |
| vulnerable feature/code path is reachable | in-scope entrypoint reaches it |
| program permits a minimal validation | scope/rules and non-destructive oracle |

If any column is unknown, write the evidence needed—not “likely vulnerable.” A WAF mitigation does
not prove the origin is patched; a version string does not prove a vendored fix is absent.

## Derive mechanisms, not a CVE wall

For each applicable candidate extract:

- affected and fixed ranges exactly as upstream states;
- prerequisite configuration/deployment mode;
- vulnerable component and data/control path;
- attacker-controlled input;
- confidentiality/integrity effect relevant to bug bounty (exclude DoS validation);
- smallest positive/negative oracle;
- canonical vulnerability class;
- official source URL and retrieval date.

Two advisories with the same fix locus/mechanism may produce one test variant. Ten unrelated CVEs do
not become one “test the framework” task.

## Research framework behavior creatively

When no advisory applies, use official architecture/configuration documentation to complete the
control map in `../_analysis.md`. Ask:

- What entrypoint exists outside normal page/controller routing?
- Which security control is opt-in, separately configured or absent on generated routes?
- Which public client value is expected, and what server policy actually limits it?
- Which internal representation crosses into HTML, JSON, a cache, queue or downstream service?
- Which extension/plugin/component owns the feature?
- Which two layers can parse the same path, host, method, identity or body differently?
- Which documented escape hatch bypasses a safe default in custom code?

These questions generalize to new frameworks without pretending they behave like a familiar one.

## Record reusable results safely

- Put target facts and sources in the target brain.
- Put advisory candidates in `hypotheses.md`, never findings.
- Put current affected/fixed facts in observations with retrieval date.
- Do not edit the global technology library during a live hunt based on one unexplained response.
- Propose a library update only after the behavior is verified against upstream and is useful beyond
  this target.

## Stop conditions

- Version remains unknown and the question was advisory applicability.
- Only availability/DoS impact remains.
- The feature is unreachable or belongs to an out-of-scope provider.
- Upstream withdrew or disputed the advisory.
- Sources disagree and the fix/affected range cannot be reconciled within the bound.
- The candidate would require destructive or state-changing proof beyond authorization.

Report the unresolved condition plainly. “No applicable issue established” is a useful result.
