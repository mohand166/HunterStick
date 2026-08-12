# Workflows — lenses and process helpers

> Everything here is a **procedure that is neither a recon phase nor a vuln class**. Phases produce
> inventory; classes test a hypothesis; these are the two things in between — *how to read a kind of
> thing*, and *how to do a step properly*.

---

## Workflows vs flows — the line that matters

They sound like the same word. They are not, and opening the wrong one wastes an afternoon.

| | `playbooks/flows/` | `playbooks/workflows/` |
|---|---|---|
| **triggered by** | a **situation you observe** — "this host 404s everything", "3,918 hosts" | an **artifact you hold** or a **step you are inside** |
| **made of** | several recon phases, bundled | one procedure |
| **sends** | recon traffic only — **never a payload** | may send test traffic; `n-day-sweep` sends checks |
| **ends by** | handing entrypoints to `vuln-hunt` | producing understanding, leads, or a verdict |
| **declares** | steps, cost and abort points **before running** | its own preconditions |

**The discriminator: a flow never tests.** If the procedure ends with a probe and a verdict, it is a
workflow. If it ends by handing you a ranked list of things to probe, it is a flow.

The pair that catches people: [`flows/api-surface.md`](../flows/api-surface.md) *recovers the
contract*; [`investigate-api-surface.md`](investigate-api-surface.md) is the lens for *testing* the
API that flow found. Recon side, then test side.

---

## Lenses — how to reason about a kind of thing

| file | when |
|---|---|
| [`../../skills/analysis/analyse-request.md`](../../skills/analysis/analyse-request.md) | the human pastes a **raw HTTP request**. The entry point: scope, credential, properties, a row in `attack-surface.md` |
| [`import-traffic.md`](import-traffic.md) | a **HAR or Burp export** — an hour of browsing turned into structured endpoints |
| [`recover-js-chunks.md`](recover-js-chunks.md) | saved entry bundles from a code-split app — recover the authorized lazy-chunk graph without executing it |
| [`investigate-api-surface.md`](investigate-api-surface.md) | testing an **HTTP/JSON API as an API** — verbs, versions, parsers |
| [`investigate-graphql.md`](investigate-graphql.md) | the transport is **GraphQL** — recover the schema, then work the class |
| [`investigate-grpc.md`](investigate-grpc.md) | the transport is **gRPC** — recover the contract, then work the class |

**Transport is addressing, not the bug.** GraphQL and gRPC are lenses precisely because the class
underneath is the same one you would test over REST. See `_master-vuln-hunting.md` §"the transport
is not the class".

## Process helpers — how to do one step properly

| file | when |
|---|---|
| [`research-component.md`](research-component.md) | a component + version from component-inventory — what is publicly known, bounded to 4–6 sources. Produces hypotheses with a probe attached |
| [`read-response-signals.md`](read-response-signals.md) | you hold a request/response **pair** and want every signal the response carries |
| [`compare-two-accounts.md`](compare-two-accounts.md) | two principals exist — the diff that finds authz bugs a scanner cannot |
| [`design-validation-test.md`](design-validation-test.md) | before probing: declare the oracle, so the result means something |
| [`generate-hypotheses.md`](generate-hypotheses.md) | turn observations into a ranked, testable backlog |
| [`investigate-asset.md`](investigate-asset.md) | one host deserves a deep dive |
| [`investigate-endpoint.md`](investigate-endpoint.md) | one endpoint deserves a deep dive |
| [`reassess-after-failure.md`](reassess-after-failure.md) | a test came back negative or inconclusive — **the enemy is sunk cost** |

## Governed procedures — they send traffic, so they are gated

| file | when |
|---|---|
| [`n-day-sweep.md`](n-day-sweep.md) | a public n-day dropped and you want to know which of a fingerprinted cohort is affected. **Pilot-gated:** select → one host → a human reads it → scale. Destructive checks refused |

`n-day-sweep` looks like a flow — situation-triggered, declares cost, aborts — and it is filed here
for one reason: **it sends a vulnerability check.** That is the line flows do not cross.

---

## Adding one

Ask which of the three it is. If it bundles phases in response to a situation and never tests, it is
a **flow** and belongs next door. If it teaches how to *do* something rather than what to run, keep
it short and point at the phase or class that owns the method — two copies of a method is how they
drift.
