# Chain — <lead>

> Use this when impact crosses more than one entrypoint or vulnerability class. Individual probes
> still live in `tested.md`; this file preserves how the primitives compose.

## Goal and boundary

- **Intended impact:** <concrete attacker outcome>
- **Scope basis:** <scope.md clause / exact supplied statement>
- **Human-approved ceiling:** <what may be demonstrated; what must remain hypothetical>

## Chain graph

| step | entrypoint | class / primitive | principal | precondition | oracle | status | artifact_ptr |
|---|---|---|---|---|---|---|---|
| 1 | | | | | | hypothesis | |

## Approval gates

| before action | why approval is needed | status |
|---|---|---|
<!-- example row (not data): <cross-tenant read / privilege escalation / state change / broad replay> | <risk and scope reason> | pending -->

## Impact argument

- **FACT:** <what the stored artifacts prove>
- **HYPOTHESIS:** <what the next safe link would establish>

## Dead ends and alternatives

- <failed link, discriminator, and what materially new evidence would reopen it>
