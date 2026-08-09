# <TARGET> — User flows

> The journeys a **user of the target application** takes. Written during `auth-app` /
> `application-mapping`, and it is what makes business-logic testing possible — a feature list
> is not. *(Named `user-flows` to keep it distinct from `playbooks/flows/`, which are research
> flows.)*
>
> A flow is worth a row when it **changes state** or **touches an object someone else owns**.
> Read-only navigation is not a flow.

| name | steps | principals | objects | state changes |
|---|---|---|---|---|
<!-- example row (not data): <e.g. transfer funds> | <1 select account · 2 enter amount · 3 confirm> | <who can start it> | <what it names> | <what is different afterwards> -->

## Where the logic bugs live
- **Steps that can be skipped or reordered** — does step 3 verify step 2 happened?
- **Objects named by one principal, acted on by another** — the authorization question.
- **State changes that are not idempotent** — replay, race, double-spend.
- **Guards that decline to run** rather than failing closed.

Each row that survives scrutiny becomes a `hypotheses.md` entry with a class from
`playbooks/system/class-signals.md` — usually `workflow-abuse`, `state-machine-abuse`,
`idor-bola` or `privilege-escalation`.
