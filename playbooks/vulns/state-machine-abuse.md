# State-Machine Abuse → merged

**This playbook has been merged into [`workflow-abuse.md`](workflow-abuse.md)** ("Business-Logic
Abuse"), with its reference layer at [`ref/workflow-abuse.md`](ref/workflow-abuse.md).

Read those. Multi-step flows and object lifecycles turned out to be the same question at different
granularity — *what rule does the app intend to hold, and where does that rule actually live?* — so
keeping two files meant one fact with two homes.

**Where the state-machine material went:**

| you wanted | now at |
|---|---|
| Reconstruct the legal state graph; illegal `from→to` edges | `ref/workflow-abuse.md` **B2** |
| Who may drive a transition (usually the better question) | `workflow-abuse.md` §1 · **B2** |
| Is a legal transition idempotent, and what else does it write | **B2** |
| Terminal states, revocation, incomplete teardown | **B6** |
| Reservation windows and double-spend | **B5** |
| Guards that decline to run | **B3** |

One thing worth carrying over explicitly: the old high-value edge list (`cancelled→shipped`,
`refunded→delivered`, `draft→published`, `expired→active`, `rejected→approved`, `unpaid→paid`)
**did not appear once** in the disclosed-report corpus. That may reflect the corpus's skew rather
than the technique's value — but treat it as a memory aid, not a discovery procedure. **B2** carries
the questions that did pay: *who may drive this transition*, *is it idempotent*, *what else does it
write*.
