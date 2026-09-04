---
name: compose-task
description: Turn an off-playbook, multi-step hunting request into brain-integrated work. Use when the hunter asks for something no single skill or flow covers — a custom pipeline such as "extract JS from the 404 hosts, pull the params, then test them", "chain these three steps", "do X then feed it into Y", or any ad-hoc request that stitches several capabilities together. Decomposes into existing skills plus the minimum novel glue, runs every step through the harness, and persists the result.
---

# compose-task — the off-playbook request, done without leaving the brain

> Read `skills/shared/_recon-method.md` and `playbooks/system/orchestrator.md` first.
>
> **This is the escape hatch, and its danger is becoming a dumping ground.** A model can already
> improvise "fuzz the JS, grab the params, test them" from training. What it improvises *outside*
> this skill bypasses the harness — no run row, no evidence, no properties, nothing in the surface —
> and an improvised task that leaves no trace is the exact "chat window that forgets" failure the
> whole workspace exists to prevent. This skill exists so a novel request obeys the **same
> discipline** as a native one: decompose, run through the recorder, persist.

## When this fires — and when it must not

- **Fires** when the request maps to no single skill or flow: a custom multi-step pipeline, an
  unusual chaining of capabilities, a one-off that stitches several tools together.
- **Must NOT fire** when a real skill fits. **Route first** (`AGENTS.md`, `tools/preflight.py <t>
  --list`). If one skill or one flow covers the ask, use *that* — reinventing it here is how the
  focused-skill discipline rots. This is the last resort, not the first stop.

## Objective

Turn the hunter's freeform goal into a **plan of existing skills plus the minimum novel glue**, run
each part through the harness so its output lands in the brain with evidence and enters the attack
surface, and stop — leaving a pipeline a later session (or another model) can read and resume.

## Inputs

- `@hunter.task` — the freeform request, in the hunter's words. This is the subject, and the ONLY
  standing input; without it there is nothing to compose.

Everything else the composed steps need is resolved **per step, as that step runs**, not declared
here — because declaring it here would make the harness demand a full host inventory before a
purely-local task could start. A component step that needs a host list gets it the moment that step
runs; a required input missing there stops that step the normal way (name it, name the producer).

## The loop

1. **Decompose, out loud.** Break the goal into ordered steps. For each, answer *does an existing
   skill do this?* Map every step you can to a skill (`content-discovery`, `javascript-analysis`,
   `parameter-discovery`, `vuln-hunt`, …); what is left — the genuinely novel glue — is the only
   part you run by hand. Write the plan into `target.md`/`hypotheses.md` so it survives the session.
2. **Confirm the shape** if the plan sends traffic or fans out — name the steps, the cost and the
   stop points, the way a flow does. A composed pipeline is still **one** human decision, not a
   licence to chain unprompted.
3. **Run each step through its own contract.** A step that *is* a skill runs that skill — its
   inputs, its `vps-run.py`/`run.py` traffic, its outputs. A step that is raw tooling **still** goes
   through `vps-run.py`/`run.py` (recorded, attributed, evidenced) — never a bare command that
   leaves no trace. Open one `kb.py run` row for the pipeline and note each step against it.
4. **Thread the outputs.** Each step's output is the next step's input, written to the brain (a
   file, `record.py`, `kb.py add`) so the chain is resumable — not held only in this session's head.
5. **Fold the result into the surface.** New entrypoints → `derive-properties`. New facts → `kb.py
   add` with evidence. A confirmed issue → `findings/`. The pipeline's product is brain state, not a
   chat answer.
6. **STOP** with the delta and at most 3 next actions, each citing a fact from this run.

## Discipline — the whole reason this is a skill and not improvisation

- **Prefer a skill to a hand-rolled step, always.** If half the pipeline is `content-discovery`,
  run `content-discovery` — do not re-implement fuzzing here.
- **Every request that touches the target goes through the recorder.** No off-harness traffic: the
  privacy gate, the attribution header and the evidence record apply to a custom step exactly as to
  a native one.
- **Evidence or it did not happen**, and **say what you bounded** — the invariants do not relax
  because the task was ad-hoc.
- **The plan is a durable artifact.** Write it down. A pipeline only this session can see is the
  failure mode this skill exists to prevent.

## Outputs

- The written plan — steps, the skill each maps to, the glue — in `target.md`/`hypotheses.md`.
- Whatever the composed steps produce, in their own `## Outputs` homes (surface rows, facts,
  findings), each with evidence.
- The pipeline recorded as a run with its selector and `--limitations`.

## Exit criteria

Every step either ran a real skill or a recorded harness command — nothing off-harness. Each step's
output is in the brain, not only in the session. New entrypoints were propertied; new facts carry
evidence. The plan is written where a resumed session can pick it up. The run is recorded.

## Next

Offer the natural continuation of whatever the pipeline surfaced — usually `derive-properties`,
`attack-surface-prioritization`, or `vuln-hunt` on a specific entrypoint the pipeline exposed.
