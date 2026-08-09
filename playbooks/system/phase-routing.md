# Phase Routing — the recon/testing graph (NOT a numbered pipeline)

> **The dependency graph that used to live here has been deleted, not corrected.**
>
> It was hand-maintained, and after the objectives were renumbered **every single number in it
> was wrong** — liveness attributed to the HTTP objective, ports to probing, prioritization off
> by one, a reference to an objective that did not exist, and one bullet that contradicted
> itself inside a single sentence. It stayed wrong for an entire renumbering because prose
> cannot be executed.
>
> Each skill now declares the input roles it consumes, and the `## Input roles` table in
> `target-schema.md` names the skill that produces each role. The graph is the join of those
> two, so it is **computed**:
>
> ```
> tools/graph.py                 what produces what
> tools/graph.py --entry         where you can start right now
> tools/graph.py --for <skill>   what must exist before this one is useful
> tools/graph.py --check         structural problems; CI runs this
> ```
>
> Routing itself is in `AGENTS.md`; the objectives are in `skills/`; what each needs is in its
> own `## Inputs`. There is no fourth copy, which is the point.
