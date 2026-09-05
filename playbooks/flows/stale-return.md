# Flow — returning to a stale target

> You were here weeks ago. The brain says 3,918 live hosts and six ranked clusters. **Some of that is
> no longer true, and nothing in the file will tell you which part.** Re-running everything wastes
> days; trusting it wastes the engagement. This flow separates what is still true from what expired.

## Situation
`index.md` last-updated is more than ~2 weeks old, or you simply do not remember the state.

## Preconditions
An existing target brain. No traffic needed for steps 1–2.

## Steps

0. **`tools/brief.py <target> --resume` first.** It reconstructs the session from the files —
   unfinished runs (including ones left `running` where traffic may already have been sent),
   standing decisions that still bind you, whether `scope.md` changed since the last run, and
   the exact read set. ~300 tokens. **Never reconstruct from chat history**: it holds abandoned
   reasoning, target-controlled text and credentials, and none of it is verified.

1. **Read the brain before touching the target** — free, and it is the whole reason it exists:
   `index.md` (state, blockers), `target.md` (architecture — what you concluded), `scope.md`
   (**re-read: programs change scope**), `attack-surface.md` (the ranking), `tested.md` (what is
   already ruled out), `hypotheses.md` (open leads), and **every other `.md` at the target root** —
   ad-hoc analysis files are usually the densest thing there and nothing indexes them.
   the live console (`tools/dashboard-server.py`) renders this in one screen.
2. **Age each input.** Which numbers came from which date? Anything older than the scope statement
   itself is suspect. State the ages out loud — *"this ranking is 23 days old"* — rather than
   silently reusing them.
3. **Re-check scope first.** A program that removed a domain makes your top-ranked cluster illegal,
   not merely stale. This is the one step that can invalidate everything downstream.
4. **Diff, don't re-run.** → `skills/monitoring/monitoring-and-diff.md`: snapshot the cheap
   signals (subdomains, live hosts), diff against the last snapshot, and take **only the delta**.
   New surface becomes new `attack-surface.md` rows and new `hypotheses.md` entries.
5. **Re-rank the affected slice only.** → `attack-surface-prioritization` over the delta plus
   anything whose evidence expired. Not the whole estate.
6. **Resume, don't restart.** The open hypotheses from last time are still the best leads unless the
   delta beat them. Say which one you are picking up and why.

## Aborts
- Scope changed → **stop everything else** and reconcile `scope.md` first. Anything now out of scope
  gets marked, not quietly dropped.
- No previous snapshot exists → step 4 cannot diff. Say so, take a baseline snapshot now, and treat
  this session as establishing the baseline rather than finding the delta. Do **not** present a full
  re-scan as a delta.
- Credentials expired → an "authz fixed" conclusion is really a dead session. Re-authenticate before
  concluding anything about access control.

## Cost
Steps 1–3 are free. Step 4 is one cheap enumeration pass. Far cheaper than a re-run, and the only
honest way back in.

## Output
- Ages stated for every input you intend to rely on.
- A delta report: new / gone / changed.
- Updated `attack-surface.md` rows for the delta; refreshed `index.md` timestamp.

## Exit
Report three sets: **still true**, **expired**, **new**. Then name the single lead you would resume,
and stop.
