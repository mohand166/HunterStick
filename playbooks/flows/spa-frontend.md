# Flow — SPA / JS-bundle frontend

> The page is a shell and a bundle. **Fuzzing this host is close to pointless** — the routes are not
> on the server in the shape you would guess, and the API the app talks to is written down inside
> the JavaScript you were just served. Read it instead.

## Situation
- HTML body is nearly empty (a `<div id="root">`, a few `<script src>`), and
- the app renders after JS runs, and
- navigation changes the URL without a full page load.

## Preconditions
- Host in `scope.md`.
- A browser (Chrome/Playwright MCP) for step 4, or a HAR/Burp export instead.

## Steps

1. **Collect every bundle**, including lazy chunks. Chunk names in the entry bundle reveal routes
   the shell never loads.
   → `skills/javascript-analysis.md`
2. **Pull the contract out of the bundle** — API base URLs, route tables, endpoint templates,
   parameter names, feature flags, role strings, and any embedded key. Parameter names from here are
   *real*; they beat any wordlist and they are why `parameter-discovery` is often unnecessary.
3. **Map the API.** The bundle told you the base and the shape.
   → `skills/api-discovery.md`, and if it is GraphQL or gRPC,
   `playbooks/workflows/investigate-graphql.md` / `investigate-grpc.md` to recover the schema.
4. **Drive the app and watch the network.** Click through every feature; the requests the app makes
   are the ground truth the bundle only hinted at.
   → `skills/application-mapping.md` (needs accounts for anything behind login).
5. **Record properties, then rank.** Each discovered endpoint gets its observed properties in
   `attack-surface.md` (rank empty; `attack-surface-prioritization` only on request) on the new slice.

## Aborts
- **A secret in the bundle** (API key, cloud credential, internal token) → stop and handle it as a
  finding path: verify it is live with the *smallest* possible check, store the artifact,
  placeholder it everywhere per `AGENTS.md` §Credentials. Do not keep mapping.
- Login required at step 4 and no usable principals → do steps 1–3, park the rest as
  `blocked (needs-account)`, and say which flow resumes it (`auth-app`).
- Bundle is minified past usefulness and no sourcemap → say so; steps 3–4 still work, step 2 degrades.

## Cost
Steps 1–2 are ~one request per bundle plus local analysis — very cheap, very high yield. Step 4 is
browser-driven and slow but quiet.

## Output
- `recon/js-findings.md` — routes, endpoints, params, secrets (redacted + pointered).
- `applications/<host>/map.md` + `endpoints.md`.
- `attack-surface.md` rows with properties derived from the contract, not guessed.

## Exit
Report the recovered contract in numbers — routes, endpoints, parameters, and how many were
*unreachable from the UI*. Those last ones are the interesting set.
