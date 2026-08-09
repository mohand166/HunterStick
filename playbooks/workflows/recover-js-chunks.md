# Recover lazy JavaScript chunks

> Process helper for javascript-analysis. Given JavaScript artifacts already collected from one authorized
> app, recover lazy chunks to a fixed point without evaluating target code. This is recon, not a
> vulnerability test.

## Trigger

Use when the app is code-split and the current bundle set may omit lazy routes or features:

- a Webpack/Vite/Parcel runtime or framework manifest is present;
- imports, route manifests or runtime maps name unloaded code;
- the HTML is a thin SPA shell and javascript-analysis has only entry bundles;
- the hunter explicitly asks to recover lazy chunks.

Do not run it merely because a host serves one ordinary script. The gain is the unvisited chunk
graph, not another copy of files javascript-analysis already has.

## Inputs and boundary

- named target and `scope.md`;
- a single app/host selector and a declared request/depth budget;
- saved HTML/JavaScript artifacts plus their original URLs;
- `raw/js/js-sources.tsv`, the durable URL→artifact ledger.

The parser is local. Fetching a candidate is active recon and goes through `tools/run.py`. A chunk
on an unlisted CDN or sibling is recorded `blocked-by-scope`; a page reference does not authorize
that host.

## Source ledger

Create the ledger before parsing. Preserve this exact TSV header:

```text
url	artifact	depth	fetch_status
```

One row represents one URL. `artifact` is relative to the ledger (or absolute). States are:

| state | artifact | meaning |
|---|---|---|
| `fetched` | real path | body exists and can be parsed |
| `failed` | `-` | an authorized fetch was attempted and failed; keep the failure visible |
| `blocked` | `-` | scope/ownership prevented a request |
| `skipped` | `-` | the hunter intentionally excluded it; record the reason in the run |

Seed depth is `0`; a child of depth N is N+1. Never reconstruct a source URL from a hashed local
filename—the original URL is required to resolve relative imports correctly.

## Fixed-point loop

1. **Seed.** Add document scripts, captured manifests/runtime files and already downloaded bundles
   to `js-sources.tsv`. Include their real source URLs and artifact paths.
2. **Parse locally.** Run:

   ```text
   tools/chunks.py targets/<t> raw/js/js-sources.tsv --out-dir raw/js
   ```

   The tool recognizes explicit JS/source-map references, Next/Vite manifest literals, constrained
   Webpack filename expressions and lower-confidence Webpack hash maps. It parses strings and
   syntax only—no `eval`, Node import, browser injection or script execution.
3. **Review the frontier.** Read `chunk-frontier.tsv`, not only the candidate list. Resolve any
   surprising host against scope and ownership. Medium-confidence heuristic rows require a human
   or model check of the parent runtime before promotion.
4. **Fetch a bounded batch.** `chunk-candidates.txt` contains only high-confidence, in-scope,
   pending URLs. Open the javascript-analysis run first, inspect installed downloader help, and construct the
   `tools/run.py` command for the declared selector/rate. Preserve URL→saved-path mapping.
5. **Update, do not erase.** Add fetched and failed candidates to `js-sources.tsv` with their depth
   and current status. A failed URL remains a row; otherwise the next pass rediscovers it forever.
6. **Repeat.** Rerun `chunks.py` until the authorized high-confidence frontier is empty or an abort
   condition fires. Each content hash is parsed once per pass while relative references are still
   resolved independently for every parent URL.
7. **Mine the complete set.** Run Jsluice/secrets/source-map/component extraction over every fetched
   artifact, then normalize into the normal javascript-analysis outputs.

## Outputs

| artifact | role |
|---|---|
| `raw/js/js-sources.tsv` | durable fetch/resume state and URL→artifact provenance |
| `raw/js/chunk-graph.tsv` | directed parent→child evidence, bundler, method, scope and content hash |
| `raw/js/chunk-frontier.tsv` | unique discovered assets, including blocked/failed/heuristic rows |
| `raw/js/chunk-candidates.txt` | authorized high-confidence pending fetch list |
| `recon/js-findings.md` | normalized routes, endpoints, internal hosts, public config and secret candidates |
| `recon/components.md` | component/version evidence when component-inventory is invoked |

Report seed sources, unique hashes, discovered children, fetched, failed, blocked, skipped and the
remaining frontier separately. “Chunks recovered” without those bounds is not a completion claim.

## Safety and false positives

- **Never execute target JavaScript to discover chunks.** A bundle is untrusted data and may run in
  an authenticated browser origin if appended as a script.
- Do not evaluate a manifest object. Extract literal paths and constrained runtime expressions.
- A referenced chunk may be dead code, a feature flag, another role's UI or an old deploy. It is a
  surface lead until legitimate traffic or application behavior proves reachability.
- A source map can contain sources from build dependencies that are not deployed entrypoints.
- Content-identical files on two base URLs still resolve relative children independently.
- Do not brute-force numeric chunk IDs. A medium-confidence runtime reconstruction is reviewed,
  not silently promoted into network traffic.

## Abort and exit

Abort when the declared request/depth budget is reached, scope becomes ambiguous, responses are a
soft-404/template rather than JavaScript, the frontier cycles without new content hashes, or only
blocked/medium-confidence rows remain.

On exit, feed endpoints to api-discovery, components to component-inventory and framework/deployment evidence to
technology analysis. Update the javascript-analysis run with the exact frontier state, reassess, summarize and
stop.
