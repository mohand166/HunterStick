# Skill outputs and storage

This is the hunter-facing answer to one question: **after I invoke this capability, what is
written, and where can I inspect it?** It covers every recon skill, every canonical vulnerability
class, every situation flow, and every workflow.

The capability file remains the authority for its method and exit criteria. This document is an
output map, not a second copy of the instructions.

## Contents

- [How to read the paths](#how-to-read-the-paths)
  - [VPS artifact filenames](#vps-artifact-filenames)
- [Records written around every run](#records-written-around-every-run)
- [Recon skills](#recon-skills)
- [Vulnerability skills](#vulnerability-skills)
  - [Files every vulnerability skill updates](#files-every-vulnerability-skill-updates)
- [Situation flows](#situation-flows)
- [Workflows](#workflows)
- [Router and maintenance skills](#router-and-maintenance-skills)
- [How to inspect a completed run](#how-to-inspect-a-completed-run)

## How to read the paths

Two stores exist for different reasons:

| store | base path | what belongs there |
|---|---|---|
| **Local target brain** | `targets/<t>/` | Small, curated facts and evidence needed to decide what to do next. This is the source of truth that survives a dead VPS, a new session, or a model switch. |
| **VPS heavy store** | `~/targets/<t>/` | Bulk scanner output, downloaded bundles, execution records, job logs, and testing loot needed to re-derive the local conclusion. |

Paths in the tables are relative to one of those bases. A dash in the VPS column means the
capability is normally local reasoning and sends no target traffic. If it reads an existing VPS
artifact, that input is named, but reading it does not create a new raw dataset.

The stable VPS buckets are:

```text
~/targets/<t>/
  raw/subdomains/  raw/dns/   raw/ports/  raw/http/
  raw/urls/        raw/content/           raw/js/
  raw/api/         raw/snapshots/         raw/sweeps/
  jobs/            logs/                  logs/exec/
  loot/
```

Some skills create a more specific child under `raw/`. The exact artifact path must be recorded in
`index.md` and the run record; never guess it from this table. Large local lists may be demoted to
the VPS by `vps-sync.py`, leaving their count and pointer in `index.md`.

### VPS artifact filenames

Directories are not enough to resume a run. Raw scanner artifacts use
`<YYYY-MM-DD>-<run-id>-<tool>-<purpose>.<ext>` where the tool controls the filename. The monitor,
sweep, chunk reducer, and command recorder have fixed names:

| VPS location | Filenames or stable pattern |
|---|---|
| `raw/subdomains/` | `<date>-<run-id>-subfinder.txt`, `<date>-<run-id>-amass.txt`, and one equivalent file per source. |
| `raw/dns/` | `<date>-<run-id>-dnsx.jsonl`, `<date>-<run-id>-resolved.txt`, and takeover/vendor response artifacts named for their host. |
| `raw/ports/` | `<date>-<run-id>-naabu.jsonl`, `<date>-<run-id>-nmap.xml`. |
| `raw/http/` | `<date>-<run-id>-httpx.jsonl`; screenshots or bodies add the host/purpose before the extension. |
| `raw/urls/` | `<date>-<run-id>-gau.txt`, `<date>-<run-id>-katana.jsonl`, plus a named reduced artifact when one is retained remotely. |
| `raw/content/` | `<date>-<run-id>-<host>-ffuf.json` or the equivalent calibrated tool output. |
| `raw/js/` | `<host>-urls.jsonl`, `<host>-secrets.jsonl`, downloaded bundle names, `js-sources.tsv`, `chunk-graph.tsv`, `chunk-frontier.tsv`, `chunk-candidates.txt`. |
| `raw/api/` | `<host>-openapi.json`, `<host>-graphql-schema.json`, `<host>-descriptor.pb`, or another protocol-specific contract filename. |
| `raw/snapshots/` | `<stamp>-subdomains.txt`, `<stamp>-http.txt`, `<stamp>-js.txt`, `<stamp>-js-external.txt`; quarantined snapshots add `.partial`. Pending review is `monitor-pending.md` at the target root. |
| `raw/sweeps/` | `<date>-<check>-pilot.txt` for the pilot and `<date>-<check>.txt` for an explicitly scaled sweep. |
| `logs/exec/` | `<YYYYMMDDTHHMMSS>-<skill>-<tool>.json`, with same-basename `.out` and `.err`. |
| `loot/` | Testing artifacts are grouped by run: `<run-id>/<case-slug>/`. The durable redacted copy uses the local evidence filenames below. |

These are filename conventions, not hard-coded scanner commands. The installed tool's output
format still wins, and the exact filename actually used is always stored in the command record and
`index.md`.

## Records written around every run

These are common side effects and are not repeated in every row below:

| record | where | when it changes |
|---|---|---|
| Run lifecycle | local `runs.tsv` | Opened with `status=running` before traffic or a brain mutation; closed with result, sources, limitations, and resume pointer. |
| Manifest | local `index.md` | Updated after a material delta with counts, timestamps, state, and exact VPS pointers. |
| Fact ledger | local `observations.tsv` | Append-only facts learned by the skill through `kb.py add`; `observed` facts require an evidence pointer. |
| Tool ledger | local `logs/tools.tsv` | First-party tool invocation, exit code, and short failure/success summary. |
| Command evidence | VPS `logs/exec/<stamp>-<skill>-<tool>.{json,out,err}` | Written by `run.py` for each external command. JSON holds reproducibility metadata; stdout/stderr remain separate. It may be pulled locally for audit. |
| Raw pointer | local `index.md` | Names the exact remote artifact and count/hash when the useful raw result stays on the VPS. |

`missing`, `0`, `partial`, and `failed` are different states. A skill that could not produce its
declared artifact must record a failed or partial run; it must not update the brain with a
confident zero.

## Recon skills

Every row loads [`skills/shared/_recon-method.md`](skills/shared/_recon-method.md) plus the linked focused skill.
The VPS column names the normal bulk bucket; the exact dated filename is recorded per run.

| Recon skill | Decision-ready output | Local brain files updated | VPS bulk/input location |
|---|---|---|---|
| [`organization-and-roots`](skills/know-your-target/organization-and-roots.md) | Owned, divested, third-party, and unresolved apexes with dated ownership and authorization evidence. | `recon/root-domains.md`; organization map and leads in `target.md`; facts in `observations.tsv`. | `raw/organization-and-roots/` when source responses are retained; otherwise source URLs are evidence pointers. |
| [`subdomain-enumeration`](skills/know-your-target/subdomain-enumeration.md) | Deduplicated hostname set, source coverage, wildcard findings, naming grammar, and new-versus-total delta. | `recon/subdomains.txt`; patterns/leads in `target.md`; source and wildcard facts in `observations.tsv`. | `raw/subdomains/`, one dated artifact per source. |
| [`dns-analysis`](skills/know-your-target/dns-analysis.md) | Record inventory, rcode classification, wildcard picture, CNAME/vendor map, dangling/private-IP leads, and deduplicated IP scan list. | `recon/dns.md`; `recon/ips.txt`; leads in `target.md`; DNS facts in `observations.tsv`. | `raw/dns/`. |
| [`asn-and-ip-discovery`](skills/know-your-target/asn-and-ip-discovery.md) | Attributed netblocks, ownership evidence, provider exclusions, certificate observations, and a recorded “not worth running” verdict when applicable. | `recon/ips-asn.md`; origin/internal-name leads in `target.md`; ownership facts in `observations.tsv`. | `raw/asn/` for RDAP/ASN evidence. It consumes the deduplicated IP list rather than creating another scan list. |
| [`subdomain-takeover`](skills/external-assets/subdomain-takeover.md) | Per-candidate vendor, DNS state, ownership-validation result, name selectability, verdict, evidence, and rejection reason. | Verdicts appended to `recon/dns.md`; confirmed leads in `target.md`; actionable reach in `hypotheses.md`; vendor behavior in `observations.tsv`. | `raw/dns/` for DNS/vendor responses; minimal validation evidence may also be placed in `loot/`. |
| [`live-host-validation`](skills/know-your-target/live-host-validation.md) | Wildcard-verified resolved names, name×address pairs, multi-address flags, and retained non-resolving `Host:` candidates. | `recon/resolved.txt`; leads in `target.md`; resolution, wildcard, certificate, and vantage facts in `observations.tsv`. | `raw/dns/`. |
| [`port-and-service-discovery`](skills/know-your-target/port-and-service-discovery.md) | Re-verified address/port/service/name rows plus coverage tier and exclusions. | `recon/ports.md`; management-plane and certificate leads in `target.md`; coverage/service facts in `observations.tsv`. | `raw/ports/`. |
| [`http-probing`](skills/know-your-target/http-probing.md) | Clean live URL set, fronting/gating/catch-all picture, and raw structured probe evidence. | `recon/live-hosts.txt`; notable hosts in `target.md`; HTTP facts in `observations.tsv`; unranked host entrypoints may be handed to `derive-properties`. | `raw/http/`. |
| [`technology-fingerprinting`](skills/surface-discovery/technology-fingerprinting.md) | Per-host edge/origin stack, framework/version precision, parser layers, confidence, evidence, and unidentified layers. | `recon/technologies.md`; stack leads in `target.md`; technology/fronting facts in `observations.tsv`. It does **not** assign attack-surface properties. | `raw/http/` plus `raw/technology-fingerprinting/` when dedicated fingerprint output is retained. |
| [`url-collection`](skills/surface-discovery/url-collection.md) | Reduced per-host path shapes, parameter names, zombie routes, version/prefix map, and corpus reduction counts. | `recon/urls.txt`; `recon/parameters.txt`; confirmed notable operations in `recon/endpoints.md`; tokenized/zombie/high-value leads in `target.md`. | `raw/urls/`; the unreduced corpus stays here and is pointed to from `index.md`. |
| [`content-discovery`](skills/surface-discovery/content-discovery.md) | Per-host calibrated baseline, confirmed paths, response transitions, request budget, and refined target vocabulary. | `recon/content/<host>.md`; `recon/wordlists/`; route/config/admin leads in `target.md`; calibration and hit facts in `observations.tsv`. | `raw/content/<host>.*`; target-derived wordlists may also be mirrored under VPS `wordlists/`. |
| [`javascript-analysis`](skills/surface-discovery/javascript-analysis.md) | Routes, call sites, body shapes, postMessage/gadget leads, redacted secret metadata, endpoint operations, and global parameter names. | `recon/js-findings.md`; `recon/endpoints.md`; `recon/parameters.txt`; JS-derived leads in `target.md`; facts in `observations.tsv`; small provenance ledgers may live under local `raw/js/`. | `raw/js/` for bundles, maps, jsluice JSONL, and recovered chunks. Secret values/context remain remote and never enter the brain. |
| [`api-discovery`](skills/surface-discovery/api-discovery.md) | Protocol identity, recovered operation set, schema/spec, version/host drift, error envelopes, and spec↔reality deltas. | `recon/endpoints.md`; parameters discovered from the contract in `recon/parameters.txt`; leads in `target.md` and `hypotheses.md`; API facts in `observations.tsv`. | `raw/api/` for OpenAPI, GraphQL, gRPC, WSDL, or route-table artifacts. |
| [`parameter-discovery`](skills/surface-discovery/parameter-discovery.md) | Accepted parameter names per entrypoint, parser fingerprints, persistent diffs, source, coverage, and invalidated slices. | `recon/parameters.txt`; supported operations enriched in `recon/endpoints.md`; leads in `target.md` and `hypotheses.md`; parser facts in `observations.tsv`. | `raw/parameters/` or the run-specific child of `raw/http/`. |
| [`cloud-asset-discovery`](skills/external-assets/cloud-asset-discovery.md) | Provider/resource identity, discovery source, read state, write state, consumer, BaaS posture, and coverage note. | `recon/cloud.md`; high-value cloud leads in `target.md`; provider/account/function facts in `observations.tsv`. | `raw/cloud/`; sensitive recovered material belongs in `loot/`, not the local brain. |
| [`repository-and-secret-recon`](skills/external-assets/repository-and-secret-recon.md) | Repository/account inventory, artifacts checked, redacted credential candidates with verification verdict and authorized asset, and coverage by source. | `recon/repos.md`; internal names/endpoints/repository leads in `target.md`; package/CI/service facts in `observations.tsv`. | `raw/repos/`; clones and sensitive material stay in `loot/`. Secret values are never copied into local Markdown. |
| [`component-inventory`](skills/surface-discovery/component-inventory.md) | One row per host/component/version with precision, evidence rung, reachability, and exact/bounded/unknown counts. | `recon/components.md`; old or widely deployed component leads in `target.md`; version facts in `observations.tsv`. | `raw/components/` when manifests, bundles, lockfiles, or banners are retained; it may also read `raw/js/` and `raw/http/`. |
| [`authentication-surface-mapping`](skills/application-understanding/authentication-surface-mapping.md) | Auth flows, endpoints, call order, error paths, session mechanism, cookie scope, IdPs, token claims, reset and rate-limit behavior. | `applications/<host>/map.md`; `recon/endpoints.md`; auth model in `target.md`; auth leads in `hypotheses.md`; facts in `observations.tsv`. | `raw/auth/` or `loot/<run-id>/` for captured flows; authenticated secrets remain referenced through `accounts.md`, never embedded. |
| [`application-mapping`](skills/application-understanding/application-mapping.md) | Features, roles, trust boundaries, state machines, auth flow, app-only endpoints, surface diff, and coverage limitations by principal. | `applications/<host>/{map.md,endpoints.md,notes.md}`; target-wide `recon/endpoints.md`; concrete leads in `hypotheses.md`; facts in `observations.tsv`. | Existing `raw/http/`, `raw/js/`, and `raw/api/` are read; new browser/request captures go to `loot/<run-id>/` and small redacted controls to local `raw/`. |
| [`derive-properties`](skills/context-and-prioritization/derive-properties.md) | One row per entrypoint with closed-vocabulary properties, evidence pointers, undetermined fields, and source→sink reason. | `attack-surface.md`; supported class leads in `hypotheses.md`; target-wide facts in `observations.tsv`. Rank and score remain empty. | —; this is local reasoning over stored evidence. |
| [`host-correlation-and-clustering`](skills/context-and-prioritization/host-correlation-and-clustering.md) | Candidate clusters, members, agreeing axes, representative, linked facts, explicit singletons, and unclusterable coverage. | `clusters.md`; outlier/stale-member leads in `target.md`; confirmed relationship facts in `observations.tsv`. | Reads `raw/http/*.json*`; reducer output is curated locally rather than creating another bulk corpus. |
| [`cross-host-endpoint-reuse`](skills/context-and-prioritization/cross-host-endpoint-reuse.md) | Confirmed route reuse with method, control, evidence, per-host difference sets, and replay coverage. | `recon/endpoints.md`; `recon/wordlists/`; control-gap leads in `target.md` and `hypotheses.md`; relationship facts in `observations.tsv`. | `raw/content/` or `raw/http/` for bounded replay results. |
| [`attack-surface-prioritization`](skills/context-and-prioritization/attack-surface-prioritization.md) | Ranked rows with scoring columns and a reason tied to evidence; top evidence-bound hypotheses. | `attack-surface.md`; `hypotheses.md`; any estate-wide ranking facts in `observations.tsv`. | —; local computation over the brain. |
| [`recon-summary-and-handoff`](skills/context-and-prioritization/recon-summary-and-handoff.md) | Coherent architecture/auth/stack summary, reconciled manifest, top leads, blind dimensions, and resumable handoff. | `target.md`; `index.md`; tidied `hypotheses.md`; generated `recon-review.html`; completed run in `runs.tsv`. | Reads pointers as needed but creates no new target-traffic corpus. |
| [`monitoring-and-diff`](skills/monitoring/monitoring-and-diff.md) | Immutable baseline/snapshot, quarantined partial runs, pending additions/removals/status-tech changes/JS-content changes, and reviewed delta. | On review: unranked/property-empty rows in `attack-surface.md`; leads in `target.md`; change facts in `observations.tsv`; interval and limits in `runs.tsv`. | `raw/snapshots/`; pending delta remains reviewable there through `monitor.py pending`. |

## Vulnerability skills

A vulnerability invocation loads [`skills/vulnerability-testing/vuln-hunt.md`](skills/vulnerability-testing/vuln-hunt.md), the shared
[`_master-vuln-hunting.md`](playbooks/vulns/_master-vuln-hunting.md), and one canonical class file.
Every canonical class below uses the same storage contract:

1. **Remote execution evidence** — an HTTP/CLI test first writes to VPS `loot/<run-id>/` (or a
   class-specific child of `raw/`) plus `logs/exec/`. Browser/Burp work can originate locally.
2. **Durable proof** — the smallest redacted request/response, browser capture, trailer, or OOB log
   needed to reproduce the conclusion is stored in local `raw/` or
   `investigations/<lead>/`. Credentials are placeholders pointing to `accounts.md`.
3. **Coverage** — every sent probe writes one `tested.md` row keyed by
   `entrypoint × class × principal × variant`, including evidenced negatives and limitations.
4. **Disposition** — `hypotheses.md` becomes confirmed, rejected, inconclusive, or remains open.
   Confirmed candidates start in `findings/draft/`, graduate to `findings/confirmed/` only after
   proof, impact, refutation, and novelty checks, and disproven leads go to `findings/rejected/`.
5. **Context delta** — incidental architecture/auth/relationship facts update `target.md`, the
   relevant app map, or `observations.tsv`; `index.md` and `runs.tsv` close the unit.

### Files every vulnerability skill updates

For a class such as `idor-bola`, `<class>` below becomes `idor-bola`. `<case>` is a short slug for
the entrypoint/variant so two tests in one run cannot overwrite each other.

| Filename | When it is written |
|---|---|
| `raw/<run-id>-<class>-<case>/evidence.md` | Always. Names the entrypoint, principal, variant, oracle, redactions, source command record, and which evidence files are present. |
| `raw/<run-id>-<class>-<case>/control-request.txt` | The normal or role-correct HTTP/RPC request, credentials placeholdered. |
| `raw/<run-id>-<class>-<case>/control-response.txt` | The response establishing expected behavior. |
| `raw/<run-id>-<class>-<case>/test-request.txt` | The one-variable test request, credentials placeholdered. |
| `raw/<run-id>-<class>-<case>/test-response.txt` | The real test response. |
| `raw/<run-id>-<class>-<case>/browser-evidence.md` | Browser-only DOM/navigation/message proof when raw HTTP is not the oracle. |
| `raw/<run-id>-<class>-<case>/oob-callback.txt` | OOB proof when the discriminator is a unique callback. |
| `raw/<run-id>-<class>-<case>/transport-evidence.txt` | Non-HTTP-body evidence such as gRPC trailers or WebSocket frames. |
| `tested.md` | One row for each probe actually sent, including evidenced negatives. `artifact_ptr` points to `evidence.md`. |
| `hypotheses.md` | The tested hypothesis changes status and gains the evidence pointer. |
| `findings/draft/<finding-slug>.md`, `findings/confirmed/<finding-slug>.md`, or `findings/rejected/<finding-slug>.md` | The result's disposition. A negative does not create a draft; a disproven lead creates a rejection note. |
| `index.md` and `runs.tsv` | Manifest state and the closed bounded run. |
| `observations.tsv`, `target.md`, `applications/<host>/map.md`, `user-flows.md`, or a recon file named in the class row | Only when the test establishes a durable fact beyond the single coverage cell. |

`evidence.md` is mandatory; the channel-specific files are created only when that channel exists.
A browser-only test must not create fake empty HTTP files, and an HTTP test must not hide its
request/response inside prose. **No stored artifact means no vulnerability FACT.**

The table below shows the class-specific evidence and any file beyond the standard set above.

| Canonical class | Evidence bundle directory | Distinct decision-ready artifact/output and additional file |
|---|---|---|
| [`authentication-bypass`](playbooks/vulns/authentication-bypass.md) | `raw/<run-id>-authentication-bypass-<case>/` | Pre-auth control versus the smallest response proving an authenticated state or action, with the issued session redacted and the alternate path recorded. |
| [`baas-rls`](playbooks/vulns/baas-rls.md) | `raw/<run-id>-baas-rls-<case>/` | The same BaaS query/object under controlled principals or anon, including policy result; durable service/rule facts may also update `recon/cloud.md`. |
| [`cache-poisoning`](playbooks/vulns/cache-poisoning.md) | `raw/<run-id>-cache-poisoning-<case>/` | Unique safe cache key, MISS→HIT sequence, unkeyed input, victim-side control, and response body. This class also owns cache deception. |
| [`cloud-misconfiguration`](playbooks/vulns/cloud-misconfiguration.md) | `raw/<run-id>-cloud-misconfiguration-<case>/` | Minimal read/list/write-policy proof against a controlled object, plus resource/consumer state; durable inventory may also update `recon/cloud.md`. |
| [`command-injection`](playbooks/vulns/command-injection.md) | `raw/<run-id>-command-injection-<case>/` | Baseline and benign output/timing/OOB discriminator showing command execution without destructive commands. |
| [`cors`](playbooks/vulns/cors.md) | `raw/<run-id>-cors-<case>/` | Request with controlled `Origin`, preflight/actual response headers, credential mode, and proof that sensitive content is browser-readable. |
| [`coupon-and-credit-abuse`](playbooks/vulns/coupon-and-credit-abuse.md) | `raw/<run-id>-coupon-and-credit-abuse-<case>/` | Legal control flow versus one bounded reuse/stack/order variation on the hunter's own account, including resulting balance/ledger state. |
| [`csrf`](playbooks/vulns/csrf.md) | `raw/<run-id>-csrf-<case>/` | Cross-origin-shaped request, cookie/SameSite context, anti-CSRF controls, and a safe state verification on the controlled account. |
| [`deserialization`](playbooks/vulns/deserialization.md) | `raw/<run-id>-deserialization-<case>/` | Serialized control and a benign type/behavior/OOB discriminator showing object reconstruction reached a dangerous path. |
| [`dom-clobbering`](playbooks/vulns/dom-clobbering.md) | `raw/<run-id>-dom-clobbering-<case>/` | Browser DOM/source-to-sink capture showing a named element shadows the expected object and changes a harmless observable behavior. |
| [`file-upload`](playbooks/vulns/file-upload.md) | `raw/<run-id>-file-upload-<case>/` | Upload request, storage/processing response, retrieval or execution control, and a harmless marker proving the server's treatment of the file. |
| [`function-level-authorization`](playbooks/vulns/function-level-authorization.md) | `raw/<run-id>-function-level-authorization-<case>/` | Identical operation under role-correct and lower-privilege principals, with the authorization result and route/handler `fix_locus`. |
| [`host-header-attacks`](playbooks/vulns/host-header-attacks.md) | `raw/<run-id>-host-header-attacks-<case>/` | Control and varied `Host`/forwarded-host request showing trusted link generation, routing, reset URL, or cache-key behavior. |
| [`idor-bola`](playbooks/vulns/idor-bola.md) | `raw/<run-id>-idor-bola-<case>/` | Owner request and one identity-swapped non-owner request for the same object, preserving the ownership and principal relationship. |
| [`ldap-injection`](playbooks/vulns/ldap-injection.md) | `raw/<run-id>-ldap-injection-<case>/` | Baseline and boolean/filter differential showing the input changes a directory query, not merely its error text. |
| [`lfi-rfi`](playbooks/vulns/lfi-rfi.md) | `raw/<run-id>-lfi-rfi-<case>/` | Normal include control versus a harmless local/remote include discriminator, with normalization and false-positive controls. |
| [`limit-bypass`](playbooks/vulns/limit-bypass.md) | `raw/<run-id>-limit-bypass-<case>/` | Counter state before/after a small bounded set of logically identical actions varied across the suspected bypass dimension. |
| [`llm-prompt-injection`](playbooks/vulns/llm-prompt-injection.md) | `raw/<run-id>-llm-prompt-injection-<case>/` | Synthetic untrusted content, model/tool boundary transcript, and proof of one unauthorized data/action effect without using researcher identity or real secrets. |
| [`mass-assignment`](playbooks/vulns/mass-assignment.md) | `raw/<run-id>-mass-assignment-<case>/` | Baseline body versus one extra field, followed by a legitimate reread of the hunter-owned object proving whether the field was bound. |
| [`mfa`](playbooks/vulns/mfa.md) | `raw/<run-id>-mfa-<case>/` | Normal two-factor flow and one alternate/skip/replay path, with the resulting session privilege and controlled-account state. |
| [`multi-tenant-isolation`](playbooks/vulns/multi-tenant-isolation.md) | `raw/<run-id>-multi-tenant-isolation-<case>/` | Same object/operation across controlled tenants, with direction and relationship recorded as the variant. |
| [`nosql-injection`](playbooks/vulns/nosql-injection.md) | `raw/<run-id>-nosql-injection-<case>/` | String control versus operator/type/structure differential proving query semantics changed. |
| [`oauth-oidc`](playbooks/vulns/oauth-oidc.md) | `raw/<run-id>-oauth-oidc-<case>/` | Redacted authorize/callback/token sequence with `redirect_uri`, state, PKCE, issuer/audience, and account-linking controls as applicable. |
| [`open-redirect`](playbooks/vulns/open-redirect.md) | `raw/<run-id>-open-redirect-<case>/` | Exact request and `Location`/navigation result proving an attacker-controlled destination, plus any allowlist normalization used. |
| [`origin-exposure`](playbooks/vulns/origin-exposure.md) | `raw/<run-id>-origin-exposure-<case>/` | Edge and candidate-origin requests with the same `Host`, body/certificate/control comparison, and the edge control demonstrably bypassed. |
| [`password-reset`](playbooks/vulns/password-reset.md) | `raw/<run-id>-password-reset-<case>/` | Controlled reset issuance, delivery, binding, expiry/reuse sequence, and resulting session/account state with tokens redacted. |
| [`path-traversal`](playbooks/vulns/path-traversal.md) | `raw/<run-id>-path-traversal-<case>/` | Normal path control versus encoded/normalized traversal that reaches a harmless known file or distinct file-handling response. |
| [`payment-abuse`](playbooks/vulns/payment-abuse.md) | `raw/<run-id>-payment-abuse-<case>/` | Server-calculated control versus one price/amount/currency/quantity variation on a sandbox or owned transaction, without completing a real charge. |
| [`postmessage`](playbooks/vulns/postmessage.md) | `raw/<run-id>-postmessage-<case>/` | Browser capture of sender origin, message shape, receiver checks, and one harmless sink/action reached by the message. |
| [`privilege-escalation`](playbooks/vulns/privilege-escalation.md) | `raw/<run-id>-privilege-escalation-<case>/` | Same privileged operation under role-correct and lower-role controlled principals, stopping at minimum proof. |
| [`prototype-pollution`](playbooks/vulns/prototype-pollution.md) | `raw/<run-id>-prototype-pollution-<case>/` | Pollution source and a benign observable gadget/control showing an inherited property changed application behavior. |
| [`race-conditions`](playbooks/vulns/race-conditions.md) | `raw/<run-id>-race-conditions-<case>/` | Synchronized bounded requests, timing/concurrency method, before/after invariant, and final state of only controlled resources. |
| [`registration`](playbooks/vulns/registration.md) | `raw/<run-id>-registration-<case>/` | Controlled signup/verification/duplicate-identity sequence and the resulting account binding or state. |
| [`request-smuggling`](playbooks/vulns/request-smuggling.md) | `raw/<run-id>-request-smuggling-<case>/` | Minimal front-end/back-end parsing differential with paired control and no victim traffic, poisoning, or destructive desync. |
| [`session-management`](playbooks/vulns/session-management.md) | `raw/<run-id>-session-management-<case>/` | Session issuance, rotation, logout/password-change invalidation, fixation/reuse control, and redacted cookie/token attributes. |
| [`sql-injection`](playbooks/vulns/sql-injection.md) | `raw/<run-id>-sql-injection-<case>/` | Baseline plus boolean/timing/benign-expression differential tied to a database oracle, not a generic error or WAF response. |
| [`ssrf`](playbooks/vulns/ssrf.md) | `raw/<run-id>-ssrf-<case>/` | URL-input control and unique attributable OOB callback or safe in-band destination difference, including redirect/DNS behavior used. |
| [`subdomain-takeover`](playbooks/vulns/subdomain-takeover.md) | `raw/<run-id>-subdomain-takeover-<case>/` | DNS chain plus provider ownership-validation/name-claimability proof; durable verdict also updates `recon/dns.md`. |
| [`template-injection`](playbooks/vulns/template-injection.md) | `raw/<run-id>-template-injection-<case>/` | Literal control versus an inert arithmetic/string expression showing server-side evaluation, without command execution. |
| [`user-enumeration`](playbooks/vulns/user-enumeration.md) | `raw/<run-id>-user-enumeration-<case>/` | Repeated valid-controlled versus known-invalid identity responses across the same channel, with stable body/timing/side-effect discriminator. |
| [`websocket`](playbooks/vulns/websocket.md) | `raw/<run-id>-websocket-<case>/` | Upgrade request and message exchange including origin, principal, message authorization, response frame, and role-correct control. |
| [`workflow-abuse`](playbooks/vulns/workflow-abuse.md) | `raw/<run-id>-workflow-abuse-<case>/` | Legal user journey versus one skipped/reordered/replayed transition, with pre/post state; durable journey knowledge may update `user-flows.md` and the app map. |
| [`xpath-injection`](playbooks/vulns/xpath-injection.md) | `raw/<run-id>-xpath-injection-<case>/` | Baseline and boolean/path differential showing XPath/XQuery semantics changed. |
| [`xss`](playbooks/vulns/xss.md) | `raw/<run-id>-xss-<case>/` | Source request plus browser execution evidence for a harmless unique canary, with the exact context and sink. |
| [`xxe`](playbooks/vulns/xxe.md) | `raw/<run-id>-xxe-<case>/` | XML control versus a safe external-entity/OOB or harmless local-read discriminator, without resource exhaustion. |

Three filenames are compatibility pointers, not separate coverage classes or output owners:
[`cache-deception`](playbooks/vulns/cache-deception.md) → `cache-poisoning`,
[`login`](playbooks/vulns/login.md) → `authentication-bypass` / `user-enumeration`, and
[`state-machine-abuse`](playbooks/vulns/state-machine-abuse.md) → `workflow-abuse`.

## Situation flows

A flow has no separate output namespace. It writes the union of the component skills the hunter
authorized, and every component still opens/closes its own run. Raw artifacts therefore remain in
the component skill's normal VPS bucket.

| Flow | Output and local files updated | VPS locations used |
|---|---|---|
| [`broken-calibration`](playbooks/flows/broken-calibration.md) | Host discriminator in `applications/<host>/notes.md` or target-wide state in `index.md`; void counts marked explicitly. A genuinely reusable quirk may update `playbooks/system/calibration-quirks.md`. | Calibration controls in the relevant `raw/<skill>/` bucket and command records in `logs/exec/`. |
| [`dead-end-host`](playbooks/flows/dead-end-host.md) | As applicable: `recon/urls.txt`, `recon/js-findings.md`, `recon/content/<host>.md`, `recon/dns.md`; discovered entrypoints reach `attack-surface.md` through property derivation. An all-empty recovery result is recorded, not forgotten. | `raw/urls/`, `raw/js/`, `raw/content/`, `raw/dns/`. |
| [`spa-frontend`](playbooks/flows/spa-frontend.md) | `recon/js-findings.md`; `recon/endpoints.md`; `recon/parameters.txt`; `applications/<host>/{map.md,endpoints.md}`; propertied `attack-surface.md` rows. | `raw/js/`, plus `raw/api/` or `raw/http/` when contracts/calls are captured. |
| [`api-surface`](playbooks/flows/api-surface.md) | `recon/endpoints.md`; recovered contract pointers; propertied `attack-surface.md`; explicit unused-operation set. | `raw/api/`. |
| [`no-signup`](playbooks/flows/no-signup.md) | Authz work parked visibly in `attack-surface.md`; auth map in `applications/<host>/map.md`; pre-auth leads in `hypotheses.md`. Any separately invoked vulnerability probe uses the standard vulnerability write set. | Auth-flow captures in `raw/auth/` or `loot/`; class-test artifacts only when the hunter separately invokes them. |
| [`auth-app`](playbooks/flows/auth-app.md) | Credential references in `accounts.md`; `applications/<host>/{map.md,endpoints.md}`; user journeys in `user-flows.md`; observed properties in `attack-surface.md`. | `raw/auth/`, `raw/http/`, and `loot/<run-id>/` for controlled authenticated captures. |
| [`huge-estate`](playbooks/flows/huge-estate.md) | `clusters.md`; ranked cluster rows in `attack-surface.md`; individually named outliers. | Primarily reads `raw/http/`; any representative probes return to `raw/http/` or `raw/content/`. |
| [`static-site`](playbooks/flows/static-site.md) | Results of its bounded takeover/cache/storage/content checks in their owning files; `tested.md` rows only for actual class probes; dated triage note in `index.md` or `clusters.md`. | `raw/dns/`, `raw/content/`, `raw/cloud/`, and `loot/` as the component check requires. |
| [`first-look`](playbooks/flows/first-look.md) | `recon/subdomains.txt`; `recon/resolved.txt`; `recon/live-hosts.txt`; `recon/technologies.md`; first unranked `attack-surface.md` entrypoints; one `runs.tsv` row per component. | `raw/subdomains/`, `raw/dns/`, `raw/http/`. |
| [`stale-return`](playbooks/flows/stale-return.md) | Ages for relied-on inputs, new/gone/changed delta, affected `attack-surface.md` rows, and refreshed `index.md` timestamp. | New dated artifacts in only the raw buckets required to refresh the stale slice. |

## Workflows

Workflows are reasoning lenses or bounded process helpers. Some are passive and some hand off into
the standard vulnerability contract; the table distinguishes them.

| Workflow | Output and local files updated | VPS / traffic behavior |
|---|---|---|
| [`compare-two-accounts`](playbooks/workflows/compare-two-accounts.md) | Paired redacted request/responses in `raw/` or `investigations/<lead>/`; one `tested.md` row per direction/principal; hypothesis disposition; finding draft or rejection; `index.md`. | Active test. Remote copies may start in `loot/<run-id>/`; runner evidence in `logs/exec/`. |
| [`design-validation-test`](playbooks/workflows/design-validation-test.md) | Written if/then hypothesis, discriminator, exact controls, safe probe, and capture plan in `investigations/<lead>/notes.md`. | No traffic and no test row; execution is a later vuln-hunt step. |
| [`generate-hypotheses`](playbooks/workflows/generate-hypotheses.md) | New ranked, falsifiable rows in `hypotheses.md`; updated count/timestamp in `index.md`; bounded run in `runs.tsv`. | No traffic; local reasoning only. |
| [`import-traffic`](playbooks/workflows/import-traffic.md) | Credential-stripped `recon/endpoints.md` rows and host/auth facts in `observations.tsv`; after review, new entrypoints are appended unranked to `attack-surface.md`. It never writes `tested.md` or credentials into `accounts.md`. | Local import of HAR/Burp XML/sitemap; no target traffic and no VPS artifact unless the supplied capture already lives there. |
| [`investigate-api-surface`](playbooks/workflows/investigate-api-surface.md) | Recovered operations/contracts enrich `recon/endpoints.md`; varied-axis request/control pairs go to `raw/` or an investigation; actual class probes update the standard vulnerability write set with route/verb/version/parser `fix_locus`. | Contract artifacts in `raw/api/`; active HTTP tests in `loot/<run-id>/` and `logs/exec/`. |
| [`investigate-asset`](playbooks/workflows/investigate-asset.md) | `applications/<host>/{map.md,endpoints.md,notes.md}`; `investigations/<asset>/`; concrete `hypotheses.md` rows; `index.md`. | Passive/read-only mapping by default; any saved captures follow the application-mapping locations. |
| [`investigate-endpoint`](playbooks/workflows/investigate-endpoint.md) | Function/input/data-flow/role model in `investigations/<endpoint>/notes.md`; new `hypotheses.md`; promoted app-map/endpoint facts; `index.md`. | Passive by default. Any request actually sent gets a redacted artifact in the investigation or `raw/`, but no `tested.md` row unless a class was tested. |
| [`investigate-graphql`](playbooks/workflows/investigate-graphql.md) | Recovered schema/operations in `recon/endpoints.md` and a stored contract; `graphql` property on relevant `attack-surface.md` rows. Actual probes log under the canonical class and resolver `fix_locus`, never a `graphql` class. | `raw/api/` for schema/manifests; class tests in `loot/<run-id>/` with query, response, role, and transport oracle. |
| [`investigate-grpc`](playbooks/workflows/investigate-grpc.md) | Recovered services/methods in `recon/endpoints.md`; `grpc` property on `attack-surface.md`. Actual probes log under the canonical class and RPC/interceptor `fix_locus`, preserving `grpc-status`. | `raw/api/` for descriptors/protos; class tests in `loot/<run-id>/` and `logs/exec/`. |
| [`n-day-sweep`](playbooks/workflows/n-day-sweep.md) | Scanner hits become **only** `hypotheses.md` rows with raw pointers; cohort, pilot, unversioned hosts, and limits are recorded in `runs.tsv`/`index.md`. It writes neither `tested.md` nor `findings/`. | `raw/sweeps/`; pilot first, then explicitly authorized scale. |
| [`read-response-signals`](playbooks/workflows/read-response-signals.md) | Supplied request/response in `raw/` or `investigations/<lead>/`; candidates in `hypotheses.md`; new stack/auth facts in `recon/technologies.md`, `target.md`, and `observations.tsv`; `index.md`. | No new traffic; reads a capture already supplied. |
| [`reassess-after-failure`](playbooks/workflows/reassess-after-failure.md) | Evidenced negative/inconclusive row in `tested.md`; updated `hypotheses.md`; disproven lead in `findings/rejected/`; by-catch in app map/`target.md`; `index.md`. | No new traffic unless the hunter later selects the sharper retry. |
| [`recover-js-chunks`](playbooks/workflows/recover-js-chunks.md) | Local provenance/frontier ledgers in `raw/js/{js-sources.tsv,chunk-graph.tsv,chunk-frontier.tsv,chunk-candidates.txt}`; normalized `recon/js-findings.md`; optional `recon/components.md`. | Bulk bundles remain in VPS `raw/js/`; each authorized fetch goes through the HTTP harness. |
| [`research-component`](playbooks/workflows/research-component.md) | Version/advisory candidates in `hypotheses.md`; reported source facts in `observations.tsv`; fixed-in/version precision in `recon/components.md`. | Public-source research only; no target test. A later cohort uses `n-day-sweep`. |

## Router and maintenance skills

These are not recon phases, vulnerability classes, flows, or workflows, but hunters commonly invoke
them and may wonder whether they own an output:

| Skill | What it writes |
|---|---|
| [`init-target`](skills/setup/init-target.md) | Creates the complete local `targets/<t>/` brain and registry row, then stops. It sends no traffic and creates no VPS raw output. |
| [`analyse-request`](skills/analysis/analyse-request.md) | Placeholdered request in `raw/<slug>-request.txt`; candidate rows in `attack-surface.md`; a new principal reference in `accounts.md` only when supplied; no `tested.md` row. |
| [`tech-analysis`](skills/analysis/tech-analysis.md) | Corrected technology/component facts, implicated entrypoints, and bounded hypotheses in their existing brain files. It does not test or create a finding. |
| [`compose-task`](skills/orchestration/compose-task.md) | Durable plan in `target.md`/`hypotheses.md`, one parent run in `runs.tsv`, and each composed skill's normal declared outputs. It has no private output directory. |
| [`ground-a-playbook`](skills/maintenance/ground-a-playbook.md) | Build-time KEEP or IMPROVE decision; on IMPROVE, a focused repository diff; gitignored `knowledge/MINED.tsv` only after verification. It does not touch a target brain. |
| [`run-flow`](skills/orchestration/run-flow.md) | Router only. The selected flow and its component skills own the outputs. Recommendation-only intent writes no target data. |
| [`vuln-hunt`](skills/vulnerability-testing/vuln-hunt.md) | Router only. The selected canonical class owns the standard vulnerability write set above. |

## How to inspect a completed run

```bash
# What changed, what is unfinished, and which files matter now
tools/brief.py <target> --resume

# Every bounded run, including failures and limitations
tools/kb.py runs targets/<target>

# Tool failures that survived the session
tools/runlog.py targets/<target> --failures

# What remains untested by entrypoint × class × principal × variant
tools/coverage.py targets/<target>

# Whether the local/VPS split is healthy and which raw pointers exist
tools/vps-sync.py status targets/<target>

# Pending monitor deltas not yet folded into the brain
tools/monitor.py pending targets/<target>
```

For the exact command, tool version, input hashes, output validation, and artifact hash, inspect the
matching `logs/exec/<stamp>-<skill>-<tool>.json`. For the reasoning result, read the local file in
the table above. Raw output alone is not a completed skill; the local brain delta and closed run are
the completion boundary.
