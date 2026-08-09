# Flow — first look ("know my target")

> The one-time orientation pass. You have a scope statement and nothing else, and the question is
> not *"where is the bug"* — it is **"what is this?"** Four phases answer that, and running them
> one request at a time through four separate asks is the most common reason a target sits
> half-mapped for a week.
>
> **This flow is quiet by design.** It ends with a picture of the estate and a first attack
> surface. It does not port-scan, and it does not fuzz.

## Situation
A target exists, `scope.md` is filled, and `recon/` is empty or nearly so. Typically the first
thing you run on a new engagement.

## Preconditions
- `scope.md` parses and is not a placeholder — everything below derives its selector from it.
- Nothing else. That is the point: this is the flow with no upstream.

## Steps

1. **Subdomain enumeration.** Passive sources first, from the authorised enumeration roots
   (`tools/scope-filter.py <t> --roots`). A wildcard is a *seed*; an exact host authorises only
   itself, so a single-host scope skips straight to step 3.
   → `skills/subdomain-enumeration.md`
2. **Live host validation.** Resolution and reachability. Turns an enumeration list into a
   working set, and the ratio is itself informative: 4,000 names resolving to 40 hosts means a
   wildcard DNS record, not an estate.
   → `skills/live-host-validation.md`
3. **HTTP probing.** Status, title, redirect chain, server. **This is the step that pays**:
   titles and redirects are where admin portals, CMS installs and login walls announce themselves.
   Append the notable ones to `attack-surface.md` as you go — rank empty, `why` filled.
   → `skills/http-probing.md`
4. **Technology fingerprinting.** Server, framework, version, favicon hash, error shape. This
   is what makes everything afterwards cheap: `host-correlation-and-clustering`, tech-risk scoring
   in `attack-surface-prioritization`, and the n-day cohorts you will want the next time a CVE
   lands.
   → `skills/technology-fingerprinting.md`

**Conditional, by scope shape** — insert before step 1 when they apply:
`dns-analysis` when the wildcard is large enough that CNAME chains matter, or when takeover is
plausible · `asn-and-ip-discovery` when scope is an IP or CIDR rather than a name.

## Explicitly NOT in this flow

- **Port and service discovery.** It is loud, and a bundle cannot silently decide to
  portscan an estate. Ask for it separately, with a selector and a budget, once step 4 has told
  you which hosts are worth it.
- **Content discovery.** Loud, and worthless before calibration.
- Anything that sends a payload. This flow triages; `vuln-hunt` tests.

## Aborts
- **Step 1 returns thousands of names** → stop and switch to `huge-estate`. Probing 4,000 hosts
  one at a time is not orientation, it is a budget.
- **Step 2 kills nearly everything** → suspect wildcard DNS. Verify with a random nonexistent
  label before believing either the big number or the small one.
- **Step 3 shows one real application and the rest parked** → you have your answer early. Skip
  step 4 for the parked hosts and enter `auth-app`, `api-surface` or `spa-frontend` on the live one.
- **Scope is a single host** → steps 1 and 2 have nothing to do. Start at step 3.

## Cost
One request per name in step 2, one or two per host in steps 3–4. On a normal estate: minutes, and
a few thousand requests. On a large one, `huge-estate` is the flow, not this.

## Output
- `recon/subdomains.txt` · `recon/live-hosts.txt` · `recon/technologies.md`
- `attack-surface.md` — first entrypoints, unranked
- `index.md` — state, and a run per skill in `runs.tsv`

## Exit
Say what the target **is**, in one paragraph: how many live hosts, what stack, how many distinct
applications, and the two or three hosts that stand out and why. Then name the flow that fits the
most interesting one. If the estate is large enough that a representative-based approach is needed,
say that instead of listing hosts.
