# &lt;TARGET&gt; — Component Inventory

> `component-inventory`. One row per `(host, component, version)`. This is what turns a published advisory into
> a selector: `tools/kb.py cohort --tech <component> --version-lt <fixed-in>`.
>
> **`precision` is not decoration.** `exact` came from a manifest or a version constant; `bounded`
> means you narrowed it by behaviour; `unknown` means the component is present and the version is
> not established. A sweep built on a guessed version sends traffic against hosts that were never
> affected — write `unknown` and leave it.
>
> Every row also belongs in `observations.tsv` (`--predicate runs --object "<name> <version>"`) —
> `cohort` reads the ledger, not this table. A row that lives only here is invisible to the n-day
> path.
>
> Column order is fixed by `playbooks/system/target-schema.md` — later skills parse it.

| host | component | version | precision | reachable | evidence | confidence | source |
|---|---|---|---|---|---|---|---|

<!-- precision:  exact | bounded | unknown
     reachable:  yes | no | unknown  — present in a bundle is not the same as reachable at runtime
     confidence: observed (you saw the version) | reported (a header said so) | inferred (asset hash)
     evidence:   the artifact and where in it — raw/js/app.bundle.js:1, /health, a stack trace
     source:     the phase or file that produced it -->

## Not yet inventoried

> Hosts that have been fingerprinted (technology-fingerprinting) but not decomposed into components. Keep this list
> honest — an empty inventory for a host is `missing`, not `no components`.

- &lt;host — or "none: every live host has been inventoried"&gt;

## Vendored / forked

> Components whose version string cannot be trusted because the code was modified. Record them
> here rather than dropping them: they are excluded from version-based cohorts, and they are often
> the more interesting ones.

- &lt;component · host · why the version is unreliable&gt;
