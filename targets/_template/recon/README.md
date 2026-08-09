Normalized recon data lives here. See playbooks/system/target-schema.md for file schemas.

- **`components.md`** — component-inventory. One row per `(host, component, version)`. This is the file an n-day selector reads: `technologies.md` says *what stack*, this says *which version*. A row with `precision: unknown` is real data — it means the component is present and the version is not established, which is different from the component being absent.
