# Optional report collections

HunterStick accepts ordinary user-supplied material under `knowledge/<subject>/`; reports do not
need a special pipeline. This directory remains supported for existing collections organized as:

```text
knowledge/reports/<subject>/
  ...report or research files...
```

If a legacy collection contains both `<id>.json` and `md/<id>.md`, the richer rendered copy wins;
raw-only files remain visible. New collections should prefer the simpler `knowledge/<subject>/`
layout described in `knowledge/README.md`.

## Optional HackerOne fetch helper

The repository includes a source-specific helper for disclosed HackerOne reports:

```bash
knowledge/tools/h1-fetch.sh sql-injection TOPSQLI.md --limit=5
knowledge/tools/h1-fetch.sh sql-injection TOPSQLI.md
```

It gets report IDs from `reddelexc/hackerone-reports` and caches available report JSON under
`knowledge/reports/<class>/`. It is resumable and records `full`, `no-content`, and `gone` states.

Credentials come from `api_keys.hackerone.{username,token}` in the gitignored `config.json`, read
through `tools/config.py`. `H1_USER` and `H1_TOKEN` may override them for CI or a one-off run. The
helper never prints the credentials.

The fetcher is optional. Users may add reports or research from any lawful source directly, without
credentials, fetching, rendering, a minimum corpus size, or a fixed file schema.

## Optional integrity helpers

For vulnerability reference files that use HackerOne-style `[#12345]` citations:

```bash
knowledge/tools/check-citations.py idor-bola
knowledge/tools/check-dispositions.py idor-bola
```

These checks are relevant only when the source collection provides report IDs and disposition
metadata. They are not gates for ordinary notes or research.

Whatever source you use, respect its terms and rate limits and do not publish material you do not
have the right to redistribute. Everything below `knowledge/` remains gitignored by default.
