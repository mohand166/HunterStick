# <TARGET> — DNS Analysis

> `dns-analysis`. A *reasoning* file, not a flat list: notable records, CNAME chains, takeover
> candidates, email-auth posture, and what the name-shape tells you about the estate
> (corp/dev/stg/api/admin buckets). Raw: VPS `~/targets/<target>/raw/dns/`.

## Summary
- <hosts resolved / of how many discovered>
- <how many have CNAMEs>
- <takeover candidates — and what filter produced them (state its blind spots)>

## Notable records
| host | record | value | chain | takeover_candidate | notes | source |
|---|---|---|---|---|---|---|

## Surface shape (name buckets)
- <corp / dev / stg / qa / api / admin / login / vpn / oauth counts — where the interesting hosts cluster>

## Email auth
- SPF / DKIM / DMARC posture: <>
