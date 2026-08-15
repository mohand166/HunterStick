# Recon Toolkit — the fallback, not the mapping

> **A skill names the tools its objective reaches for** — `content-discovery` says `ffuf`,
> `url-collection` says `katana` — and it loads at exactly the moment you are choosing one. That
> mapping lives next to the method it belongs to.
>
> **What a skill deliberately does NOT give you is the invocation.** No flag lists, no command
> templates: `skills/shared/_recon-method.md` puts tool correctness on you, every run, against the
> binary actually installed. That is not an omission this file fills. A skill once instructed two
> `httpx` flags that do not exist in the installed build, and every downstream parse would have
> reported a confident zero across 62,646 targets. **A flag list is `--help` with a shelf life.**
>
> So this file is for the two cases a skill cannot cover: a task no skill describes, and a tool
> you have not used before. **A general "best tool" list rots** — it was true when written and
> nothing detects when it stops being true.
>
> **Prefer this target's own evidence over anything below.** `tools/runlog.py <t>` shows which
> tools have actually run and what they exited with; `tools/kb.py patterns <t>` shows what they
> found. "ffuf returned nothing on this host three times and katana found the routes" is a fact
> about *this* engagement and beats any recommendation here.


## Asset discovery

| Task | Primary | Alternatives | Retired → use instead |
|---|---|---|---|
| Passive subdomain enum | **subfinder** (with API keys — see below) | amass (v5) & **BBOT** for depth, Subdominator, github-subdomains, Chaos | ✗ Sublist3r (dead); assetfinder/findomain (low coverage) |
| Active brute + resolve | **puredns** (wraps massdns; wildcard-safe) | shuffledns | ✗ raw massdns scripts |
| Permutation generation | **alterx** | gotator, dnsgen (AlephNullSK fork) | ✗ altdns / goaltdns |
| DNS resolution & records | **dnsx** | puredns resolve (wildcard-heavy targets) | — |
| ASN / CIDR / IP ranges | **asnmap** + **mapcidr** (expand) | metabigor (no API key), ASNHunter | — |
| Org / root-domain discovery | **pius** (Praetorian; CT+RIR+whois+favicon+registries) | amass intel, reverse-whois (Whoxy), crt.sh `O=` pivot, favicon→Shodan | — |

**Resolvers:** use `trickest/resolvers` (rebuilt daily); keep a small **trusted** set
(8.8.8.8, 1.1.1.1) for final validation; `dnsvalidator` to build your own if brute-forcing at scale.
**API keys that most improve passive coverage** (subfinder/amass config): SecurityTrails,
Censys, Shodan, VirusTotal, GitHub tokens, Chaos (high value); Netlas, FullHunt,
BinaryEdge, FOFA, IntelX (also good). **This is a generic list of what helps, not a claim any of
them are configured** — SecurityTrails and Censys are both paid and neither is keyed in this
project as of writing; run `tools/config.py check` before relying on a named source instead of
assuming it from this table.

## Host analysis

| Task | Primary | Alternatives | Retired → use instead |
|---|---|---|---|
| Live host + HTTP probe | **httpx** (status/title/tech/redirect/CDN/hash) | httprobe (bare alive only) | ✗ httprobe beyond alive-check |
| Port + service scan | **naabu** (fast sweep) → **nmap -sV** (versions) | masscan (huge ranges), rustscan | ✗ nmap-alone for large scope |
| Tech fingerprinting | **httpx -td** (scale); **whatweb** (deep single host) | webanalyze, nuclei tech templates | ✗ Wappalyzer CLI (went commercial) |
| Screenshots at scale | **gowitness** | WitnessMe; Eyeballer (triage shots) | ✗ **aquatone** (abandoned); EyeWitness (buggy) |
| Favicon correlation | **httpx -favicon** (mmh3) | FavFreak, favicon_hash_shodan | — |
| TLS/SAN + JARM correlation | **tlsx** (`-san -cn -jarm`) | cero (fast SAN), crt.sh | ✗ manual openssl scripts |
| WAF / CDN detection | **wafw00f** (WAF) + **cdncheck** (CDN/cloud/WAF class) | whatwaf | — |

JARM + favicon-mmh3 + shared cert SAN = the strong signals for clustering hosts by
backend (host-correlation-and-clustering) and finding origin IPs behind a CDN.

## Content & data

| Task | Primary | Alternatives | Retired → use instead |
|---|---|---|---|
| URL collection (archives) | **gau** (broad); **waymore** (deep — pulls response bodies) | github-endpoints, cariddi | ✗ waybackurls (single-source) |
| Active / JS-aware crawl | **katana** (`-headless -jc -kf all`) | — | ✗ gospider, hakrawler (for JS coverage) |
| URL dedupe / denoise | **uro** | — | — |
| Content / dir discovery | **feroxbuster** (recursive) + **ffuf** (surgical) | dirsearch | ✗ dirb, DirBuster, gobuster-dir |
| Parameter discovery | **x8** (fast) / **Arjun** (classic) | Burp Param Miner; ParamSpider (names→seed) | — |
| JS endpoint extraction | **jsluice** (AST — beats regex) | xnLinkFinder | ✗ LinkFinder, relative-url-extractor |
| Lazy-chunk graph recovery | **`tools/chunks.py`** (local, non-executing) | browser network capture for runtime-only loads | ✗ injecting/evaluating every discovered chunk |
| JS/repo secret detection | **trufflehog v3** (verified) + **gitleaks** (fast) | Nosey Parker, Mantra, js-snitch | ✗ trufflehog v2, gitrob, git-secrets |
| Source-map recovery | **sourcemapper** | unwebpack-sourcemap, unsourcemap | — |
| GraphQL | **graphw00f** (fingerprint) + **clairvoyance** (schema when introspection off) | InQL (Burp), graphql-cop, BatchQL | — |
| Swagger/OpenAPI | ffuf spec-brute + **nuclei** exposure templates | SwaggerHole | — |
| gRPC | **grpcurl** (reflection) + protoc from recovered `.proto` | grpcui | — |
| Cloud buckets/blobs | **cloud_enum** (multi) / **S3Scanner** | goblob, BlobHunter (Azure), GCPBucketBrute | ✗ lazys3, bucket_finder, AWSBucketDump |
| .git exposure | **git-dumper** / GitTools | nuclei git-exposure templates | — |
| GitHub/GitLab dorking | **gitdorks_go** / GitDorker (needs PAT) | manual dorks (HackTricks) | — |
| Vuln templating | **nuclei** + nuclei-templates (`-tags kev,cve,exposures,takeover`) | **cent** (aggregate community templates) | — |
| Quick-win confirmers | **dalfox** (XSS), gxss/kxss (reflection), subzy (takeover), **interactsh** (OOB/SSRF) | — | — |

**Wordlists:** **Assetnote** (regenerated monthly — freshest, tech-aware) + **SecLists**
(universal baseline: `raft-*`, `burp-parameter-names.txt`, `api/`); OneListForAll as a
consolidated mega-list. Params: Assetnote `parameters_top_1m`. Always pair discovery with
target-specific lists generated in parameter-discovery / used in content-discovery.

---

## The consensus pipeline

```
subfinder(+keys) → dnsx/puredns(+trickest resolvers) → alterx →
naabu → httpx(+tlsx+cdncheck) → gowitness →
gau/waymore + katana | uro →
feroxbuster/ffuf (Assetnote+SecLists) →
chunks.py fixed-point recovery → jsluice + trufflehog on the complete JS set →
nuclei
```

Every recon phase's example commands are drawn from this list — but they are **starting
points**: pick the tool here, then configure it adaptively for the target
(`adaptive-tooling.md`). If a tool isn't installed on the VPS, see `vps-setup.md`.
