#!/usr/bin/env python3
"""Group an httpx JSON run into response-similarity candidates for human correlation.

    tools/cluster.py --from raw/http/2026-08-04-httpx.json          # print clusters
    ssh vps 'cat ~/targets/acme/raw/http/*.json' | tools/cluster.py # cluster the remote run
    tools/cluster.py --from <file> --write targets/acme             # also write recon/clusters.md

Why this exists
---------------
A large estate often repeats responses across many names. The pair **(exact body hash, observed
host IP)** is a useful reduction for finding those repetitions, but neither value proves an
application or origin: the IP may be an edge and the body may be a generic shell, WAF page, or
catch-all. This tool therefore produces *candidate groups*, not a distinct-application count and
not a `shares-backend` fact. Promote a group only after another independent application/origin
axis agrees (for example a session-cookie namespace, origin certificate, application-specific 404,
or a shared unique route).

A shared FRONT is not a shared BACKEND. An IP that answers with many different body hashes is an
edge/CDN signal, not proof; a known CDN CNAME is a stronger fronting annotation. The program
computes these signals and leaves every candidate explicitly unconfirmed.

Exit: 0 clustered · 1 no usable rows (says why) · 2 bad input.
"""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

# CNAME suffixes that mean "behind a shared front" — a cluster on one of these is not one origin.
CDN_SUFFIXES = (
    "cloudfront.net", "fastly.net", "akamai.net", "akamaiedge.net", "edgekey.net", "edgesuite.net",
    "cloudflare.net", "cloudflare.com", "azureedge.net", "azurefd.net", "googleusercontent.com",
    "gslb.taobao.com", "yahoodns.net", "impervadns.net", "incapdns.net", "cdn77.org", "b-cdn.net",
    "llnwd.net", "cdnetworks.net", "stackpathdns.com", "netdna-cdn.com",
)
def body_hash(d):
    h = d.get("hash")
    if isinstance(h, dict) and h.get("body_mmh3"):
        return str(h["body_mmh3"])
    return str(d["body_mmh3"]) if d.get("body_mmh3") else None


def first_cname(d):
    c = d.get("cname")
    if isinstance(c, list) and c:
        return str(c[0]).lower()
    return str(c).lower() if c else ""


def is_cdn_cname(cname):
    return any(cname == s or cname.endswith("." + s) for s in CDN_SUFFIXES)


def load_rows(stream):
    for line in stream:
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue


def cluster(rows, min_hosts, edge_threshold, status_filter):
    """Group by (body hash, host_ip). Returns (clusters, stats). Each cluster carries its member
    hostnames and annotations (CDN CNAME, edge IP) — annotations describe the front, they do NOT
    decide whether the group is one application. The pair establishes only that the same exact
    response content was observed through the same address."""
    groups = defaultdict(set)               # (body, ip) -> {hosts}
    meta = {}                               # (body, ip) -> representative row facts
    bodies_per_ip = defaultdict(set)        # ip -> {distinct body hashes}  (edge detector)
    cname_of = {}                           # host -> cname
    all_bodies = set()                      # distinct exact response bodies
    all_deploys = set()                     # distinct (body, observed-IP) pairs
    total = kept = 0

    for d in rows:
        total += 1
        bm = body_hash(d)
        ip = d.get("host_ip")
        if not ip and isinstance(d.get("a"), list) and d["a"]:
            ip = d["a"][0]                  # fall back to the first A record when host_ip is absent
        host = d.get("host") or d.get("input") or d.get("url")
        if not bm or not ip or not host:
            continue
        if status_filter is not None and d.get("status_code") != status_filter:
            continue
        host = str(host)
        # the IP appears as its own "host" when httpx probes bare addresses — not a real hostname
        if host == ip:
            continue
        kept += 1
        key = (bm, ip)
        groups[key].add(host)
        bodies_per_ip[ip].add(bm)
        all_bodies.add(bm)
        all_deploys.add(key)
        cname_of[host] = first_cname(d)
        if key not in meta:
            tech = d.get("tech")
            meta[key] = {
                "title": (d.get("title") or "").strip(),
                "tech": ", ".join(tech) if isinstance(tech, list) else (tech or ""),
            }

    clusters = []
    for (bm, ip), hosts in groups.items():
        if len(hosts) < min_hosts:
            continue
        cdn = any(is_cdn_cname(cname_of.get(h, "")) for h in hosts)
        edge_ip = len(bodies_per_ip[ip]) >= edge_threshold
        clusters.append({
            "body": bm, "ip": ip, "hosts": sorted(hosts), "n": len(hosts),
            "title": meta[(bm, ip)]["title"], "tech": meta[(bm, ip)]["tech"],
            "cdn": cdn, "edge_ip": edge_ip,
            "distinct_bodies_on_ip": len(bodies_per_ip[ip]),
        })
    clusters.sort(key=lambda c: (-c["n"], c["ip"]))
    stats = {"total": total, "kept": kept, "clusters": len(clusters),
             "body_variants": len(all_bodies), "pair_groups": len(all_deploys),
             # Compatibility for private scripts written against the first release. These names
             # must not be displayed as application/deployment facts.
             "apps": len(all_bodies), "deployments": len(all_deploys)}
    return clusters, stats


def render(clusters, stats, target_name, sample):
    out = []
    head = f"{target_name} — " if target_name else ""
    out.append(f"\n# {head}response-similarity candidates by (body-hash, observed IP)\n")
    out.append(f"  {stats['kept']} of {stats['total']} rows carry a body hash + IP.  "
               f"They contain {stats['body_variants']} exact body variant(s) and "
               f"{stats['pair_groups']} body/IP pair(s). These are reductions, not app counts.\n")

    catchall = [c for c in clusters if c["n"] >= sample["catchall"]]
    apps = [c for c in clusters if c["n"] < sample["catchall"]]

    if apps:
        out.append("  SIMILARITY GROUPS — hosts returned identical content through one observed IP.")
        out.append("  UNCONFIRMED: do not merge targets, infer duplicate impact, or record")
        out.append("  `shares-backend` until a second independent application/origin axis agrees.")
        out.append("  [cdn]/[edge-ip] makes shared-front infrastructure especially likely:")
        for c in apps[:sample["limit"]]:
            out.append(_line(c, sample))
        if len(apps) > sample["limit"]:
            out.append(f"    … {len(apps) - sample['limit']} more (raise --limit)")
        out.append("")
    if catchall:
        out.append(f"  CATCH-ALL / PARKED — one body across ≥{sample['catchall']} hosts on a single IP.")
        out.append("  Likely generic front pages. Sample and confirm before deprioritising; never")
        out.append("  create a backend edge from this signal alone:")
        for c in catchall[:sample["limit"]]:
            out.append(_line(c, sample))
        out.append("")
    if not clusters:
        out.append(f"  no (body-hash, IP) group reaches ≥{sample['min']} hosts — responses may be")
        out.append("  unique, dynamic, status-filtered, or missing hashes. No app-count inference.")
    return "\n".join(out) + "\n"


def _line(c, sample):
    flags = []
    if c["cdn"]:
        flags.append("cdn")
    if c["edge_ip"]:
        flags.append(f"edge-ip:{c['distinct_bodies_on_ip']}bodies")
    flag = f"  [{', '.join(flags)}]" if flags else ""
    title = f'  "{c["title"][:48]}"' if c["title"] else ""
    tech = f"  {{{c['tech'][:48]}}}" if c["tech"] else ""
    sample_hosts = ", ".join(c["hosts"][:sample["hosts"]])
    more = f" (+{c['n'] - sample['hosts']})" if c["n"] > sample["hosts"] else ""
    return (f"    n={c['n']:<4} ip={c['ip']:<16} body={c['body']:<12}{tech}{title}{flag}\n"
            f"          {sample_hosts}{more}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", nargs="?", help="targets/<t> — only used to place --write output")
    ap.add_argument("--from", dest="src", metavar="FILE",
                    help="httpx JSONL file to cluster; omit to read stdin")
    ap.add_argument("--min", type=int, default=2, metavar="N",
                    help="minimum distinct hosts to call it a cluster (default 2)")
    ap.add_argument("--edge-threshold", type=int, default=8, metavar="N",
                    help="an IP answering N+ distinct bodies is a shared front, not an origin (default 8)")
    ap.add_argument("--status", type=int, default=200, metavar="CODE",
                    help="only cluster rows with this status; --status -1 for all (default 200)")
    ap.add_argument("--catchall", type=int, default=40, metavar="N",
                    help="a body on N+ hosts (one IP) is a catch-all/parked front, not an app (default 40)")
    ap.add_argument("--limit", type=int, default=25, help="max clusters per section to print")
    ap.add_argument("--hosts", type=int, default=4, help="sample hostnames to show per cluster")
    ap.add_argument("--write", metavar="TARGET", help="also write TARGET/recon/clusters.md")
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        ap.print_help(); return 0
    args = ap.parse_args()

    if args.min < 1:
        print("FAIL — --min must be at least 1", file=sys.stderr); return 2

    if args.src:
        src = Path(args.src)
        if not src.exists():
            print(f"FAIL — {src} does not exist", file=sys.stderr); return 2
        stream = src.open(encoding="utf-8", errors="replace")
    elif not sys.stdin.isatty():
        stream = sys.stdin
    else:
        print("FAIL — no input: pass --from FILE or pipe httpx JSONL on stdin", file=sys.stderr)
        return 2

    status_filter = None if args.status == -1 else args.status
    clusters, stats = cluster(load_rows(stream), args.min, args.edge_threshold, status_filter)
    if stream is not sys.stdin:
        stream.close()

    if stats["kept"] == 0:
        print("FAIL — no rows carried both a body hash and a host_ip. Wrong file, or an httpx run "
              "without -json/hash fields — cannot cluster.", file=sys.stderr)
        return 1

    target_name = None
    write_target = args.write or (args.target if args.target and args.target != "-" else None)
    if write_target:
        target_name = Path(write_target).name
    sample = {"min": args.min, "limit": args.limit, "hosts": args.hosts, "catchall": args.catchall}
    report = render(clusters, stats, target_name, sample)
    print(report)

    if args.write:
        tdir = Path(args.write)
        if not (tdir / "index.md").exists():
            print(f"FAIL — {args.write} is not a target brain (no index.md); not writing",
                  file=sys.stderr)
            return 2
        recon = tdir / "recon"
        recon.mkdir(exist_ok=True)
        (recon / "clusters.md").write_text(
            f"# {tdir.name} — host clusters\n\n"
            "> Derived by `tools/cluster.py` from exact response body + observed IP.\n"
            "> Every group is an unconfirmed similarity candidate. Require a second independent "
            "application/origin axis before merging hosts or recording `shares-backend`.\n"
            + report, encoding="utf-8")
        print(f"  wrote {recon / 'clusters.md'} ({(recon / 'clusters.md').stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
