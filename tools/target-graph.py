#!/usr/bin/env python3
"""Derive the engagement's relationship graph from the brain, on demand — for chains and linkage.

    tools/target-graph.py targets/acme                 # the graph: nodes, edges, components
    tools/target-graph.py targets/acme --linkage api.acme.com   # blast radius of one node
    tools/target-graph.py targets/acme --chains        # vuln chains, and low-sev seeds worth pairing

Why this exists
---------------
`kb.py chains` already walks host↔host **trust edges** (references, shares-session, shares-secret,
shares-backend …) and finds multi-hop paths. This adds the layer above it: the **vulnerability**
graph. It joins those trust edges to the *findings and open hypotheses* — so a **low-severity
primitive that is noise on its own becomes a chain seed**: an open-redirect on A plus an OAuth flow
on B that trusts A is an account takeover, and this names that pairing (and, when only half of it
exists, names the missing half to go hunt).

It is DERIVED, never stored: it reads `observations.tsv` (trust edges), `hypotheses.md`,
`attack-surface.md` and `findings/` (vuln primitives) every run. The files stay the readable source
of truth; there is no graph database to drift. Nothing here sends traffic or mutates the brain.

Exit: 0 produced a graph · 1 the brain is too empty to graph (says what is missing) · 2 not a brain.
"""
import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import kb   # noqa: E402  — reuse the predicate vocabulary; one definition, no drift

# Classes that are LOW severity ALONE but are classic chain seeds — the ones a hunter drops and a
# triager closes N/A, yet each completes a critical when paired. Naming them is the whole point.
LOW_SEED_CLASSES = {
    "open-redirect", "cors", "host-header-attacks", "cache-deception", "cache-poisoning",
    "postmessage", "dom-clobbering", "clickjacking", "user-enumeration", "session-management",
    "subdomain-takeover", "origin-exposure",
}

# A hypothesis in one of these states is NOT a present primitive — it was looked at and dismissed.
REJECTED_STATUS = {
    "rejected", "invalid", "wontfix", "duplicate", "closed", "n-a", "na", "false-positive", "dismissed",
}

# Chain rules: name, the vuln primitives it needs, the trust-edge predicate(s) that would connect
# them (None = no host↔host edge required), the impact, and — for a DIRECTED connector between two
# primitives — which primitive class is the edge SUBJECT and which is the OBJECT. The predicate is
# specific on purpose (an n-day pivots over `shares-backend`, not any edge), and the direction is
# specific too: `references`/`authenticates-via`/`shares-secret`/`shares-session` are A→B only, so a
# reverse edge does not complete the chain. `direction` is None when the connector is symmetric or
# no edge is required.
CHAIN_RULES = [
    ("account-takeover", {"open-redirect", "oauth-oidc"},
     {"references", "shares-session", "authenticates-via"},
     "OAuth code/token exfil via the redirect → full account takeover",
     ("oauth-oidc", "open-redirect")),
    ("account-takeover", {"open-redirect", "authentication-surface-mapping"},
     {"references", "shares-session", "authenticates-via"},
     "redirect on a login/callback host → credential or code theft",
     ("authentication-surface-mapping", "open-redirect")),
    ("session-hijack", {"subdomain-takeover"}, {"references", "shares-session"},
     "claim the dangling host, then a cookie scoped to the parent or a CORS trust leaks the session",
     None),
    ("stored-xss", {"xss", "csrf"}, None,
     "a reflected/self XSS delivered via CSRF becomes persistent / cross-user", None),
    ("cross-origin-data-theft", {"cors"}, {"references", "shares-session"},
     "permissive CORS + a session-bearing endpoint on a trusting host → read another user's data",
     None),
    ("cloud-credential-theft", {"ssrf", "cloud-misconfiguration"}, None,
     "SSRF reaches the metadata endpoint of a cloud-hosted host → instance credentials", None),
    ("authz-bypass-via-secret", {"repository-and-secret-recon", "function-level-authorization"},
     {"shares-secret"},
     "a leaked key consumed by another host → authenticated access there",
     ("repository-and-secret-recon", "function-level-authorization")),
    ("cross-tenant", {"idor-bola", "multi-tenant-isolation"}, {"same-tenant-model"},
     "an object-ref bug where a tenant id from A is honoured by B → cross-tenant data", None),
    ("cluster-wide-nday", {"n-day"}, {"shares-backend"},
     "RCE/authz n-day on one host that shares-backend with a cluster → pivots across all members",
     None),
    ("mass-impact-cache", {"host-header-attacks", "cache-poisoning"}, None,
     "host-header injection poisoned into a shared cache → served to every user", None),
]


def norm(s):
    return re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-")


def load_primitives(tdir):
    """{normalized-class -> [(host, where, status)]} from open hypotheses, findings, and the
    attack-surface class column. These are the vuln nodes the chains reason over."""
    prims = defaultdict(list)

    hyp = tdir / "hypotheses.md"
    if hyp.exists():
        for line in hyp.read_text(encoding="utf-8", errors="replace").splitlines():
            c = [x.strip() for x in line.split("|")]
            if len(c) >= 7 and c[1].startswith("H-"):
                status = norm(c[5]) or "open"
                if status in REJECTED_STATUS:
                    continue                       # a dismissed hypothesis is not a present primitive
                host = re.sub(r"`", "", c[2])[:60]
                for cls in re.split(r"[/,]", c[3]):
                    if norm(cls):
                        prims[norm(cls)].append((host, f"hypothesis {c[1]}", status))

    surf = tdir / "attack-surface.md"
    if surf.exists():
        for line in surf.read_text(encoding="utf-8", errors="replace").splitlines():
            c = [x.strip() for x in line.split("|")]
            # rows are | rank | entrypoint | vuln_class | ... — data rows only
            if len(c) >= 4 and c[1] and c[3] and c[2] not in ("vuln_class", "") and "---" not in line:
                host = re.sub(r"[`*]", "", c[2])[:60]
                for cls in re.split(r"[/,]", c[3]):
                    if norm(cls) and "vuln_class" not in cls:
                        prims[norm(cls)].append((host, "attack-surface", "candidate"))

    for state in ("confirmed", "draft"):
        d = tdir / "findings" / state
        if d.is_dir():
            for f in d.glob("*.md"):
                t = f.read_text(encoding="utf-8", errors="replace")
                cls = re.search(r"(?im)^\s*(?:class|vuln[_-]?class)\s*[:=]\s*([a-z0-9 /-]+)", t)
                host = re.search(r"(?im)^\s*(?:host|target|url)\s*[:=]\s*(\S+)", t)
                if cls:
                    for one in re.split(r"[/,]", cls.group(1)):
                        if norm(one):
                            prims[norm(one)].append((host.group(1)[:60] if host else f.stem,
                                                     f"finding/{state}", state))
    return prims


def load_edges(tdir):
    """Trust edges (subject -> object, predicate) from observed EDGE_PREDICATES in observations.tsv."""
    rows = kb.read_rows(tdir)
    adj = defaultdict(list)
    edge_count = defaultdict(int)
    for r in rows:
        if r["predicate"] in kb.EDGE_PREDICATES and r["confidence"] == "observed":
            a, b = r["subject"], r["object"].strip().lower()
            adj[a].append((b, r["predicate"]))
            edge_count[r["predicate"]] += 1
            if r["predicate"] in kb.SYMMETRIC_EDGES:
                adj[b].append((a, r["predicate"]))
    return adj, edge_count, rows


def match_map(present, needed):
    """{wanted-class -> [present keys that satisfy it]}. Loose (so 'n-day (Next.js)', stored as
    'n-day-next-js', satisfies the 'n-day' rule) — but it returns the ACTUAL stored key, so a later
    prims[key] lookup finds the primitive instead of silently missing on the wanted alias."""
    out = {}
    for want in needed:
        haves = [have for have in present if want in have or have in want]
        if haves:
            out[want] = haves
    return out


def matches(present, needed):
    """Set of wanted classes that are satisfied — the thin view used for seed/PARTIAL logic."""
    return set(match_map(present, needed))


def host_tokens(cell):
    """Hostname-like tokens inside a primitive's host cell, which may be a bare host, a truncated
    string, or a descriptive phrase listing several ('on auth-gated APIs — api.x, dev.y')."""
    return set(re.findall(r"[a-z0-9][a-z0-9.-]*\.[a-z]{2,}", (cell or "").lower()))


def host_match(a, b):
    """Exact hostname or an explicit parent/subdomain relationship — NEVER a bare substring, so
    `evilapi.example.com` does not match `api.example.com`."""
    a, b = a.strip(".").lower(), b.strip(".").lower()
    return bool(a) and bool(b) and (a == b or a.endswith("." + b) or b.endswith("." + a))


def edges_by_pred(rows):
    """{predicate -> [(host_a, host_b)]} for observed edges; symmetric predicates get both directions."""
    out = defaultdict(list)
    for r in rows:
        if r["predicate"] in kb.EDGE_PREDICATES and r["confidence"] == "observed":
            a, b = r["subject"].strip().lower(), r["object"].strip().lower()
            out[r["predicate"]].append((a, b))
            if r["predicate"] in kb.SYMMETRIC_EDGES:
                out[r["predicate"]].append((b, a))
    return out


def class_hosts(haves, prims):
    """Every hostname carrying any of these present keys."""
    hs = set()
    for have in haves:
        for entry in prims.get(have, []):
            hs |= host_tokens(entry[0])
    return hs


def chain_link(needed, matched, prims, ebp, preds, direction):
    """Is the chain's trust link ACTUALLY present? `preds` = the acceptable predicate(s). A
    single-primitive chain needs an edge of an acceptable predicate incident to the primitive host.
    A multi-primitive chain needs one CONNECTING the two primitives' hosts — not merely an edge that
    touches one of them, not an edge of the wrong type, and — when `direction` names the required
    (subject_class, object_class) — not the reverse of a directed edge. Returns (True, edge) or
    (False, reason). `ebp` already expands SYMMETRIC edges both ways, so the stored orientation is
    the one that counts."""
    classes = sorted(needed)
    hostsets = {w: class_hosts(matched.get(w, []), prims) for w in classes}
    cand = [(p, a, b) for p in preds for (a, b) in ebp.get(p, [])]
    have_pred_edge = any(ebp.get(p) for p in preds)
    label = "/".join(sorted(preds))

    if len(classes) == 1:
        A = hostsets[classes[0]]
        for p, a, b in cand:
            if any(host_match(a, h) for h in A):
                return True, f"{p} on {a}"
        if not A:
            return False, "the primitive host is not a resolvable hostname — adjacency cannot be checked"
        return False, (f"no {label} edge touches {sorted(A)[0]}" if have_pred_edge
                       else f"no {label} edge recorded")

    if direction:                             # directed connector: subject→object, one way only
        subj, obj = direction
        S, O = hostsets.get(subj, set()), hostsets.get(obj, set())
        for p, a, b in cand:
            if any(host_match(a, h) for h in S) and any(host_match(b, h) for h in O):
                return True, f"{p}: {a} → {b}"
        return False, (f"no {label} edge from the {subj} host to the {obj} host" if have_pred_edge
                       else f"no {label} edge recorded")

    # symmetric / undirected connector: either orientation completes it (ebp holds both directions)
    for i, ci in enumerate(classes):
        for cj in classes[i + 1:]:
            A, B = hostsets[ci], hostsets[cj]
            for p, a, b in cand:
                if any(host_match(a, h) for h in A) and any(host_match(b, h) for h in B):
                    return True, f"{p}: {a} ↔ {b}"
    return False, (f"no {label} edge connects the two primitive hosts" if have_pred_edge
                   else f"no {label} edge recorded")


def basis_of(matched, hit, prims):
    """Chain confidence = the WEAKEST required class (a chain is only as sound as its shakiest
    primitive), where each class is taken at its STRONGEST available evidence. So one confirmed
    finding paired with one candidate reads as 'candidate', never 'confirmed'."""
    labels = {4: "confirmed", 3: "draft", 2: "hypothesis", 1: "candidate"}

    def prim_rank(where, status):
        if "confirm" in status or where == "finding/confirmed":
            return 4
        if where == "finding/draft" or status == "draft":
            return 3
        if where.startswith("hypothesis"):
            return 2
        return 1

    per_class = []
    for want in hit:
        best = 0
        for have in matched.get(want, []):
            for _, where, status in prims.get(have, []):
                best = max(best, prim_rank(where, status))
        per_class.append(best or 1)
    return labels[min(per_class)] if per_class else "candidate"


def shares_host(needed, matched, prims):
    """A chain that needs NO trust edge still needs its primitives CO-LOCATED — a reflected XSS on
    one host and a CSRF on an unrelated host is not a stored-XSS. Require one host common to every
    required class. Returns (True, host) or (False, reason)."""
    sets = [class_hosts(matched.get(w, []), prims) for w in sorted(needed)]
    if any(not s for s in sets):
        return False, "a primitive host is not a resolvable hostname — co-location cannot be checked"
    for h in sets[0]:
        if all(any(host_match(h, x) for x in s) for s in sets[1:]):
            return True, h
    return False, "the primitives are on unrelated hosts — a no-edge chain still needs them on one host"


def cmd_chains(tdir, prims):
    present = set(prims)
    _, edge_count, rows = load_edges(tdir)
    ebp = edges_by_pred(rows)
    print(f"\n# {tdir.name} — vuln chains  (findings + open hypotheses + surface candidates)\n")
    if not present:
        print("  no vuln primitives yet — run derive-properties, then vuln-hunt. Nothing to chain.")
        return 1

    seeds = sorted(present & LOW_SEED_CLASSES)
    if seeds:
        print("  LOW-SEV SEEDS present — noise alone, but each completes a chain if you find its pair:")
        for s in seeds:
            where = prims[s][0]
            print(f"    · {s}  (on {where[0]}, {where[1]})")
        print()

    ready, linkmissing, partial = [], [], []
    for name, needed, preds, impact, direction in CHAIN_RULES:
        matched = match_map(present, needed)
        hit = set(matched)
        miss = needed - hit
        if not hit:
            continue
        if miss:
            partial.append((name, hit, miss, matched, impact))
            continue
        basis = basis_of(matched, hit, prims)
        btag = "" if basis == "confirmed" else f"  [basis: {basis}, not a confirmed finding]"
        if preds is None:
            if len(needed) > 1:                       # no edge, but the primitives must co-locate
                ok, detail = shares_host(needed, matched, prims)
                if ok:
                    ready.append((name, hit, impact, f" · both on {detail}", btag))
                else:
                    linkmissing.append((name, hit, impact, detail, btag))
            else:
                ready.append((name, hit, impact, "", btag))
            continue
        ok, detail = chain_link(needed, matched, prims, ebp, preds, direction)
        if ok:
            ready.append((name, hit, impact, f" · {detail} — walk it (kb.py chains)", btag))
        else:
            linkmissing.append((name, hit, impact, detail, btag))

    if ready:
        print("  READY — primitives present and the connecting trust edge is on the right host:")
        for name, hit, impact, gate, btag in ready:
            print(f"    ✓ {name}: have {', '.join(sorted(hit))} → {impact}{gate}{btag}")
        print()
    if linkmissing:
        print("  LINK MISSING — primitives present, but the specific trust edge that connects them is not:")
        for name, hit, impact, detail, btag in linkmissing:
            print(f"    ⚠ {name}: have {', '.join(sorted(hit))} → {impact}{btag}")
            print(f"        {detail} — record or find that edge, then it is walkable")
        print()
    if partial:
        print("  PARTIAL — you hold one half; hunt the other to complete it:")
        for name, hit, miss, matched, impact in partial:
            for h in sorted(hit):
                w = prims[matched[h][0]][0]
                print(f"    ○ {name}: HAVE {h} (on {w[0]}) → FIND {', '.join(sorted(miss))} → {impact}")
        print()
    if not ready and not linkmissing and not partial:
        print("  primitives present, but none pair into a known chain yet. As findings land, re-run.")
    return 0


def cmd_linkage(tdir, node, adj, prims):
    """Blast radius over trust edges, DIRECTION-AWARE: outgoing reachability (following edge
    direction) is reported separately from incoming edges, because a directed a→b means b is
    reachable from a — not the reverse. A node with only an incoming edge is still in the graph."""
    print(f"\n# {tdir.name} — linkage from {node}\n")
    radj = defaultdict(list)
    for a, vs in adj.items():
        for b, pred in vs:
            radj[b].append((a, pred))
    in_graph = node in adj or node in radj
    if not in_graph and node not in prims and not any(node in v for v in prims.values()):
        near = [n for n in list(adj)[:200] if node.split(".")[0] in n]
        print(f"  '{node}' has no recorded trust edges." + (f" Near: {', '.join(near[:5])}" if near else ""))
        return 1

    def primtag(h):
        p = [c for c in prims if any(h == x for x, *_ in prims[c])]
        return f"   [{', '.join(p)}]" if p else ""

    seen, frontier, hops, out_any = {node}, [node], 0, False
    print(f"  {node}{primtag(node)}")
    while frontier and hops < 6:
        nxt = []
        for a in frontier:
            for b, pred in adj.get(a, []):
                if b not in seen:
                    seen.add(b); nxt.append(b); out_any = True
                    print(f"    {'  '*hops}→ {b}  ({pred}){primtag(b)}")
        frontier = nxt; hops += 1
    if not out_any:
        print("    (no outgoing edges)")

    incoming = [(a, pred) for a, pred in radj.get(node, []) if a not in seen]
    if incoming:
        print("\n  incoming (these point AT the host; reverse reachability, reported separately):")
        for a, pred in sorted(incoming):
            print(f"    ← {a}  ({pred}){primtag(a)}")

    print(f"\n  blast radius (reachable, outgoing): {len(seen)} node(s)"
          + (f" · {len(incoming)} incoming edge(s)" if incoming else ""))
    return 0


def cmd_summary(tdir, adj, edge_count, prims):
    hosts = set(adj) | {b for vs in adj.values() for b, _ in vs}
    print(f"\n# {tdir.name} — target graph  (derived; source of truth stays the files)\n")
    print(f"  hosts with trust edges : {len(hosts)}")
    print(f"  trust edges            : {sum(edge_count.values())}" +
          (f"  ({', '.join(f'{k}×{v}' for k, v in edge_count.items())})" if edge_count else ""))
    print(f"  vuln primitives        : {sum(len(v) for v in prims.values())} "
          f"across {len(prims)} class(es)")
    low = sorted(set(prims) & LOW_SEED_CLASSES)
    if low:
        print(f"  low-sev chain seeds    : {', '.join(low)}")
    # WEAK connected components — traverse edges in BOTH directions, so a lone directed a→b is ONE
    # component (not two one-host components), and the count does not depend on iteration order.
    undirected = defaultdict(set)
    for a, vs in adj.items():
        for b, _ in vs:
            undirected[a].add(b)
            undirected[b].add(a)
    comp, cid = {}, 0
    for start in hosts:
        if start in comp:
            continue
        cid += 1; stack = [start]
        while stack:
            n = stack.pop()
            if n in comp:
                continue
            comp[n] = cid
            for b in undirected.get(n, ()):
                if b not in comp:
                    stack.append(b)
    if cid:
        sizes = defaultdict(int)
        for c in comp.values():
            sizes[c] += 1
        big = sorted(sizes.values(), reverse=True)[:5]
        print(f"  connected components   : {cid}  (largest: {', '.join(map(str, big))} hosts)")
    print("\n  next: --chains for pairings, --linkage <host> for one blast radius, "
          "kb.py chains for host paths.\n")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target")
    ap.add_argument("--chains", action="store_true", help="vuln chains + low-sev seeds to pair")
    ap.add_argument("--linkage", metavar="NODE", help="blast radius reachable from one node")
    if len(sys.argv) == 1 or sys.argv[1] in ("-h", "--help"):
        ap.print_help(); return 0
    args = ap.parse_args()

    tdir = Path(args.target).resolve()
    if not (tdir / "index.md").exists():
        print(f"FAIL — {args.target} is not a target brain", file=sys.stderr); return 2

    prims = load_primitives(tdir)
    if args.chains:
        return cmd_chains(tdir, prims)
    adj, edge_count, _ = load_edges(tdir)
    if args.linkage:
        return cmd_linkage(tdir, args.linkage.strip().lower(), adj, prims)
    if not adj and not prims:
        print("  brain too empty to graph — no observed trust edges and no vuln primitives yet.\n"
              "  Record edges with kb.py add (references / shares-session / shares-backend …) and\n"
              "  derive-properties to seed primitives, then re-run.")
        return 1
    return cmd_summary(tdir, adj, edge_count, prims)


if __name__ == "__main__":
    sys.exit(main())
