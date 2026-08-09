#!/usr/bin/env python3
"""The one scope parser. Every tool that can reach the network imports this.

    from scopelib import parse_scope, matches, apex_of

There used to be three near-identical copies of this regex — in `import-http.py`, `monitor.py`
and `sweep.py` — and they disagreed with the target template, which writes the hunter's statement
under `## Supplied scope statement — verbatim`. None of the three recognised that heading, so a
normally initialized target failed every one of them with "no in-scope domains". Three copies of a
rule is how a rule stops being true; there is one now.

What it reads, in order of preference
-------------------------------------
1. `### In scope` / `### Out of scope` under **`## Mechanical allowlist`** — the derived, machine
   readable list. This is what tools should be matching against.
2. Any other `## In scope` / `## Out of scope` heading, for a hunter who wrote the file by hand.
3. Nothing else. The verbatim statement is deliberately **not** parsed for hostnames: it is prose,
   it may name a company rather than a domain, and silently guessing hostnames out of a sentence is
   exactly the inference this workspace forbids.

The verbatim statement stays the authority. The mechanical list is a derived convenience, and when
the two disagree the verbatim one wins — which is why `parse_scope` reports whether the mechanical
section is missing or still a placeholder instead of quietly returning an empty allowlist.
"""
import ipaddress
import re
from functools import lru_cache
from pathlib import Path

FILE_EXT = re.compile(r"\.(md|txt|json|ya?ml|html?|sh|py|jsonl|tsv|csv|log|png|svg)$", re.I)

# Two-label public suffixes, so `acme.com.tw` collapses to itself and not to `com.tw`.
# A pragmatic list, not the Public Suffix List — wrong only in the direction of keeping a longer
# name, which is the safe direction.
TWO_LABEL_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "co.jp", "ne.jp", "or.jp", "com.au",
    "net.au", "org.au", "com.br", "com.cn", "com.tw", "com.hk", "com.sg", "com.mx",
    "co.in", "co.nz", "co.za", "co.kr", "com.tr", "com.ar", "com.my", "co.il", "com.pl",
    "com.ua", "com.vn", "com.ph", "co.th", "com.sa", "com.eg", "com.co", "com.pe",
}

# Program platforms appear in every scope file as the source URL. Enumerating them would mean
# enumerating another company's estate.
PLATFORMS = {
    "hackerone.com", "hackerone.net", "intigriti.com", "intigriti.me", "bugcrowd.com",
    "yeswehack.com", "immunefi.com", "synack.com", "openbugbounty.org", "huntr.dev",
    "github.com", "gitlab.com", "google.com", "cve.org", "mitre.org", "nvd.nist.gov",
}

PLACEHOLDER = re.compile(r"^\s*[-*]?\s*(<[^>]*>|TBD\b|none supplied|—|-)\s*$", re.I)
DOMAIN = re.compile(r"(?<![\w.-])(\*\.)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?![\w-])", re.I)
# phase-routing promises IP/CIDR entry, so the parser has to understand them or that route dies
# at the scope gate. Matched by SUBNET CONTAINMENT in matches(); a bare IP is a /32.
CIDR = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?)(?![\w.])")


# Invisible and near-invisible characters that make a heading or a row stop being recognised.
# A BOM pasted mid-file, an NBSP from a rich-text copy, a zero-width space from a web page —
# each one silently turned `### Out of scope` into ordinary prose, which dropped every exclusion
# under it and QUIETLY WIDENED SCOPE. That is the worst failure this file can have, so the
# normalisation happens once, here, before anything is parsed.
INVISIBLE = str.maketrans({"\ufeff": "", "\u200b": "", "\u200c": "", "\u200d": "",
                           "\u00a0": " ", "\u202f": " ", "\u2007": " ", "\u2060": ""})


def clean(text):
    return (text or "").translate(INVISIBLE)



def apex_of(host):
    """Collapse a host to its registrable apex: legal.acme.com -> acme.com."""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in TWO_LABEL_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _sections(text):
    """{heading-lowercase: [lines]} for every ## / ### heading.

    Tolerates up to three leading spaces (markdown allows them) and strips invisible characters
    first. A heading that fails to parse does not error — it silently becomes prose, taking every
    entry under it with it.
    """
    out, cur = {}, "_preamble"
    for line in clean(text).splitlines():
        m = re.match(r"^ {0,3}#{2,}\s*(.+?)\s*$", line)
        if m:
            cur = m.group(1).lower()
            out.setdefault(cur, [])
            continue
        out.setdefault(cur, []).append(line)
    return out


def _patterns(lines):
    """[(is_wildcard, domain)] exactly as written. Nothing is ever widened.

    This function used to collapse inclusions to their registrable apex, which was a scope-widening
    bug: `app.acme.com` became `acme.com` (authorising the whole estate from one host) and
    `*.dev.acme.com` became `*.acme.com` (authorising every unrelated sibling). Deriving an
    enumeration root and deciding whether a host is authorised are **different operations** —
    `enumeration_roots()` does the former, and it is the only place a domain is ever shortened.
    """
    out = []
    for line in lines:
        if PLACEHOLDER.match(line):
            continue
        for wild, dom in DOMAIN.findall(line):
            dom = dom.lower().rstrip(".")
            if FILE_EXT.search(dom):
                continue
            out.append((wild == "*.", dom))
        for cidr in CIDR.findall(line):
            out.append((False, cidr))
    return out


def prose_exclusions(text):
    """Out-of-scope entries with no hostname in them — a job cannot enforce these.

    "Sold / shut down: Flickr, Tumblr, MapQuest" is a real exclusion with nothing to match on.
    Naming them is the difference between a filter that is incomplete and one that is silently
    incomplete.
    """
    out = []
    for head, lines in _sections(text).items():
        if not re.search(r"out[\s-]*of[\s-]*scope|excluded|not eligible", head):
            continue
        for line in lines:
            s = line.strip(" -*\t")
            if not s or s.startswith(("|", ">", "<", "```")):
                continue
            without = DOMAIN.sub("", s)
            if len(re.sub(r"[^A-Za-z]", "", without)) >= 12:
                out.append(s[:110])
    return out


def parse_scope(tdir):
    """Read scope.md. Returns a dict — never raises, never guesses.

    keys: in_scope, out_of_scope  -> [(is_wildcard, domain)]
          prose                   -> exclusions no tool can enforce
          state                   -> "ok" | "no-file" | "no-mechanical-section" | "placeholder"
          detail                  -> a sentence naming what to do about it
    """
    f = Path(tdir) / "scope.md"
    if not f.exists():
        return {"in_scope": [], "out_of_scope": [], "prose": [], "state": "no-file",
                "detail": f"{f} does not exist. Nothing can be reconciled against it."}

    text = clean(f.read_text(encoding="utf-8-sig", errors="replace"))
    secs = _sections(text)
    inc, exc = [], []
    for head, lines in secs.items():
        if re.search(r"out[\s-]*of[\s-]*scope|excluded|not eligible", head):
            exc += _patterns(lines)
        elif re.search(r"in[\s-]*scope", head):
            inc += _patterns(lines)

    # de-dup, drop platforms, and never let a host-level exclusion cancel a whole apex
    inc = sorted({(w, d) for w, d in inc if d not in PLATFORMS})
    exc = sorted(set(exc))
    inc = [(w, d) for w, d in inc if (w, d) not in exc]

    res = {"in_scope": inc, "out_of_scope": exc, "prose": prose_exclusions(text),
           "state": "ok", "detail": ""}
    if inc:
        return res

    has_section = any(re.search(r"in[\s-]*scope", h) for h in secs)
    if not has_section:
        res["state"] = "no-mechanical-section"
        res["detail"] = (
            "scope.md has no `In scope` section. The hunter's statement is stored verbatim and is\n"
            "       still the authority, but tools need a derived list to match against. Add:\n\n"
            "         ## Mechanical allowlist\n         ### In scope\n         - *.example.com\n"
            "         ### Out of scope\n         - admin.example.com\n\n"
            "       Deriving it is `init-target` step 4; it is not guessed from prose on purpose.")
    else:
        res["state"] = "placeholder"
        res["detail"] = ("scope.md has an `In scope` section but every entry is still a "
                         "placeholder. Fill it from the verbatim statement before any tool runs.")
    return res


@lru_cache(maxsize=4096)
def _network(entry):
    """An allowlist entry as an ip_network, or None when it is a domain.

    `strict=False` so `69.147.92.11` becomes `69.147.92.11/32` — a bare IP and a /32 are the
    same authorisation, and callers should not have to know which form was written.
    """
    try:
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return None


@lru_cache(maxsize=8192)
def _address(host):
    """A host as an ip_address, or None when it is a name. Cached — `matches()` runs per host
    over lists of tens of thousands."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def matches(host, patterns):
    """Does `host` match any pattern? Domains by name, IPs by SUBNET CONTAINMENT.

    Containment is the whole point of allowing a CIDR in scope.md. Before this, entries were
    compared as strings: `98.139.0.0/16` authorised the literal text `98.139.0.0/16` and **not
    a single address inside it**, so the IP/CIDR route `phase-routing` promises died silently at
    the scope gate — every bare IP was dropped as "not in scope.md", and a web service reachable
    only by IP could never be probed.

    It applies to exclusions too: an excluded CIDR must exclude the addresses within it, or the
    exclusion is decorative.
    """
    host = (host or "").lower()
    host_ip = _address(host) if host and host[0].isdigit() else None
    for w, d in patterns:
        if host == d or (w and host.endswith("." + d)):
            return True
        if host_ip is not None:
            net = _network(d)
            if net is not None and host_ip.version == net.version and host_ip in net:
                return True
    return False


def in_scope(host, parsed):
    """True only if the host matches an inclusion AND no exclusion. Ambiguous is out."""
    return matches(host, parsed["in_scope"]) and not matches(host, parsed["out_of_scope"])


def enumeration_roots(parsed):
    """Domains it is authorised to run `subfinder -d` against — the ONLY widening in this module.

    A **wildcard** entry authorises everything beneath it, so `*.dev.acme.com` legitimately yields
    the enumeration root `dev.acme.com`. It does **not** yield `acme.com`: the wildcard covers the
    subtree it names, not the subtree's parent.

    An **exact host** authorises only itself, so it yields **no** root at all. Enumerating
    `acme.com` because `app.acme.com` was in scope is precisely the widening this separation
    exists to prevent — the host is still testable, it is just not an enumeration seed.

    Returns (roots, skipped) so a caller can say what it is NOT enumerating rather than silently
    dropping it.
    """
    roots, skipped = [], []
    for wild, dom in parsed["in_scope"]:
        if CIDR.fullmatch(dom):
            skipped.append((dom, "an IP/CIDR is not a DNS enumeration root — use "
                                 "`dns-analysis` / `live-host-validation`"))
        elif wild:
            roots.append(dom)
        else:
            skipped.append((dom, "exact host — in scope for testing, but not an enumeration seed"))
    return sorted(set(roots)), skipped


def authorises(root, parsed):
    """Is an explicitly supplied enumeration root actually covered by scope?

    `monitor.py --apex` used to accept any string, which let a hunter schedule twice-daily
    enumeration of a domain scope.md never authorised.
    """
    root = (root or "").lower()
    for wild, dom in parsed["in_scope"]:
        if root == dom and wild:
            return True                      # exactly the wildcard root
        if wild and root.endswith("." + dom):
            return True                      # a narrower root under an authorised wildcard
    return False


def require_scope(tdir, die):
    """parse_scope, or call die() with a message that says what to fix."""
    p = parse_scope(tdir)
    if p["state"] != "ok":
        die(f"{p['detail']}")
    return p
