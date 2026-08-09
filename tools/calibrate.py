#!/usr/bin/env python3
"""Decide whether discovery output from a host can be trusted — the calibration gate, performed.

    tools/calibrate.py --host app.acme.com --header 'X-Bug-Bounty: handle'
    tools/calibrate.py --list hosts.txt --out raw/calibration/ --rate 5

Why this exists
---------------
`preflight.py` gates every phase on calibration, `kb.py` stores the verdict, and
`adaptive-tooling.md` describes the method — but nothing *performed* it. So the gate read
`UNRECORDED` on every phase of a whole engagement: a rule that depends on someone remembering to
do it by hand is a rule that does not happen.

**An uncalibrated tool is a random-number generator with a progress bar.** If a host answers `200`
for every path, a wordlist run "finds" every entry, `attack-surface-prioritization` ranks that
fiction, and someone tests
paths that never existed.

What it does
------------
Requests the baseline (`/`) and several paths that **cannot** exist, then compares status, body
length, word count and redirect target.

  clean    — improbable paths are clearly distinguishable from the baseline. Discovery here is
             trustworthy, and the discriminator is reported so a fuzzer can be configured for it.
  broken   — every improbable path looks like a real page (soft-404 / catch-all redirect).
             Discovery counts from this host are fiction until a discriminator is found.
  unknown  — could not be established: timeouts, connection failures, or the host is not HTTP.
             NOT a pass. `unknown` and `clean` are different answers.

Three improbable paths, not one, because a single unlucky collision with a real path would
condemn a host that is fine.

Sends real HTTP to the `--host` you name. It does **not** consult `scope.md` — the human chose the
host, and this workspace does not gate a human-named action on scope. Pass `--header` for program
attribution; most programs require it, so supplying it is strongly recommended, but its absence is
not a refusal here. Exit: 0 all clean · 1 at least one broken/unknown · 2 the check could not run.
"""
import argparse
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# Fixed, not random, so a run is reproducible and a future reader can re-issue the exact request.
PROBES = ("zzq7x-ctrl-a-does-not-exist", "q9m2w-ctrl-b-does-not-exist",
          "vk3p8-ctrl-c-does-not-exist/nested")
LEN_TOLERANCE = 0.05          # bodies within 5% count as "the same page"


def die(msg):
    print(f"FAIL — {msg}", file=sys.stderr)
    sys.exit(2)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is a signal, not something to follow — a catch-all 301 to /home is the quirk."""
    def redirect_request(self, *a, **k):
        return None


def fetch(url, header, timeout):
    """(status, length, words, location) or None when the request could not complete."""
    req = urllib.request.Request(url, method="GET")
    if header and ":" in header:
        k, v = header.split(":", 1)
        req.add_header(k.strip(), v.strip())
    req.add_header("User-Agent", "HunterStick-calibrate/1.0")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE          # a bad cert is not a calibration answer
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    try:
        with opener.open(req, timeout=timeout) as r:
            body = r.read(200_000)
            return (r.status, len(body), len(body.split()), r.headers.get("Location", ""))
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read(200_000)
        except Exception:                                        # noqa: BLE001
            pass
        return (e.code, len(body), len(body.split()), e.headers.get("Location", "") if e.headers else "")
    except Exception:                                            # noqa: BLE001 - any failure is 'unknown'
        return None


def verdict(baseline, probes):
    """(state, discriminator) from the baseline and the improbable-path responses.

    Pure: no network, so the decision is testable.
    """
    if baseline is None or not any(p is not None for p in probes):
        return "unknown", "baseline or probes did not complete"
    live = [p for p in probes if p is not None]
    if len(live) < 2:
        return "unknown", "fewer than two probes completed"

    b_status, b_len, b_words, _ = baseline
    statuses = {p[0] for p in live}

    # Any 4xx/5xx on an improbable path is real discrimination.
    if all(p[0] >= 400 for p in live):
        return "clean", f"status ({b_status} vs {sorted(statuses)[0]})"

    # Every improbable path answers like the real page -> soft-404 / catch-all.
    if all(p[0] == b_status for p in live):
        lens = [p[1] for p in live]
        spread = (max(lens) - min(lens)) / max(1, max(lens))
        near_baseline = all(abs(p[1] - b_len) <= b_len * LEN_TOLERANCE for p in live)
        if near_baseline:
            return "broken", (f"status {b_status} and body ~{b_len}B for paths that cannot exist "
                              f"— nothing separates hit from miss")
        if spread <= LEN_TOLERANCE:
            return "broken", (f"status {b_status}, catch-all body ~{lens[0]}B (baseline {b_len}B) "
                              f"— filter on length, not status")
        return "clean", f"same status {b_status}, but body length varies (baseline {b_len}B)"

    locs = {p[3] for p in live if p[3]}
    if len(locs) == 1 and all(300 <= p[0] < 400 for p in live):
        return "broken", f"catch-all redirect to {locs.pop()} for every unknown path"
    return "clean", f"statuses differ (baseline {b_status}, probes {sorted(statuses)})"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", action="append", default=[])
    ap.add_argument("--list", type=Path, help="file of hosts, one per line")
    ap.add_argument("--scheme", default="https", choices=("https", "http"))
    ap.add_argument("--header", help="attribution header, e.g. 'X-Bug-Bounty: handle'")
    ap.add_argument("--rate", type=float, default=2.0, help="requests per second (default 2)")
    ap.add_argument("--timeout", type=int, default=12)
    ap.add_argument("--out", type=Path, help="directory for per-host evidence JSON")
    ap.add_argument("--allow-no-header", action="store_true",
                    help="probe without an attribution header; say why in the run record")
    args = ap.parse_args()

    hosts = list(args.host)
    if args.list:
        if not args.list.is_file():
            die(f"{args.list} does not exist")
        hosts += [l.strip() for l in args.list.read_text().splitlines() if l.strip()]
    hosts = [h.lower() for h in dict.fromkeys(hosts)]
    if not hosts:
        die("no hosts given — an empty calibration is not a pass")
    if not args.header and not args.allow_no_header:
        die("no --header. Programs require attribution on every request; pass it, or "
            "--allow-no-header and record why.")
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)

    delay = 1.0 / args.rate if args.rate > 0 else 0
    results, worst = [], 0
    for h in hosts:
        base_url = f"{args.scheme}://{h}/"
        baseline = fetch(base_url, args.header, args.timeout)
        time.sleep(delay)
        probes = []
        for p in PROBES:
            probes.append(fetch(f"{args.scheme}://{h}/{p}", args.header, args.timeout))
            time.sleep(delay)
        state, why = verdict(baseline, probes)
        results.append((h, state, why))
        worst = max(worst, {"clean": 0, "broken": 1, "unknown": 1}[state])
        mark = {"clean": "ok     ", "broken": "BROKEN ", "unknown": "unknown"}[state]
        print(f"  {mark} {h:<44} {why}")
        if args.out:
            (args.out / f"{h}.json").write_text(json.dumps({
                "host": h, "scheme": args.scheme, "state": state, "discriminator": why,
                "baseline": baseline, "probe_paths": list(PROBES), "probes": probes,
            }, indent=2), encoding="utf-8")

    counts = {}
    for _, s, _ in results:
        counts[s] = counts.get(s, 0) + 1
    print("\n  " + " · ".join(f"{v} {k}" for k, v in sorted(counts.items())))
    if args.out:
        print(f"  evidence: {args.out}")
    print("\n  Record each verdict so the gate can see it:")
    for h, s, why in results:
        ev = f" --evidence {args.out}/{h}.json" if args.out else ""
        print(f"    tools/kb.py add <target> --subject {h} --predicate calibration "
              f"--object {s} --confidence observed --source calibrate{ev}")
    if "broken" in counts:
        print("\n  BROKEN means discovery counts from that host are fiction until you find a\n"
              "  discriminator. See playbooks/system/calibration-quirks.md before re-deriving one.")
    return 1 if worst else 0


if __name__ == "__main__":
    sys.exit(main())
