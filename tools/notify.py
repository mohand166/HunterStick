#!/usr/bin/env python3
"""Fire-and-forget event notifications to any webhook channel the hunter configures.

    tools/notify.py send targets/acme --event monitor-delta --title "3 new subdomains" [--body ...]
    tools/notify.py test                          # sends a test event through every channel
    tools/notify.py spool                         # retry events that failed earlier

Design rules
------------
* **Any channel, one sender.** Discord, Slack, Teams, ntfy, Gotify and Telegram bots are all
  plain HTTP POSTs, so a channel is just `{name, url, headers?, template?}` in config.json under
  `notify.channels`. No per-vendor adapters to drift.
* **A dead webhook must never break a finished run.** Sending is best-effort: a network error or
  non-2xx response spools the event to `.notify-spool.jsonl` (bounded, last 50) and the caller
  continues. The spool is retried on the next send. The CLI therefore exits 0 on a *delivery*
  failure and says so; only a malformed config exits 2.
* **Redaction by default.** The payload is built from structured fields the caller passes —
  target slug, event kind, one-line title, short body. Never a command line (it can carry the
  attribution header), never an artifact's contents. With `notify.strict: true` even the target
  name is replaced, because a webhook is a third party.
* **Secrets stay secret.** Channel URLs contain tokens (a Discord webhook URL *is* a
  credential). They are never printed; `config.py check` shows only that `notify.channels` is
  SET.

Default body carries both `text` and `content` keys (Slack/Teams/generic read `text`, Discord
reads `content`) plus the structured fields, so a bare URL works for the common channels without
a template. A per-channel `template` object overrides the body entirely — values are rendered
with `{event}`, `{target}`, `{title}`, `{body}`, `{ts}` placeholders.

Exit: 0 sent (or spooled / no channels configured) · 2 malformed notify config.
"""
import argparse
import datetime as _dt
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPOOL = ROOT / ".notify-spool.jsonl"
SPOOL_MAX = 50
TIMEOUT_S = 10
EVENTS = ("monitor-delta", "monitor-quarantined", "run-failed", "run-completed",
          "tech-watch", "runbook-digest", "test")


def _now():
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_channels(channels_file=None):
    """(channels, strict, problem) — channels is None when there is a config problem.

    A standalone channels file (used on the VPS by the monitor cron job, which has no
    config.json) wins over the local config."""
    strict = False
    if channels_file:
        try:
            data = json.loads(Path(channels_file).read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as e:
            return None, False, f"cannot read channels file: {e}"
        strict = bool(data.get("strict"))
    else:
        try:
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            import config
            flat = config.load()
        except SystemExit:
            return None, False, "config.json is malformed — fix it before notifications can work"
        data = {"channels": flat.get("notify.channels")}
        strict = bool(flat.get("notify.strict"))
    channels = data.get("channels") or []
    if not isinstance(channels, list) or \
            not all(isinstance(c, dict) and isinstance(c.get("url"), str) and c.get("url")
                    for c in channels):
        return None, False, ("notify.channels must be a list of objects each with a non-empty "
                             "'url' (see config.example.json)")
    return channels, strict, None


def _render(value, fields):
    """Replace {event}/{target}/{title}/{body}/{ts} in a string; unknown keys stay literal."""
    if not isinstance(value, str):
        return value
    out, i = [], 0
    while True:
        j, k = value.find("{", i), -1
        if j < 0:
            out.append(value[i:])
            return "".join(out)
        out.append(value[i:j])
        k = value.find("}", j)
        if k < 0:
            out.append(value[j:])
            return "".join(out)
        key = value[j + 1:k]
        out.append(str(fields.get(key, value[j:k + 1])))
        i = k + 1


def build_payload(channel, fields):
    template = channel.get("template")
    if isinstance(template, dict) and template:
        return {k: _render(v, fields) for k, v in template.items()}
    line = f"{fields['title']}"
    if fields.get("body"):
        line += f"\n{fields['body']}"
    return {"event": fields["event"], "target": fields.get("target", ""),
            "title": fields["title"], "body": fields.get("body", ""),
            "text": line, "content": line, "ts": fields["ts"]}


def _post(channel, payload):
    headers = {"Content-Type": "application/json"}
    if isinstance(channel.get("headers"), dict):
        headers.update({str(k): str(v) for k, v in channel["headers"].items()})
    req = urllib.request.Request(
        channel["url"], data=json.dumps(payload).encode("utf-8"), headers=headers,
        method=str(channel.get("method", "POST")).upper())
    from netlib import ssl_context
    with urllib.request.urlopen(req, timeout=TIMEOUT_S, context=ssl_context()) as resp:
        return 200 <= resp.status < 300


def _spool_append(entry):
    try:
        rows = []
        if SPOOL.exists():
            rows = [json.loads(l) for l in
                    SPOOL.read_text(encoding="utf-8-sig").splitlines() if l.strip()]
        rows.append(entry)
        SPOOL.write_text("\n".join(json.dumps(r) for r in rows[-SPOOL_MAX:]) + "\n",
                         encoding="utf-8")
    except OSError:
        pass  # the spool is best-effort too; losing an event beats breaking the run


def _flush_spool(channels):
    """Retry spooled events oldest-first. Delivered rows are dropped; failures re-spooled."""
    if not SPOOL.exists():
        return 0
    try:
        rows = [json.loads(l) for l in
                SPOOL.read_text(encoding="utf-8-sig").splitlines() if l.strip()]
    except (OSError, json.JSONDecodeError):
        return 0
    SPOOL.unlink(missing_ok=True)
    sent = 0
    for entry in rows:
        if _try_send(channels, entry):
            sent += 1
        else:
            _spool_append(entry)
    return sent


def _try_send(channels, entry):
    ok = False
    for channel in channels:
        try:
            ok = _post(channel, build_payload(channel, entry)) or ok
        except (urllib.error.URLError, OSError, ValueError):
            continue
    return ok


def send(event, title, body="", target=None, channels_file=None):
    """Send one event to every configured channel. Returns (delivered_channels, spooled, note).

    Never raises: a notification is an afterthought to a finished run, not a gate on it."""
    channels, strict, problem = load_channels(channels_file)
    if channels is None:
        return 0, 0, problem
    if not channels:
        return 0, 0, "no channels configured — set notify.channels in config.json"
    fields = {"event": event, "title": title, "body": body, "ts": _now(),
              "target": "(redacted)" if strict else (target or "")}
    if _try_send(channels, fields):
        _flush_spool(channels)
        return len(channels), 0, None
    _spool_append(fields)
    return 0, 1, "delivery failed — event spooled for retry (tools/notify.py spool)"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")
    s = sub.add_parser("send", help="send one event through every configured channel")
    s.add_argument("target", nargs="?", default=None,
                   help="target slug for the payload (redacted when notify.strict is set)")
    s.add_argument("--event", required=True, choices=EVENTS, help="event kind")
    s.add_argument("--title", required=True, help="one line the hunter reads on their phone")
    s.add_argument("--body", default="", help="optional short detail — never secrets or commands")
    s.add_argument("--channels-file", default=None,
                   help="standalone channels JSON (used on the VPS by the monitor job)")
    t = sub.add_parser("test", help="send a test event to verify a channel end to end")
    t.add_argument("target", nargs="?", default=None)
    t.add_argument("--target", dest="target_flag", default=None,
                   help="same as the positional, for readability in docs")
    t.add_argument("--channels-file", default=None)
    sub.add_parser("spool", help="retry events that failed delivery earlier")
    args = ap.parse_args()
    if not args.cmd:
        ap.print_help()
        return 2

    if args.cmd == "spool":
        channels, _strict, problem = load_channels()
        if channels is None:
            print(f"FAIL — {problem}", file=sys.stderr)
            return 2
        n = _flush_spool(channels)
        print(f"{n} spooled event(s) delivered" if n else "spool empty or still undeliverable")
        return 0

    if args.cmd == "test":
        target = args.target or args.target_flag
        sent, spooled, note = send("test", "HunterStick notification test",
                                   "If you can read this, the channel works.", target,
                                   args.channels_file)
    else:
        sent, spooled, note = send(args.event, args.title, args.body, args.target,
                                   args.channels_file)
    if note and sent == 0 and spooled == 0:
        print(f"note — {note}")
        return 0 if "no channels" in note else 2
    print(f"sent to {sent} channel(s)" + (f" · {spooled} spooled" if spooled else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
