#!/bin/sh
# h1-fetch.sh — cache disclosed HackerOne reports for one vuln class.
#
#   usage:  knowledge/tools/h1-fetch.sh <class-slug> <UPSTREAM_FILE.md> [--limit N]
#   e.g.    knowledge/tools/h1-fetch.sh sql-injection TOPSQLI.md
#
# Ids come from github.com/reddelexc/hackerone-reports (docs/tops_by_bug_type/).
# Bodies come from hackerone.com/reports/<id> with Basic auth + Accept: application/json —
# the only route that returns `vulnerability_information` (see knowledge/reports/README.md).
#
# Resumable: an already-cached id is skipped. Re-run freely.
# Fail loud: `visibility: full` with a 0-char body is a FAILURE, not an empty result.
#   404 -> recorded once as `gone`, never retried in a loop.
#
# Creds: config.json -> api_keys.hackerone.{username,token}, via tools/config.py. Never echoed.
# set -u, not set -e: one bad report must not abort the run.
set -u

CLASS=""; UPSTREAM=""; LIMIT=0
for a in "$@"; do
  case "$a" in
    --limit=*) LIMIT=${a#--limit=} ;;
    --limit)   ;;
    [0-9]*)    [ "$LIMIT" = "0" ] && LIMIT="$a" ;;
    *.md)      UPSTREAM="$a" ;;
    -*)        echo "FAIL: unknown flag $a" >&2; exit 2 ;;
    *)         [ -z "$CLASS" ] && CLASS="$a" ;;
  esac
done
[ -n "$CLASS" ] && [ -n "$UPSTREAM" ] || { echo "usage: $0 <class-slug> <UPSTREAM_FILE.md> [--limit N]" >&2; exit 2; }

# --- preflight -------------------------------------------------------------
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
# config.json is the single source of truth; env vars still win (CI, one-off runs).
if [ -z "${H1_USER:-}" ] || [ -z "${H1_TOKEN:-}" ]; then
  eval "$("$ROOT/tools/config.py" env 2>/dev/null)" || true
fi
[ -n "${H1_USER:-}" ] && [ -n "${H1_TOKEN:-}" ] || {
  echo "FAIL: HackerOne credentials not set." >&2
  echo "      Set api_keys.hackerone.{username,token} in config.json" >&2
  echo "      (cp config.example.json config.json), or export H1_USER / H1_TOKEN." >&2
  echo "      Check with: tools/config.py check" >&2
  exit 2; }
command -v python3 >/dev/null || { echo "FAIL: python3 required" >&2; exit 2; }

OUT="$ROOT/knowledge/reports/$CLASS"
IDX="$ROOT/knowledge/reports/index.tsv"
mkdir -p "$OUT" || exit 2
[ -f "$IDX" ] || printf 'class\treport_id\tvisibility\tbody_chars\tsummary_chars\tcwe\tseverity\tprogram\tdisclosed_at\ttitle\n' > "$IDX"

SRC="https://raw.githubusercontent.com/reddelexc/hackerone-reports/master/docs/tops_by_bug_type/$UPSTREAM"
IDS="$OUT/.ids.txt"
curl -sS --max-time 30 "$SRC" -o "$OUT/.upstream.md" || { echo "FAIL: cannot fetch $SRC" >&2; exit 2; }
[ -s "$OUT/.upstream.md" ] || { echo "FAIL: upstream list empty: $SRC" >&2; exit 2; }
grep -o 'reports/[0-9]\+' "$OUT/.upstream.md" | cut -d/ -f2 | awk '!seen[$0]++' > "$IDS"
n_ids=$(awk 'END{print NR}' "$IDS")
[ "$n_ids" -gt 0 ] || { echo "FAIL: no report ids parsed from $UPSTREAM" >&2; exit 2; }
[ "$LIMIT" != "0" ] && { head -n "$LIMIT" "$IDS" > "$IDS.tmp" && mv "$IDS.tmp" "$IDS"; n_ids=$(awk 'END{print NR}' "$IDS"); }

echo "class=$CLASS  ids=$n_ids  -> $OUT"

# --- fetch -----------------------------------------------------------------
full=0; nocontent=0; gone=0; cached=0; failed=0; i=0
while IFS= read -r id; do
  [ -n "$id" ] || continue
  i=$((i + 1))
  f="$OUT/$id.json"
  if [ -s "$f" ]; then cached=$((cached + 1)); continue; fi

  code=$(curl -sS --max-time 30 -u "$H1_USER:$H1_TOKEN" -H 'Accept: application/json' \
         -o "$f.part" -w '%{http_code}' "https://hackerone.com/reports/$id" 2>/dev/null)

  case "$code" in
    200)
      if python3 -c "import json,sys; json.load(open('$f.part'))" 2>/dev/null; then
        mv "$f.part" "$f"
        line=$(python3 - "$f" "$CLASS" <<'PY'
import json,sys
f,cls=sys.argv[1],sys.argv[2]
d=json.load(open(f))
vi=d.get('vulnerability_information') or ''
sm=''.join((s.get('content') or '') for s in (d.get('summaries') or []) if isinstance(s,dict))
w=(d.get('weakness') or {}).get('name') or ''
team=((d.get('team') or {}).get('handle')) or ''
t=(d.get('title') or '').replace('\t',' ').replace('\n',' ')
print('\t'.join([cls,str(d.get('id')),str(d.get('visibility')),str(len(vi)),str(len(sm)),w,
                 str(d.get('severity_rating')),team,str(d.get('disclosed_at'))[:10],t]))
PY
        )
        printf '%s\n' "$line" >> "$IDX"
        vis=$(printf '%s' "$line" | cut -f3); bc=$(printf '%s' "$line" | cut -f4)
        case "$vis" in
          full) if [ "$bc" -eq 0 ]; then echo "  ASSERT-FAIL $id: visibility=full but body 0 chars"; failed=$((failed+1));
                else full=$((full+1)); fi ;;
          *)    nocontent=$((nocontent+1)) ;;
        esac
      else
        echo "  FAIL $id: 200 but not JSON"; rm -f "$f.part"; failed=$((failed+1))
      fi ;;
    404) gone=$((gone+1)); rm -f "$f.part"
         printf '%s\t%s\tgone\t0\t0\t\t\t\t\t\n' "$CLASS" "$id" >> "$IDX" ;;
    429) echo "  RATE-LIMITED at id $id (HTTP 429) — stopping; re-run to resume"; rm -f "$f.part"; break ;;
    *)   echo "  FAIL $id: HTTP $code"; rm -f "$f.part"; failed=$((failed+1)) ;;
  esac
  [ $((i % 25)) -eq 0 ] && echo "  ...$i/$n_ids"
done < "$IDS"

# --- assert ----------------------------------------------------------------
have=$(find "$OUT" -maxdepth 1 -name '*.json' | awk 'END{print NR}')
echo "done: full=$full no-content=$nocontent gone=$gone cached=$cached failed=$failed | cached files=$have"
[ "$have" -eq 0 ] && { echo "FAILURE: nothing cached for $CLASS" >&2; exit 1; }
[ "$failed" -gt 0 ] && echo "NOTE: $failed fetch failures — re-run to retry them (cached ids are skipped)."
exit 0
