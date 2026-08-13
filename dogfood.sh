#!/usr/bin/env bash
# dogfood.sh — daily-driver commands for the receipts dogfood.
# The experiment itself (the bet, the decision date, the journal) is DOGFOOD.md.
#
#   ./dogfood.sh              status: verdict for every session chain
#   ./dogfood.sh report [LOG] timeline of the newest (or named) chain
#   ./dogfood.sh anchor       anchor every chain head to Bitcoin
#   ./dogfood.sh upgrade      complete pending anchor proofs
#   ./dogfood.sh drill        tamper fire drill on a scratch chain
#   ./dogfood.sh note "..."   append a line to the DOGFOOD.md journal

set -euo pipefail
cd "$(dirname "$0")"
R() { python3 receipts.py "$@"; }
DIR=receipts

chains() {
  local log
  for log in "$DIR"/*.jsonl; do
    [ -e "$log" ] || continue
    case "$log" in *.anchors.jsonl) continue ;; esac
    echo "$log"
  done
}

newest_chain() { chains | xargs -r ls -t 2>/dev/null | head -1; }

cmd=${1:-status}
[ $# -gt 0 ] && shift

case "$cmd" in

  status)
    found=0
    while IFS= read -r log; do
      [ -n "$log" ] || continue
      found=1
      entries=$(wc -l < "$log" | tr -d ' ')
      code=0
      out=$(R verify --log "$log" --anchors 2>&1) || code=$?
      verdict=$(printf '%s\n' "$out" | tail -1)
      printf '%-48s %4s entries  %s\n' "$log" "$entries" "$verdict"
      if [ "$code" -ne 0 ]; then
        printf '  !! exit %s — full detail: python3 receipts.py verify --log %s --anchors\n' \
          "$code" "$log"
      fi
    done < <(chains)
    if [ "$found" -eq 0 ]; then
      echo "no session chains in $DIR/ yet — work a Claude Code session in this repo first"
    fi
    ;;

  report)
    log=${1:-$(newest_chain)}
    if [ -z "$log" ]; then
      echo "no session chains in $DIR/ yet" >&2
      exit 1
    fi
    R report --log "$log"
    echo
    R verify --log "$log" --anchors || true
    ;;

  anchor)
    while IFS= read -r log; do
      [ -n "$log" ] || continue
      R anchor --log "$log" || true
    done < <(chains)
    ;;

  upgrade)
    while IFS= read -r log; do
      [ -n "$log" ] || continue
      [ -e "$log.anchors.jsonl" ] || continue
      R anchor --upgrade --log "$log" || true
    done < <(chains)
    ;;

  drill)
    # The fire drill: attack a scratch chain the way the writer would, and
    # confirm the alarm sounds. A tamper-evidence tool that has never caught
    # tampering in the field is untested in the way that matters.
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    log="$tmp/drill.jsonl"
    R init --log "$log" > /dev/null
    for action in "step one" "the incriminating step" "step three"; do
      R log --log "$log" --actor drill --action "$action" > /dev/null
    done
    head=$(R head --log "$log")
    pass=0 fail=0
    check() {  # check <name> <expected-exit> <actual-exit>
      if [ "$2" -eq "$3" ]; then
        echo "PASS  $1"; pass=$((pass + 1))
      else
        echo "FAIL  $1 (expected exit $2, got $3)"; fail=$((fail + 1))
      fi
    }

    cp "$log" "$tmp/edited.jsonl"
    python3 - "$tmp/edited.jsonl" <<'PY'
import json, sys
path = sys.argv[1]
lines = open(path, encoding="utf-8").read().splitlines()
entry = json.loads(lines[2])
entry["action"] = "the incriminating step (rewritten)"
lines[2] = json.dumps(entry)
open(path, "w", encoding="utf-8").write("".join(l + "\n" for l in lines))
PY
    code=0; R verify --log "$tmp/edited.jsonl" > /dev/null 2>&1 || code=$?
    check "edited entry is caught (BROKEN)" 1 "$code"

    cp "$log" "$tmp/deleted.jsonl"
    python3 - "$tmp/deleted.jsonl" <<'PY'
import sys
path = sys.argv[1]
lines = open(path, encoding="utf-8").read().splitlines()
del lines[2]
open(path, "w", encoding="utf-8").write("".join(l + "\n" for l in lines))
PY
    code=0; R verify --log "$tmp/deleted.jsonl" > /dev/null 2>&1 || code=$?
    check "deleted entry is caught (BROKEN)" 1 "$code"

    # The adversary's best move: drop an entry and recompute every hash so
    # the chain is internally consistent again (ADR-0002).
    cp "$log" "$tmp/regen.jsonl"
    python3 - "$tmp/regen.jsonl" <<'PY'
import hashlib, json, sys
path = sys.argv[1]
entries = [json.loads(l) for l in open(path, encoding="utf-8")]
del entries[2]
prev = entries[0]["entry_hash"]
for i, entry in enumerate(entries[1:], start=1):
    entry.pop("entry_hash")
    entry["n"] = i
    entry["prev"] = prev
    canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")
    prev = entry["entry_hash"] = hashlib.sha256(canonical).hexdigest()
open(path, "w", encoding="utf-8").write(
    "".join(json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n"
            for e in entries))
PY
    code=0; R verify --log "$tmp/regen.jsonl" > /dev/null 2>&1 || code=$?
    check "regenerated chain fools plain verify (the known gap)" 0 "$code"
    code=0; R verify --log "$tmp/regen.jsonl" --expect-head "$head" > /dev/null 2>&1 || code=$?
    check "regeneration caught against the head record (HEAD-MISMATCH)" 3 "$code"

    echo
    echo "$pass passed, $fail failed"
    [ "$fail" -eq 0 ]
    ;;

  note)
    if [ $# -lt 1 ]; then
      echo 'usage: ./dogfood.sh note "what happened"' >&2
      exit 1
    fi
    printf -- '- %s: %s\n' "$(date +%F)" "$*" >> DOGFOOD.md
    tail -1 DOGFOOD.md
    ;;

  *)
    sed -n '2,10p' "$0"
    exit 1
    ;;
esac
