#!/usr/bin/env bash
# End-to-end check on a GPU machine: run real searches, then verify every match
# with tests/verify.py (libsecp256k1, no shared code), and make sure the verifier
# rejects tampered output. Usage: tests/e2e.sh [python-with-coincurve]
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${1:-python3}
VANITY=./vanity

work=$(mktemp -d)
chmod 700 "$work"
trap 'rm -rf "$work"' EXIT  # matches hold private keys; never leave them behind

step() { printf '\n== %s\n' "$*"; }

step "GPU self-test"
$VANITY --selftest

step "search: one of each, many prefixes at once"
PREFIXES="1A 1zz 11 111 1Ab 1Cat 1Dog 1Ze 1Bit 1Kp 1xy9 1QQQ 1Moon 1Love 1Zz9z"
$VANITY -o "$work/each.txt" $PREFIXES >/dev/null
$PY tests/verify.py --expect "$(echo $PREFIXES | tr ' ' ,)" "$work/each.txt"

step "search: keep going, 300 matches of one prefix (covers all six key variants)"
$VANITY -k -n 300 -o "$work/many.txt" 1Ab >/dev/null
$PY tests/verify.py "$work/many.txt" | tail -1

step "verifier must reject tampered output"
fail=0
tamper() {  # write the first record with one field altered, expect verify.py to fail
    "$PY" - "$work/each.txt" "$1" > "$work/bad.txt" <<'EOF2'
import sys
rec = open(sys.argv[1]).read().split("\n\n")[0].splitlines()
field = sys.argv[2]
out = []
for line in rec:
    key, _, val = line.partition(":")
    if key.strip() == field:
        v = val.strip()
        if field == "Prefix":
            v = "1NotIt"
        else:  # replace the last character with a different one
            alphabet = "0123456789abcdef" if "key" in field else "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
            v = v[:-1] + next(c for c in alphabet if c != v[-1])
        line = "%s: %s" % (key, v)
    out.append(line)
print("\n".join(out) + "\n")
EOF2
    if "$PY" tests/verify.py "$work/bad.txt" >/dev/null; then
        echo "NOT caught: $1 changed"; fail=1
    else
        echo "caught: $1 changed"
    fi
}
for f in "Private key" "Public key" "Address" "WIF" "Prefix"; do tamper "$f"; done
[ $fail = 0 ]

step "all end-to-end checks passed"
