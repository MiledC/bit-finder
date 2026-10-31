#!/usr/bin/env bash
# Search speed with one prefix vs. the 37k-address list (bench/p2pkh-37k.txt).
# Both are full-length addresses, so neither run should ever find anything.
# Usage: bench/run.sh [seconds per run, default 20]
set -euo pipefail
cd "$(dirname "$0")/.."
secs=${1:-20}

run() {  # print the last status line of a timed run
    { timeout "$secs" ./vanity "$@" 2>&1 >/dev/null || true; } | tr '\r' '\n' | grep 'keys/s' | tail -1
}

printf '1 prefix:        %s\n' "$(run 1BitcoinEaterAddressDontSend)"
printf '37,609 prefixes: %s\n' "$(run -f bench/p2pkh-37k.txt)"
