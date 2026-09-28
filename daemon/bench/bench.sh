#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
W="${WARDEND_BIN:-$(dirname "$0")/../wardend}"
N=${1:-200}
for r in 1 2 3; do
  s=$(date +%s%N); bash -c "for i in \$(seq 1 $N); do /bin/true; done"; e=$(date +%s%N)
  echo "bare   N=$N run$r: $(( (e-s)/1000000 )) ms"
done
for r in 1 2 3; do
  s=$(date +%s%N); $W run --quiet --log /tmp/bench.jsonl -- bash -c "for i in \$(seq 1 $N); do /bin/true; done"; e=$(date +%s%N)
  echo "warden N=$N run$r: $(( (e-s)/1000000 )) ms"
done
rm -f /tmp/bench.jsonl
for r in 1 2 3; do
  s=$(date +%s%N); $W run --log /tmp/bench.jsonl --wait-killable -- bash -c "for i in \$(seq 1 $N); do /bin/true; done" 2>&1 | tail -1; e=$(date +%s%N)
  echo "warden+wait-killable N=$N run$r: $(( (e-s)/1000000 )) ms"
done
