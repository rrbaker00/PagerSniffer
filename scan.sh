#!/usr/bin/env bash
# Quick power sweep to find which paging channel is actually transmitting,
# before you commit the sniffer to a channel list.
#
#   ./scan.sh 138M 155M          # VHF paging band (default)
#   ./scan.sh 449M 470M          # UHF on-site + wide-area
#   ./scan.sh 138M 155M 40       # with explicit gain
set -e
LO=${1:-138M}
HI=${2:-155M}
GAIN=${3:-40}
SECS=25
OUT=$(mktemp)

command -v rtl_power >/dev/null || { echo "rtl_power not found - run ./setup.sh"; exit 1; }

echo "[*] Sweeping ${LO}..${HI} for ${SECS}s (gain ${GAIN}) ..."
timeout $((SECS + 3)) rtl_power -f "${LO}:${HI}:2k" -i 1 -g "$GAIN" "$OUT" || true

echo "[*] Strongest bins (likely carriers / active pagers):"
awk -F, '
{
  lo=$3+0; step=$5+0;
  for (i=7; i<=NF; i++) {
    f = lo + (i-7)*step; v = $i+0;
    if (v > peak[f]) peak[f] = v;
  }
}
END {
  for (f in peak) printf "%.4f MHz   %7.1f dB\n", f/1e6, peak[f];
}' "$OUT" | sort -k3 -nr | head -30

rm -f "$OUT"
echo
echo "[*] Then camp on the best one, e.g.:"
echo "      python3 pager_sniffer.py --freq 153.3500"
