#!/bin/bash
# GPU Monitor — adaptive terminal, refreshes every 1s
# Usage: ./gpu_monitor.sh [interval_seconds]

INTERVAL="${1:-1}"

while true; do
    start=$(date +%s%N)

    output=$(nvidia-smi 2>&1)
    lines=$(echo "$output" | wc -l)
    target=$(awk "BEGIN {printf \"%d\", $lines * 1.15}")

    cols=$(tput cols 2>/dev/null || echo 120)
    printf '\e[8;%d;%dt' "$target" "$cols"

    clear
    echo "$output"

    # Subtract elapsed time so total cycle ≈ INTERVAL
    elapsed=$(( ($(date +%s%N) - start) / 1000000 ))
    remaining=$(awk "BEGIN {v = $INTERVAL - $elapsed/1000; print (v > 0) ? v : 0}")
    sleep "$remaining"
done
