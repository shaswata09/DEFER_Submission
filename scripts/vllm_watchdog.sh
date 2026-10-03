#!/bin/bash
# Keep a vLLM profile alive for the duration of a long run.
#
# The Qwen3-235B TP=4 server lost a worker once under load
# ("Worker proc VllmWorker-1 died unexpectedly, shutting down executor"), which
# takes the whole engine down and silently turns every later trial into an
# error. Over an 8 hour programme that is unacceptable, so this watchdog polls
# the profile's ports and restarts whatever has died. start_server is
# idempotent -- it skips anything already answering -- so a restart only brings
# back the dead service.
#
#   ./scripts/vllm_watchdog.sh q235 &        # until stopped
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."

PROFILE="${1:-q235}"
INTERVAL="${WATCHDOG_INTERVAL:-60}"
LOG="logs/vllm_watchdog.log"
# Watch the PRIMARY only. A dead primary kills every trial, so it is worth
# restarting. A validator that is merely slow under panel load reads as "down"
# and restarting it would try to put a second copy on a GPU that is already
# ~92% full, taking out its neighbour too -- the validators are left alone and
# a transient hiccup just costs individual trials.
case "$PROFILE" in
    q235) PORTS="${WATCH_PORTS:-8000}" ;;
    mid)  PORTS="${WATCH_PORTS:-8004}" ;;
    *)    echo "unknown profile $PROFILE"; exit 2 ;;
esac

note() { echo "$(date '+%F %T')  $*" >> "$LOG"; }
note "watchdog start for profile $PROFILE (ports: $PORTS)"

restarts=0
strikes=0
while true; do
    down=""
    for p in $PORTS; do
        # A loaded server can be slow to answer /health. start_server probes with
        # --max-time 1, so a false "down" here makes it launch a SECOND copy onto
        # GPUs that already hold the model -> OOM -> the real crash. Be patient,
        # and only act when the port is unreachable AND nothing is listening.
        curl -s --max-time 30 "http://127.0.0.1:${p}/health" >/dev/null 2>&1 && continue
        ss -ltn 2>/dev/null | grep -q ":${p} " && continue     # still bound: alive, just busy
        down="$down $p"
    done
    if [ -n "$down" ]; then
        # require three consecutive sightings before touching anything
        strikes=$((strikes+1))
        if [ "$strikes" -lt 3 ]; then
            note "possible down:$down (strike $strikes/3) -- not acting yet"
            sleep "$INTERVAL"; continue
        fi
        restarts=$((restarts+1))
        note "DOWN:$down -- restart #$restarts"
        # Only clear orphaned workers when the primary is the thing that died
        # AND its GPUs are still holding memory; a blanket pkill would take out
        # the healthy validators sharing this box.
        if echo "$down" | grep -qE "8000|8004"; then
            held=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits 2>/dev/null \
                   | head -4 | awk '{s+=$1} END{print s+0}')
            if [ "${held:-0}" -gt 2000 ]; then
                note "primary GPUs still hold ${held} MiB -- clearing orphaned workers"
                # map each compute PID to its GPU index and kill only those on
                # the primary's GPUs (0-3); the validators live on GPU4.
                nvidia-smi --query-gpu=index,uuid --format=csv,noheader 2>/dev/null \
                    | tr -d ' ' > /tmp/_gpuidx.$$
                nvidia-smi --query-compute-apps=pid,gpu_uuid --format=csv,noheader 2>/dev/null \
                    | tr -d ' ' | while IFS=, read -r pid uuid; do
                        idx=$(grep -F ",$uuid" /tmp/_gpuidx.$$ | cut -d, -f1)
                        case "$idx" in 0|1|2|3) kill -9 "$pid" 2>/dev/null ;; esac
                    done
                rm -f /tmp/_gpuidx.$$
                sleep 10
            fi
        fi
        sleep 5
        bash scripts/vllm_profiles.sh start "$PROFILE" >> "$LOG" 2>&1
        note "restart attempt finished; re-checking in ${INTERVAL}s"
        strikes=0
    else
        strikes=0
    fi
    sleep "$INTERVAL"
done
