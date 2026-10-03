#!/bin/bash
# ============================================================
# DEFER — Live System Monitor
# Usage: ./monitor.sh [refresh_seconds]
# ============================================================

export TERM="${TERM:-xterm-256color}"
[ "$TERM" = "dumb" ] && export TERM="xterm-256color"

INTERVAL="${1:-1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs/vllm"

# ---- Colors ----
BOLD=$'\033[1m'
GREEN=$'\033[32m'
YELLOW=$'\033[33m'
RED=$'\033[31m'
CYAN=$'\033[36m'
DIM=$'\033[90m'
RESET=$'\033[0m'

# ---- Bar helper ----
bar() {
    local pct=$1 width=${2:-20}
    local filled=$(( pct * width / 100 ))
    local empty=$(( width - filled ))
    local color="$GREEN"
    [ "$pct" -gt 50 ] && color="$YELLOW"
    [ "$pct" -gt 85 ] && color="$RED"
    local b=""
    for ((i=0; i<filled; i++)); do b+="█"; done
    for ((i=0; i<empty; i++)); do b+="░"; done
    echo "${color}${b}${RESET}"
}

# ---- Port to model name map ----
model_name() {
    case "$1" in
        8000) echo "Qwen3-235B (Primary)" ;;
        8001) echo "GLM-4.7 (Diversity)" ;;
        8002) echo "Qwen3-32B (V1)" ;;
        8003) echo "Mistral-Small (V5)" ;;
        8004) echo "Llama-4-Scout (V3)" ;;
        8005) echo "DeepSeek-R1 (V2)" ;;
        *)    echo "Unknown :$1" ;;
    esac
}

while true; do
    clear

    # ---- Header ----
    local_time=$(date '+%H:%M:%S')
    uptime_str=$(uptime -p 2>/dev/null | sed 's/up //')
    echo ""
    echo "  ${BOLD}DEFER System Monitor${RESET}  ${DIM}${local_time}  up ${uptime_str}${RESET}"
    echo "  ══════════════════════════════════════════════════════════════════════════════"

    # ---- CPU ----
    cpu_count=$(nproc)
    # Get CPU usage from /proc/stat (snapshot comparison is too slow for 1s, use top)
    cpu_usage=$(top -bn1 2>/dev/null | grep "^%Cpu" | awk '{print 100 - $8}' | head -1)
    cpu_usage=${cpu_usage:-0}
    cpu_pct=$(printf "%.0f" "$cpu_usage")
    load=$(cat /proc/loadavg | awk '{print $1, $2, $3}')

    echo ""
    echo "  ${BOLD}CPU${RESET}  ${cpu_count} cores  load: ${load}"
    echo "  $(bar $cpu_pct 40) ${cpu_pct}%"

    # ---- RAM ----
    read -r mem_total mem_used mem_free mem_available < <(free -m | awk '/^Mem:/ {print $2, $3, $4, $7}')
    mem_pct=$(( mem_used * 100 / mem_total ))
    swap_line=$(free -m | awk '/^Swap:/ {printf "%dMB / %dMB", $3, $2}')

    echo ""
    echo "  ${BOLD}RAM${RESET}  ${mem_used}MB / ${mem_total}MB  (${mem_available}MB available)  swap: ${swap_line}"
    echo "  $(bar $mem_pct 40) ${mem_pct}%"

    # ---- GPU ----
    echo ""
    echo "  ${BOLD}GPUs${RESET}"

    # Map PIDs to ports for labeling
    declare -A pid_port
    for port in 8000 8001 8002 8003 8004 8005; do
        # Find vLLM process listening on this port
        vllm_pid=$(ss -tlnp 2>/dev/null | grep ":${port} " | grep -oP 'pid=\K[0-9]+' | head -1)
        if [ -n "$vllm_pid" ]; then
            pid_port[$vllm_pid]=$port
        fi
    done

    while IFS=', ' read -r idx name mem_used mem_total gpu_util temp power; do
        local pct=0
        [ "$mem_total" -gt 0 ] 2>/dev/null && pct=$(( mem_used * 100 / mem_total ))
        local gpu_bar=$(bar $pct 15)
        local util_pct="${gpu_util}%"
        local temp_str="${temp}°C"
        local power_str="${power}W"

        # Color temp
        local tc="$GREEN"
        [ "$temp" -gt 60 ] && tc="$YELLOW"
        [ "$temp" -gt 80 ] && tc="$RED"

        printf "  ${BOLD}GPU %s${RESET} %s ${DIM}%6dMB/%6dMB${RESET} %3d%%  util:%-4s  ${tc}%s${RESET}  %s\n" \
            "$idx" "$gpu_bar" "$mem_used" "$mem_total" "$pct" "$util_pct" "$temp_str" "$power_str"

        # Show processes on this GPU
        while IFS=', ' read -r pid proc_mem; do
            [ -z "$pid" ] && continue
            local proc_name
            proc_name=$(ps -p "$pid" -o comm= 2>/dev/null)
            [ -z "$proc_name" ] && continue

            # Check if it's a vLLM worker
            local label=""
            local parent_pid
            parent_pid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')

            # Try to match PID or parent PID to a port
            if [ -n "${pid_port[$pid]}" ]; then
                label="$(model_name ${pid_port[$pid]})"
            elif [ -n "${pid_port[$parent_pid]}" ]; then
                label="$(model_name ${pid_port[$parent_pid]})"
            else
                # Check grandparent
                local gp_pid
                gp_pid=$(ps -o ppid= -p "$parent_pid" 2>/dev/null | tr -d ' ')
                if [ -n "${pid_port[$gp_pid]}" ]; then
                    label="$(model_name ${pid_port[$gp_pid]})"
                fi
            fi

            # Get thread name for vLLM workers
            local thread_name
            thread_name=$(cat /proc/$pid/comm 2>/dev/null)
            if [[ "$thread_name" == VLLM* ]]; then
                proc_name="$thread_name"
            fi

            if [ -n "$label" ]; then
                printf "    ${DIM}└─ PID %-7s %6sMB  %-20s  %s${RESET}\n" "$pid" "$proc_mem" "$proc_name" "${CYAN}${label}${RESET}"
            else
                printf "    ${DIM}└─ PID %-7s %6sMB  %s${RESET}\n" "$pid" "$proc_mem" "$proc_name"
            fi
        done < <(nvidia-smi --query-compute-apps=pid,used_gpu_memory --format=csv,noheader,nounits -i "$idx" 2>/dev/null)

    done < <(nvidia-smi --query-gpu=index,name,memory.used,memory.total,utilization.gpu,temperature.gpu,power.draw --format=csv,noheader,nounits 2>/dev/null)

    # ---- vLLM Server Status ----
    echo ""
    echo "  ${BOLD}vLLM Servers${RESET}"
    echo "  ${DIM}──────────────────────────────────────────────────────────────────────────${RESET}"

    any_server=0
    for port in 8000 8001 8002 8003 8004 8005; do
        local name=$(model_name $port)
        local status log_tail

        if curl -s --max-time 1 "http://localhost:$port/health" > /dev/null 2>&1; then
            status="${GREEN}● ready${RESET}"
            any_server=1

            # Get request stats if available
            local metrics
            metrics=$(curl -s --max-time 1 "http://localhost:$port/metrics" 2>/dev/null)
            local reqs=""
            if [ -n "$metrics" ]; then
                local pending running
                pending=$(echo "$metrics" | grep "vllm:num_requests_waiting " | grep -oP '[0-9.]+$' | head -1)
                running=$(echo "$metrics" | grep "vllm:num_requests_running " | grep -oP '[0-9.]+$' | head -1)
                [ -n "$pending" ] || [ -n "$running" ] && reqs="${DIM}  queue:${pending:-0} running:${running:-0}${RESET}"
            fi
            printf "  %-30s %s%s\n" "$name" "$status" "$reqs"

        elif ss -tln 2>/dev/null | grep -q ":${port} "; then
            status="${YELLOW}● starting${RESET}"
            any_server=1
            log_tail=""
            if [ -f "$LOG_DIR/port_${port}.log" ]; then
                log_tail=$(tail -1 "$LOG_DIR/port_${port}.log" 2>/dev/null | sed 's/^([^)]*) //' | cut -c1-60)
            fi
            printf "  %-30s %s  ${DIM}%s${RESET}\n" "$name" "$status" "$log_tail"

        elif pgrep -f "port $port" > /dev/null 2>&1; then
            status="${YELLOW}● loading${RESET}"
            any_server=1
            log_tail=""
            if [ -f "$LOG_DIR/port_${port}.log" ]; then
                log_tail=$(tail -1 "$LOG_DIR/port_${port}.log" 2>/dev/null | sed 's/^([^)]*) //' | cut -c1-60)
            fi
            printf "  %-30s %s  ${DIM}%s${RESET}\n" "$name" "$status" "$log_tail"

        else
            status="${DIM}○ stopped${RESET}"
            printf "  %-30s %s\n" "$name" "$status"
        fi
    done

    if [ $any_server -eq 0 ]; then
        echo "  ${DIM}No servers running. Use ./start_servers.sh to launch.${RESET}"
    fi

    # ---- Disk ----
    echo ""
    echo "  ${BOLD}Disk${RESET}"
    local models_size logs_size
    models_size=$(du -sh "$SCRIPT_DIR/models/" 2>/dev/null | awk '{print $1}')
    logs_size=$(du -sh "$SCRIPT_DIR/logs/" 2>/dev/null | awk '{print $1}')
    disk_info=$(df -h "$SCRIPT_DIR" 2>/dev/null | tail -1 | awk '{print $3 "/" $2 " (" $5 " used)"}')
    echo "  ${DIM}Storage: ${disk_info}  │  Models: ${models_size}  │  Logs: ${logs_size}${RESET}"

    # ---- Footer ----
    echo ""
    echo "  ${DIM}Press Ctrl+C to exit  │  Refresh: ${INTERVAL}s${RESET}"

    unset pid_port
    sleep "$INTERVAL"
done
