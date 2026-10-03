#!/bin/bash
# ============================================================
# DEFER — Interactive vLLM Server Launcher
# Usage: ./start_servers.sh
#
# MEMORY REALITY (actual BF16 weight sizes):
#   Qwen3-235B:    438GB → needs TP=4 (GPU 0,1,4,5 NVLink)
#   GLM-4.7:       668GB → TP=4 FP8 (~334GB, 84GB/GPU)
#   Qwen3-32B:      61GB → TP=1 (single GPU)
#   Mistral-Small:   89GB → TP=1 (single GPU)
#   Llama-4-Scout:  202GB → needs TP=2 (NVLink pair)
#
# Cannot run all simultaneously on 6× H200 (846GB total).
# Use server groups below.
# ============================================================

# ---- Color constants ----
BOLD=""
GREEN=""
YELLOW=""
RED=""
DIM=""
CYAN=""
RESET=""

# Enable colors only if terminal supports them
if [ -t 1 ] && [ "${TERM:-dumb}" != "dumb" ]; then
    BOLD=$'\033[1m'
    GREEN=$'\033[32m'
    YELLOW=$'\033[33m'
    RED=$'\033[31m'
    DIM=$'\033[90m'
    CYAN=$'\033[36m'
    RESET=$'\033[0m'
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODELS_DIR="${MODELS_DIR:-$SCRIPT_DIR/models}"
LOG_DIR="$SCRIPT_DIR/logs/vllm"
mkdir -p "$LOG_DIR"

# Non-interactive named profiles (revision v2,:
#   ./start_servers.sh --profile q235 | mid | glm      (start + wait)
#   ./start_servers.sh --status | --stop
case "${1:-}" in
    --profile) exec "$SCRIPT_DIR/scripts/vllm_profiles.sh" start "${2:?profile name}" ;;
    --status)  exec "$SCRIPT_DIR/scripts/vllm_profiles.sh" status ;;
    --stop)    exec "$SCRIPT_DIR/scripts/vllm_profiles.sh" stop ;;
esac

# ---- Auto-detect NVLink topology ----
detect_nvlink_pairs() {
    local topo pairs=()
    topo=$(nvidia-smi topo -m 2>/dev/null)
    local gpu_count
    gpu_count=$(nvidia-smi --query-gpu=index --format=csv,noheader | wc -l)
    for ((i=0; i<gpu_count; i++)); do
        for ((j=i+1; j<gpu_count; j++)); do
            local conn
            conn=$(echo "$topo" | grep "^GPU${i}" | awk -v col=$((j+2)) '{print $col}')
            if [[ "$conn" == NV* ]]; then
                pairs+=("$i,$j")
            fi
        done
    done
    echo "${pairs[@]}"
}

NV_PAIRS=($(detect_nvlink_pairs))

# Find largest NVLink-connected group
# From topology: GPU 0,1,4,5 are all NV6-linked; GPU 2,3 are NV6-linked
find_nvlink_group() {
    local gpu_count
    gpu_count=$(nvidia-smi --query-gpu=index --format=csv,noheader | wc -l)
    local topo
    topo=$(nvidia-smi topo -m 2>/dev/null)

    # Build adjacency and find connected components via NVLink
    declare -A adj
    for ((i=0; i<gpu_count; i++)); do
        adj[$i]=""
        for ((j=0; j<gpu_count; j++)); do
            [ $i -eq $j ] && continue
            local conn
            conn=$(echo "$topo" | grep "^GPU${i}" | awk -v col=$((j+2)) '{print $col}')
            if [[ "$conn" == NV* ]]; then
                adj[$i]+="$j "
            fi
        done
    done

    # Greedy: find the largest clique starting from each GPU
    local best_group="" best_size=0
    for ((start=0; start<gpu_count; start++)); do
        local group=("$start")
        for ((cand=start+1; cand<gpu_count; cand++)); do
            local all_linked=1
            for member in "${group[@]}"; do
                if [[ ! " ${adj[$member]} " =~ " $cand " ]]; then
                    all_linked=0
                    break
                fi
            done
            [ $all_linked -eq 1 ] && group+=("$cand")
        done
        if [ ${#group[@]} -gt $best_size ]; then
            best_size=${#group[@]}
            best_group=$(IFS=,; echo "${group[*]}")
        fi
    done
    echo "$best_group"
}

NVLINK_GROUP=$(find_nvlink_group)
echo ""
echo "  Detected NVLink topology:"
echo "    NVLink pairs: ${NV_PAIRS[*]}"
echo "    Largest NVLink group: GPU [$NVLINK_GROUP]"

# ---- Server Group Definitions ----
# GPU layout:
#   GPU 0,1,4,5 (NVLink): Primary TP=4 OR GLM TP=4 (swap)
#   GPU 2: V1 Qwen3-32B  OR  V5 Mistral (swap)
#   GPU 3: V2 DeepSeek-R1 OR  V5 Mistral (swap)
#   GPU 4,5: also V3 Llama-4-Scout TP=2 (when Primary not loaded)
#
# V1(GPU 2) + V2(GPU 3) can run simultaneously for diverse consensus.
# V5 Mistral swaps onto GPU 2 or 3 when replacing V1 or V2.

SERVER_GROUPS=(
    "A: Main Experiments — Qwen3-235B + V1 + V2"
    "B: GLM Diversity — GLM-4.7-FP8 + V1 + V2"
    "C: Same-Family — Qwen3-235B + V1 only"
    "D: Llama Primary — Llama-4-Scout + V1 + V2"
    "E: With Mistral — Qwen3-235B + V1 + V5"
    "F: Claude Primary — V1 + V2 + V3 + V5 (all local validators)"
    "G: Mid-Tier Parallel — Qwen3-32B + Mistral + GPT-OSS-120B (benchmark groups G/H/I/J)"
    "H: Custom — pick individual servers"
)

GROUP_COUNT=${#SERVER_GROUPS[@]}

# ---- Server pool ----
# idx: 0=Qwen3-235B  1=GLM-4.7  2=V1  3=V2  4=V5  5=V3  6=GPT-OSS-120B
ALL_NAMES=(
    "Qwen3-235B (Primary, TP=4)"
    "GLM-4.7 (Diversity, TP=4 FP8)"
    "Qwen3-32B (Validator V1 / Group G primary)"
    "DeepSeek-R1-Distill-32B (Validator V2)"
    "Mistral-Small-3.2-24B (Validator V5 / Group H primary)"
    "Llama-4-Scout-17B-16E (Validator V3, TP=2)"
    "GPT-OSS-120B (Group J primary, TP=4)"
)
ALL_PORTS=(8000 8001 8002 8005 8003 8004 8006)
ALL_GPUS=(
    "0,1,4,5"         # Qwen3-235B: TP=4 on NVLink group
    "0,1,4,5"         # GLM-4.7: TP=4 FP8 (swap with Primary)
    "2"                # V1 Qwen3-32B (also Group G primary)
    "3"                # V2 DeepSeek-R1
    "3"                # V5 Mistral (swap with V2 on GPU 3; also Group H primary)
    "4,5"              # V3 Llama-4-Scout: TP=2 (conflicts with Primary)
    "0,1,4,5"          # GPT-OSS-120B: TP=4 NVLink group (swap with Qwen-235B/GLM)
)
ALL_CMDS=(
    "vllm serve $MODELS_DIR/Qwen/Qwen3-235B-A22B-Instruct-2507 --tensor-parallel-size 4 --dtype bfloat16 --enable-auto-tool-choice --tool-call-parser hermes --gpu-memory-utilization 0.9 --max-model-len 32768 --enforce-eager --port 8000"
    "vllm serve $MODELS_DIR/zai-org/GLM-4.7-FP8 --tensor-parallel-size 4 --dtype auto --enable-auto-tool-choice --tool-call-parser glm47 --reasoning-parser glm45 --gpu-memory-utilization 0.9 --max-model-len 32768 --enforce-eager --port 8001"
    "vllm serve $MODELS_DIR/Qwen/Qwen3-32B --dtype bfloat16 --enable-auto-tool-choice --tool-call-parser hermes --gpu-memory-utilization 0.9 --max-model-len 32768 --port 8002"
    "vllm serve $MODELS_DIR/deepseek-ai/DeepSeek-R1-Distill-Qwen-32B --dtype bfloat16 --gpu-memory-utilization 0.9 --max-model-len 32768 --port 8005"
    "vllm serve $MODELS_DIR/mistralai/Mistral-Small-3.2-24B-Instruct-2506 --dtype bfloat16 --tokenizer-mode mistral --enable-auto-tool-choice --tool-call-parser mistral --gpu-memory-utilization 0.9 --max-model-len 32768 --port 8003"
    "vllm serve $MODELS_DIR/meta-llama/Llama-4-Scout-17B-16E-Instruct --tensor-parallel-size 2 --dtype bfloat16 --enable-auto-tool-choice --tool-call-parser llama4_pythonic --gpu-memory-utilization 0.9 --max-model-len 32768 --enforce-eager --port 8004"
    "vllm serve $MODELS_DIR/openai/gpt-oss-120b --tensor-parallel-size 4 --enable-auto-tool-choice --tool-call-parser openai --gpu-memory-utilization 0.9 --max-model-len 32768 --enforce-eager --port 8006"
)
POOL_COUNT=${#ALL_NAMES[@]}

# ---- Group compositions (indices into ALL_* arrays) ----
#
# Experiment coverage:
#   Eval A (540 attack + 60 benign): Group A
#   Eval A GLM diversity (30 trials): Group B
#   Eval C (memory poisoning, 90):    Group A
#   Eval D (TAMAS, 400):              Group A (+ GPT-4o API)
#   Ablation (270 runs):              Group A
#   Validator same-family (30):        Group C (call V1 three times)
#   Validator default diverse (30):    Group A (V1 + V2 + V4 Claude API)
#   Validator all-local diverse (30):  Group D (V1 + V2 + V3 Llama)
#   Eval B (boundary analysis):        Analytical, no servers needed
#   Eval E (latency):                  Extracted from A logs
#   Eval H (cross-domain):            Structural, no servers needed
#
GROUP_A_IDX=(0 2 3)    # Qwen3-235B(0,1,4,5) + V1(2) + V2(3) [+V4 Claude +V6 GPT-4o API]
GROUP_B_IDX=(1 2 3)    # GLM-4.7 FP8(0,1,4,5) + V1(2) + V2(3) [+V4 Claude +V6 GPT-4o API]
GROUP_C_IDX=(0 2)      # Qwen3-235B(0,1,4,5) + V1(2) [same-family: 3x Qwen3-32B]
GROUP_D_IDX=(5 2 3)    # Llama(4,5) + V1(2) + V2(3) [+V4 Claude +V6 GPT-4o API]
GROUP_E_IDX=(0 2 4)    # Qwen3-235B(0,1,4,5) + V1(2) + V5 Mistral(3) [+V4 Claude +V6 GPT-4o API]
GROUP_F_IDX=(2 3 5)    # Claude API primary — V1(2)+V2(3)+V3(4,5) [V5 swaps with V2, not simultaneous]
# G_SERVER serves benchmark groups G/H/I/J in parallel:
#   - Qwen3-32B on 8002 = V1 validator AND primary for benchmark Group G
#   - Mistral on   8003 = V5 validator AND primary for benchmark Group H
#   - GPT-OSS-120B 8006 = primary for benchmark Group J
#   - Llama-3.1-8B is served from the RTX 5090 node (REMOTE_5090_URL in .env) for Group I
GROUP_G_IDX=(2 4 6)    # Qwen3-32B(2) + V5 Mistral(3) + GPT-OSS-120B(0,1,4,5)

# ---- Selection menu ----
cursor=0

draw_group_menu() {
    clear
    echo ""
    echo "  DEFER — Select Server Group"
    echo "  ────────────────────────────────────────────────────────────────"
    echo ""
    echo "  7 model families: Qwen, GLM, DeepSeek, Meta, Mistral, Anthropic, OpenAI"
    echo "  Available: 6x H200 = 846GB (groups share GPUs, swap as needed)"
    echo ""

    local descs=(
        "Qwen3-235B (0,1,4,5) + V1 Qwen3-32B (2) + V2 DeepSeek-R1 (3) + V4 Claude + V6 GPT-4o"
        "GLM-4.7 FP8 (0,1,4,5) + V1 (2) + V2 (3) + V4 Claude + V6 GPT-4o"
        "Qwen3-235B (0,1,4,5) + V1 Qwen3-32B (2) only -- same-family consensus"
        "Llama-4-Scout (4,5) + V1 (2) + V2 (3) + V4 Claude + V6 GPT-4o -- Llama as primary"
        "Qwen3-235B (0,1,4,5) + V1 (2) + V5 Mistral (3) + V4 Claude + V6 GPT-4o"
        "Claude API primary + V1 (2) + V2 (3) + V3 Llama (4,5) -- frees GPU for V3"
        "Qwen3-32B (2) + Mistral (3) + GPT-OSS-120B (0,1,4,5) -- shared by benchmark groups G/H/I/J in parallel; Llama-3.1-8B (Group I) served externally"
        "Pick individual servers manually"
    )

    for ((i=0; i<GROUP_COUNT; i++)); do
        local prefix="  "
        [ $i -eq $cursor ] && prefix="> "

        if [ $i -eq $cursor ]; then
            echo "${prefix}${GREEN}${SERVER_GROUPS[$i]}${RESET}"
            echo "    ${DIM}${descs[$i]}${RESET}"
        else
            echo "${prefix}${DIM}${SERVER_GROUPS[$i]}${RESET}"
            echo "    ${DIM}${descs[$i]}${RESET}"
        fi
    done
    echo ""
    echo "  ↑/↓ move  |  Enter select  |  q quit"
}

draw_group_menu

while true; do
    IFS= read -rsn1 key
    if [[ "$key" == $'\e' ]]; then
        read -rsn2 -t 0.01 rest
        key="${key}${rest}"
    fi
    case "$key" in
        $'\033[A'|k)  ((cursor > 0)) && ((cursor--)) ;;
        $'\033[B'|j)  ((cursor < GROUP_COUNT-1)) && ((cursor++)) ;;
        ''|$'\n')   break ;;
        q)          clear; echo "  Cancelled."; exit 0 ;;
    esac
    draw_group_menu
done

group_choice=$cursor

# ---- Resolve selected servers ----
SEL_IDX=()

case $group_choice in
    0) SEL_IDX=("${GROUP_A_IDX[@]}") ;;
    1) SEL_IDX=("${GROUP_B_IDX[@]}") ;;
    2) SEL_IDX=("${GROUP_C_IDX[@]}") ;;
    3) SEL_IDX=("${GROUP_D_IDX[@]}") ;;
    4) SEL_IDX=("${GROUP_E_IDX[@]}") ;;
    5) SEL_IDX=("${GROUP_F_IDX[@]}") ;;
    6) SEL_IDX=("${GROUP_G_IDX[@]}") ;;
    7)
        # Custom: show individual server picker
        sel=()
        for ((i=0; i<POOL_COUNT; i++)); do sel+=(0); done
        cursor=0

        draw_custom_menu() {
            clear
            echo ""
            echo "  Custom Server Selection"
            echo "  ──────────────────────────────────────────────"
            echo ""
            for ((i=0; i<POOL_COUNT; i++)); do
                local prefix="  "; [ $i -eq $cursor ] && prefix="> "
                local box="[ ]"; [ "${sel[$i]}" -eq 1 ] && box="[x]"
                if [ "${sel[$i]}" -eq 1 ]; then
                    echo "${prefix}${GREEN}${box} ${ALL_NAMES[$i]}  (GPU ${ALL_GPUS[$i]}, port ${ALL_PORTS[$i]})${RESET}"
                else
                    echo "${prefix}${DIM}${box} ${ALL_NAMES[$i]}  (GPU ${ALL_GPUS[$i]}, port ${ALL_PORTS[$i]})${RESET}"
                fi
            done
            echo ""
            echo "  ↑/↓ move  |  Space toggle  |  Enter launch  |  q back"
        }

        draw_custom_menu
        while true; do
            IFS= read -rsn1 key
            if [[ "$key" == $'\e' ]]; then
                read -rsn2 -t 0.01 rest
                key="${key}${rest}"
            fi
            case "$key" in
                $'\033[A'|k)  ((cursor > 0)) && ((cursor--)) ;;
                $'\033[B'|j)  ((cursor < POOL_COUNT-1)) && ((cursor++)) ;;
                ' ')
                    if [ "${sel[$cursor]}" -eq 1 ]; then sel[$cursor]=0; else sel[$cursor]=1; fi
                    ;;
                ''|$'\n')   break ;;
                q)          clear; echo "  Cancelled."; exit 0 ;;
            esac
            draw_custom_menu
        done
        for ((i=0; i<POOL_COUNT; i++)); do
            [ "${sel[$i]}" -eq 1 ] && SEL_IDX+=("$i")
        done
        ;;
esac

SEL_COUNT=${#SEL_IDX[@]}
if [ $SEL_COUNT -eq 0 ]; then
    clear; echo "  No servers selected. Exiting."; exit 0
fi

# ---- Check GPU conflicts ----
check_gpu_conflicts() {
    declare -A gpu_usage
    for i in "${SEL_IDX[@]}"; do
        IFS=',' read -ra gpus <<< "${ALL_GPUS[$i]}"
        for g in "${gpus[@]}"; do
            if [ -n "${gpu_usage[$g]}" ]; then
                echo "  WARNING: GPU $g used by both ${ALL_NAMES[${gpu_usage[$g]}]} and ${ALL_NAMES[$i]}"
            fi
            gpu_usage[$g]=$i
        done
    done
}

# ---- Kill stale GPU processes ----
clear
echo ""
echo "  Checking for stale GPU processes..."
stale_pids=$(nvidia-smi --query-compute-apps=pid --format=csv,noheader 2>/dev/null | tr -d ' ')
if [ -n "$stale_pids" ]; then
    echo "  Found stale processes: $stale_pids — killing..."
    for p in $stale_pids; do kill "$p" 2>/dev/null; done
    sleep 2
    echo "  Cleared."
else
    echo "  GPUs clear."
fi

# ---- Show allocation plan ----
echo ""
echo "  ┌──────────────────────────────────────────────────────────────┐"
echo "  │  Allocation Plan                                            │"
echo "  └──────────────────────────────────────────────────────────────┘"
echo ""
for i in "${SEL_IDX[@]}"; do
    printf '  %-50s GPU %-11s Port %d\n' "${ALL_NAMES[$i]}" "${ALL_GPUS[$i]}" "${ALL_PORTS[$i]}"
done
echo ""
check_gpu_conflicts
echo ""

# ---- Fix FlashInfer CUTLASS JIT compilation failures on H200 ----
# FlashInfer 0.6.7 fused_moe JIT compilation segfaults on SM90a (H200).
# Temporarily hide the flashinfer package so vLLM uses builtin Triton MoE.
FLASHINFER_DIR=$(python3 -c "import flashinfer; import os; print(os.path.dirname(flashinfer.__file__))" 2>/dev/null)
if [ -n "$FLASHINFER_DIR" ] && [ -d "$FLASHINFER_DIR" ] && [ ! -d "${FLASHINFER_DIR}_disabled" ]; then
    mv "$FLASHINFER_DIR" "${FLASHINFER_DIR}_disabled"
    echo "  ${YELLOW}Temporarily disabled flashinfer (CUTLASS JIT broken on H200)${RESET}"
    echo "  ${DIM}Renamed: ${FLASHINFER_DIR} → ${FLASHINFER_DIR}_disabled${RESET}"
    echo "  ${DIM}To re-enable: mv ${FLASHINFER_DIR}_disabled ${FLASHINFER_DIR}${RESET}"
elif [ -d "${FLASHINFER_DIR}_disabled" ]; then
    echo "  ${DIM}FlashInfer already disabled${RESET}"
fi
export VLLM_ATTENTION_BACKEND=FLASH_ATTN
rm -rf ~/.cache/flashinfer 2>/dev/null
echo ""

# ---- Launch servers ----
PIDS=()
declare -A PID_MAP

for i in "${SEL_IDX[@]}"; do
    logfile="$LOG_DIR/port_${ALL_PORTS[$i]}.log"
    > "$logfile"
    echo "  ${GREEN}●${RESET} ${ALL_NAMES[$i]}  → $logfile"
    CUDA_VISIBLE_DEVICES="${ALL_GPUS[$i]}" ${ALL_CMDS[$i]} > "$logfile" 2>&1 &
    pid=$!
    PIDS+=($pid)
    PID_MAP[$i]=$pid
done

echo ""
echo "  Waiting for servers... (press Ctrl+C to abort)"
sleep 3

# ---- Trap ----
cleanup() {
    echo ""
    echo "  Stopping all servers..."
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null; done
    wait 2>/dev/null
    echo "  All servers stopped."
    exit 0
}
trap cleanup SIGINT SIGTERM

# ---- Status tracking ----
declare -A STATUS DETAIL
for i in "${SEL_IDX[@]}"; do STATUS[$i]="pending"; done

start_time=$(date +%s)
SPINNERS=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
spin_idx=0
TIMEOUT=1200  # 20 minutes — large models need time for CUDA graph compilation

get_status() {
    local logfile="$1" port="$2" pid="$3"
    if curl -s --max-time 1 "http://localhost:$port/health" > /dev/null 2>&1; then
        echo "ready|Server healthy and accepting requests"; return
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
        local err
        err=$(grep -i "CUDA out of memory\|Failed to load\|not enough GPU\|ValueError\|ModuleNotFound\|No such file\|error" "$logfile" 2>/dev/null | tail -1)
        echo "failed|${err:0:75}"; return
    fi
    if [ ! -s "$logfile" ]; then
        echo "pending|Process started, waiting for output..."; return
    fi
    if grep -q "warming up\|warm up" "$logfile" 2>/dev/null; then
        echo "loading|Warming up model (almost ready)..."; return
    fi
    if grep -q "profiling\|capturing\|CUDA graph" "$logfile" 2>/dev/null; then
        echo "loading|Capturing CUDA graphs..."; return
    fi
    if grep -q "Loading model weights" "$logfile" 2>/dev/null; then
        local pct; pct=$(grep -oP '\d+%' "$logfile" 2>/dev/null | tail -1)
        echo "loading|Loading model weights${pct:+... $pct}"; return
    fi
    if grep -q "Loading safetensors" "$logfile" 2>/dev/null; then
        echo "loading|Loading safetensors shards..."; return
    fi
    if grep -qi "Initializ" "$logfile" 2>/dev/null; then
        echo "loading|Initializing model engine..."; return
    fi
    local last; last=$(tail -3 "$logfile" 2>/dev/null | grep -v '^$' | tail -1)
    echo "loading|${last:0:75}"
}

draw_dashboard() {
    local now elapsed_total mins secs
    now=$(date +%s)
    elapsed_total=$(( now - start_time ))
    mins=$(( elapsed_total / 60 )); secs=$(( elapsed_total % 60 ))
    local ready_count=0 fail_count=0 loading_count=0

    clear
    echo ""
    echo "  ${BOLD}Server Status${RESET}  ${DIM}[${mins}m $(printf '%02d' $secs)s elapsed]${RESET}"
    echo "  ──────────────────────────────────────────────────────────────────────────────"

    for i in "${SEL_IDX[@]}"; do
        local logfile="$LOG_DIR/port_${ALL_PORTS[$i]}.log"
        local result state detail icon color
        result=$(get_status "$logfile" "${ALL_PORTS[$i]}" "${PID_MAP[$i]}")
        state="${result%%|*}"; detail="${result#*|}"
        STATUS[$i]="$state"
        local elapsed_s=$(( now - start_time ))

        case "$state" in
            ready)   icon="✓"; color="$GREEN"; ((ready_count++)) ;;
            loading) icon="${SPINNERS[$spin_idx]}"; color="$YELLOW"; ((loading_count++)) ;;
            failed)  icon="✗"; color="$RED"; ((fail_count++)) ;;
            *)       icon="${SPINNERS[$spin_idx]}"; color="$DIM"; ((loading_count++)) ;;
        esac

        echo "  ${color}${icon}${RESET} ${ALL_NAMES[$i]}  ${color}[${state}]${RESET}  ${DIM}${elapsed_s}s${RESET}"
        echo "    ${DIM}└─ ${detail}${RESET}"
    done

    echo "  ──────────────────────────────────────────────────────────────────────────────"

    local gpu_line="  ${DIM}GPU:${RESET}"
    while IFS=', ' read -r idx used total; do
        local pct=0
        [ "$total" -gt 0 ] 2>/dev/null && pct=$(( used * 100 / total ))
        local filled=$(( pct / 10 )) empty=$(( 10 - filled ))
        local gc="$DIM"
        [ "$pct" -gt 0 ] && gc="$GREEN"
        [ "$pct" -gt 50 ] && gc="$YELLOW"
        [ "$pct" -gt 85 ] && gc="$RED"
        local bar=""
        for ((b=0; b<filled; b++)); do bar+="█"; done
        for ((b=0; b<empty; b++)); do bar+="░"; done
        gpu_line+=" ${gc}${idx}:${bar} ${pct}%${RESET}"
    done < <(nvidia-smi --query-gpu=index,memory.used,memory.total --format=csv,noheader,nounits 2>/dev/null)
    echo "$gpu_line"

    echo "  ──────────────────────────────────────────────────────────────────────────────"

    if [ $loading_count -eq 0 ] && [ $fail_count -eq 0 ]; then
        echo "  ${GREEN}✓ All ${ready_count} servers ready! Press Ctrl+C to stop all.${RESET}"
    elif [ $loading_count -eq 0 ] && [ $ready_count -gt 0 ] && [ $fail_count -gt 0 ]; then
        echo "  ${YELLOW}⚠ ${ready_count} ready, ${fail_count} failed. Check logs: ${LOG_DIR}${RESET}"
    elif [ $loading_count -eq 0 ] && [ $ready_count -eq 0 ]; then
        echo "  ${RED}✗ All ${fail_count} servers failed. Check logs: ${LOG_DIR}${RESET}"
    else
        echo "  ${DIM}⏳ ${loading_count} loading, ${ready_count} ready, ${fail_count} failed  (timeout: 20 min)${RESET}"
    fi
    echo ""
}

while true; do
    spin_idx=$(( (spin_idx + 1) % ${#SPINNERS[@]} ))
    elapsed=$(( $(date +%s) - start_time ))
    draw_dashboard

    all_settled=1
    for i in "${SEL_IDX[@]}"; do
        [ "${STATUS[$i]}" != "ready" ] && [ "${STATUS[$i]}" != "failed" ] && all_settled=0
    done
    [ $all_settled -eq 1 ] && break
    [ $elapsed -ge $TIMEOUT ] && echo "  Timeout reached." && break
    sleep 1
done

any_ready=0
for i in "${SEL_IDX[@]}"; do [ "${STATUS[$i]}" = "ready" ] && any_ready=1; done

if [ $any_ready -eq 1 ]; then
    wait
fi
