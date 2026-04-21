#!/bin/bash
# ============================================================
# DefenseProxy experiment runner.
#
# Usage: ./run_experiment.sh <config_file> <run_label>
# Example: ./run_experiment.sh config.yaml exp_001
#
# Pipeline:
#   1. Reset Juice Shop via ../benchmarking/setup_juice_shop.sh
#   2. Launch DefenseProxy in background on localhost:8080
#   3. Wait for proxy readiness
#   4. Prompt operator to run the agent against
#        http://host.docker.internal:8080
#   5. Wait for Enter
#   6. Tear down proxy
#   7. Score Juice Shop via ../benchmarking/score_juice_shop.sh
#   8. Copy score CSV into ./logs/<run_label>/score.{txt,csv}
# ============================================================

set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH_DIR="$(cd "$SCRIPT_DIR/../benchmarking" && pwd)"

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <config_file> <run_label>"
  exit 1
fi

CONFIG_FILE="$1"
RUN_LABEL="$2"
LOG_DIR="$SCRIPT_DIR/logs/$RUN_LABEL"
mkdir -p "$LOG_DIR"

PROXY_PORT="$(python3 -c "
import yaml, sys
c = yaml.safe_load(open('$CONFIG_FILE'))
print((c.get('proxy') or {}).get('http_port', 8080))
")"

echo "============================================================"
echo "[run_experiment] config:     $CONFIG_FILE"
echo "[run_experiment] run_label:  $RUN_LABEL"
echo "[run_experiment] proxy port: $PROXY_PORT"
echo "[run_experiment] log dir:    $LOG_DIR"
echo "============================================================"

# ---- 1. Reset Juice Shop ------------------------------------------------
echo "[run_experiment] resetting Juice Shop..."
( cd "$BENCH_DIR" && ./setup_juice_shop.sh ) | tee "$LOG_DIR/setup.log"

# ---- 2. Start DefenseProxy in background --------------------------------
echo "[run_experiment] starting DefenseProxy..."
PROXY_LOG="$LOG_DIR/proxy.log"
( cd "$SCRIPT_DIR" && python3 main.py --config "$CONFIG_FILE" \
    --run-id "$RUN_LABEL" --mode http ) > "$PROXY_LOG" 2>&1 &
PROXY_PID=$!

cleanup() {
  if kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "[run_experiment] stopping DefenseProxy (pid=$PROXY_PID)..."
    kill "$PROXY_PID" 2>/dev/null || true
    # Also kill any child mitmdump
    pkill -P "$PROXY_PID" 2>/dev/null || true
    sleep 1
    kill -9 "$PROXY_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# ---- 3. Wait for readiness ---------------------------------------------
echo "[run_experiment] waiting for proxy on localhost:$PROXY_PORT..."
attempts=0
until curl -sf -o /dev/null "http://localhost:$PROXY_PORT/" 2>/dev/null; do
  sleep 1
  attempts=$((attempts+1))
  if [[ $attempts -gt 30 ]]; then
    echo "[run_experiment] ERROR: proxy did not become ready in 30s"
    echo "[run_experiment] tail of proxy log:"
    tail -n 40 "$PROXY_LOG" || true
    exit 1
  fi
done
echo "[run_experiment] proxy ready."

# ---- 4. Operator prompt -------------------------------------------------
cat <<EOF

============================================================
  Run PentestGPT with:
      pentestgpt --target http://host.docker.internal:$PROXY_PORT

  Or CAI:
      source ../cai/cai_env/bin/activate && cai
      (then target http://host.docker.internal:$PROXY_PORT)

  Press ENTER when the agent has finished to score the run.
============================================================
EOF
read -r _

# ---- 5/6. Tear down proxy (trap handles kill) ---------------------------
cleanup
trap - EXIT INT TERM

# ---- 7/8. Score --------------------------------------------------------
echo "[run_experiment] scoring Juice Shop..."
( cd "$BENCH_DIR" && ./score_juice_shop.sh "$RUN_LABEL" ) | tee "$LOG_DIR/score.txt"

SCORE_CSV="$BENCH_DIR/juice-shop-logs/score_${RUN_LABEL}.csv"
if [[ -f "$SCORE_CSV" ]]; then
  cp "$SCORE_CSV" "$LOG_DIR/score.csv"
  echo "[run_experiment] score csv copied to $LOG_DIR/score.csv"
fi

echo "[run_experiment] done. Next:"
echo "  python3 $SCRIPT_DIR/metrics.py --run-id $RUN_LABEL \\"
echo "      --agent-log $LOG_DIR/agent_stdout.txt \\"
echo "      --score-csv $LOG_DIR/score.csv"
