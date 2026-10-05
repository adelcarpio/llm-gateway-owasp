#!/usr/bin/env bash
# Demo completa SIN Docker: levanta mock + gateway con uvicorn y ejecuta cada ataque
# en baseline y en secure, reiniciando el gateway entre perfiles.
# Uso: scripts/local_demo.sh [llm10 llm01 llm02 llm07 upstream]
set -uo pipefail
cd "$(dirname "$0")/.."
[[ -f .env ]] || python3 scripts/bootstrap_env.py
CASES=("${@:-llm10 llm01 llm02 llm07 upstream}")
read -r -a CASES <<< "${CASES[*]}"
MOCK_PID=""; GW_PID=""

start_mock() {
  MOCK_TIMEOUT_SECONDS="${MOCK_TIMEOUT_SECONDS:-8}" uvicorn mock_upstream.app:app --port 9000 \
    --no-server-header --log-level warning & MOCK_PID=$!
  for _ in $(seq 1 40); do curl -sf localhost:9000/_stats >/dev/null && return; sleep 0.25; done
}
start_gw() {  # $1 = baseline|secure, $2 = --no-sanitizer opcional
  [[ -n "$GW_PID" ]] && kill "$GW_PID" 2>/dev/null && wait "$GW_PID" 2>/dev/null
  ./scripts/switch_profile.sh "$1" ${2:-} >/dev/null
  uvicorn app.main:create_app --factory --port 8000 --no-server-header --log-level warning \
    >/dev/null 2>>/tmp/llm-gateway-server.log & GW_PID=$!
  for _ in $(seq 1 40); do curl -sf localhost:8000/health >/dev/null && break; sleep 0.25; done
  curl -s -X POST localhost:9000/_reset >/dev/null
}
cleanup() { kill $GW_PID $MOCK_PID 2>/dev/null; ./scripts/switch_profile.sh secure >/dev/null; }
trap cleanup EXIT

start_mock
for c in "${CASES[@]}"; do
  for p in baseline secure; do
    extra=""; [[ "$c" == "llm07" && "$p" == "secure" ]] && extra="--no-sanitizer"
    start_gw "$p" "$extra"
    [[ "$c" == "llm02" || "$c" == "llm07" ]] && : > logs/gateway.log
    case "$c" in
      llm10) ./attacks/llm10_burst.sh ;;
      llm01) ./attacks/llm01_injection.sh ;;
      llm02) ./attacks/llm02_disclosure.sh ;;
      llm07) ./attacks/llm07_leak.sh ;;
      upstream) ./attacks/upstream_failures.sh ;;
    esac
  done
done
echo; echo "Recuerda: 'make clean-logs' tras las demos en baseline (el log contiene la credencial ficticia)."
