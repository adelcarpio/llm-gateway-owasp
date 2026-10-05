# Utilidades comunes de los scripts de ataque.
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
[[ -f .demo_keys ]] && source .demo_keys
GW="${GATEWAY_URL:-http://localhost:8000}"
MOCK="${MOCK_URL:-http://localhost:9000}"
: "${DEMO_CLIENT_KEY_A:?Ejecuta 'make bootstrap' y 'source .demo_keys'}"
profile() { curl -s "$GW/health" | python3 -c 'import sys,json;print(json.load(sys.stdin)["profile"])'; }
mock_mode() { curl -s -X POST "$MOCK/_mode" -H 'Content-Type: application/json' -d "{\"mode\":\"$1\"}" >/dev/null; }
mock_calls() { curl -s "$MOCK/_stats" | python3 -c 'import sys,json;print(json.load(sys.stdin)["calls"])'; }
banner() { printf '\n\033[1m== %s  [perfil: %s] ==\033[0m\n' "$1" "$(profile)"; }
