#!/usr/bin/env bash
# Degradacion controlada: timeout, 5xx, 429 y apertura del circuit breaker.
source "$(dirname "$0")/_common.sh"
banner "Degradacion controlada ante fallos upstream"
for mode in timeout 500 429; do
  mock_mode "$mode"
  echo "-- MOCK_MODE=$mode"
  curl -s -m 60 -w "\nHTTP %{http_code} en %{time_total}s\n" -X POST "$GW/v1/chat" \
    -H "X-Gateway-Key: $DEMO_CLIENT_KEY_B" -H "Content-Type: application/json" \
    -d '{"messages":[{"role":"user","content":"Hola"}]}' | tail -n 8
done
echo "-- Circuit breaker (MOCK_MODE=500, 7 solicitudes):"
mock_mode 500
for i in $(seq 1 7); do
  curl -s -o /dev/null -w "%{http_code} " -X POST "$GW/v1/chat" -H "X-Gateway-Key: $DEMO_CLIENT_KEY_B" \
    -H "Content-Type: application/json" -d '{"messages":[{"role":"user","content":"Hola"}]}'
done
echo; echo "Llamadas que llegaron al proveedor: $(mock_calls)"
mock_mode ok
