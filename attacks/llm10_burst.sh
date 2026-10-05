#!/usr/bin/env bash
# LLM10: 15 solicitudes en rafaga con la MISMA key rotando X-Forwarded-For.
source "$(dirname "$0")/_common.sh"
banner "LLM10 Unbounded Consumption"
for i in $(seq 1 15); do
  curl -s -o /dev/null -w "req $i -> %{http_code}\n" -X POST "$GW/v1/chat" \
    -H "X-Gateway-Key: $DEMO_CLIENT_KEY_A" -H "X-Forwarded-For: 203.0.113.$i" \
    -H "Content-Type: application/json" \
    -d '{"messages":[{"role":"user","content":"Resume en una linea que es un gateway"}]}'
done
echo "Llamadas que llegaron al proveedor: $(mock_calls)"
echo "-- Segundo cliente (no debe verse afectado):"
curl -s -D - -o /dev/null -X POST "$GW/v1/chat" -H "X-Gateway-Key: $DEMO_CLIENT_KEY_B" \
  -H "Content-Type: application/json" -d '{"messages":[{"role":"user","content":"Hola"}]}' \
  | grep -iE "^HTTP|x-ratelimit|retry-after"
