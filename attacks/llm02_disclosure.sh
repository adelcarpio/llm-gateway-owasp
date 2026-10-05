#!/usr/bin/env bash
# LLM02: fallo de credencial upstream + busqueda de secretos y datos personales en logs.
source "$(dirname "$0")/_common.sh"
banner "LLM02 Sensitive Information Disclosure"
mock_mode 401
echo "-- Respuesta al cliente ante fallo de credencial upstream:"
curl -s -w "\nHTTP %{http_code}\n" -X POST "$GW/v1/chat" -H "X-Gateway-Key: $DEMO_CLIENT_KEY_A" \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"Mi DNI es 40123456, revisa mi contrato"}]}' | tail -n 25
mock_mode ok
curl -s -o /dev/null -X POST "$GW/v1/chat" -H "X-Gateway-Key: $DEMO_CLIENT_KEY_A" \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"Mi DNI es 40123456, revisa mi contrato"}]}'
echo "-- Coincidencias de credenciales / DNI en logs/gateway.log:"
grep -cE "sk-ant-|Bearer|x-gateway-key|40123456" logs/gateway.log || true
if command -v gitleaks >/dev/null; then
  gitleaks detect --no-git --source logs/ --config .gitleaks.toml --redact -v || true
else
  echo "(gitleaks no instalado: https://github.com/gitleaks/gitleaks#installing)"
fi
