#!/usr/bin/env bash
# Uso: scripts/switch_profile.sh baseline|secure [--no-sanitizer]
# Escribe .env.profile y reinicia el gateway (Docker Compose si esta corriendo).
set -euo pipefail
cd "$(dirname "$0")/.."
PROFILE="${1:-}"
if [[ "$PROFILE" != "baseline" && "$PROFILE" != "secure" ]]; then
  echo "Uso: $0 baseline|secure [--no-sanitizer]" >&2; exit 1
fi
{
  echo "GATEWAY_PROFILE=$PROFILE"
  [[ "${2:-}" == "--no-sanitizer" ]] && echo "SEC_SANITIZER_ENABLED=false"
} > .env.profile
chmod 600 .env.profile

if docker compose ps -q gateway 2>/dev/null | grep -q .; then
  docker compose up -d --force-recreate --no-deps gateway >/dev/null
  for _ in $(seq 1 30); do
    curl -sf localhost:8000/health >/dev/null 2>&1 && break; sleep 0.5
  done
  echo "Gateway reiniciado en Docker con perfil: $(curl -s localhost:8000/health)"
else
  echo "Perfil '$PROFILE' escrito en .env.profile. Reinicia el gateway local: make run"
fi
