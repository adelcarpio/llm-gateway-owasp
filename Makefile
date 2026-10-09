SHELL := /bin/bash
PROFILE ?= secure
MOCK_MODE ?= ok
PY ?= python3

.PHONY: help install bootstrap up down logs run run-mock baseline secure reset mock-mode \
        test evidence report attack-llm10 attack-llm01 attack-llm02 attack-llm07 attack-upstream \
        attacks-all demo-local scan clean-logs test-casos attack-extra

help:  ## Lista de comandos
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  %-18s %s\n", $$1, $$2}'

install:  ## Instala dependencias de desarrollo y hooks (gitleaks en pre-commit)
	$(PY) -m pip install -r requirements-dev.txt
	pre-commit install || true

bootstrap:  ## Genera .env, .env.profile y .demo_keys (gitignored)
	$(PY) scripts/bootstrap_env.py

up:  ## Levanta gateway + mock + redis con Docker Compose
	docker compose up -d --build

down:  ## Detiene el entorno
	docker compose down

logs:  ## Sigue el log de auditoria en JSON
	tail -f logs/gateway.log | jq -c .

run-mock:  ## (sin Docker) Arranca el mock upstream en :9000
	uvicorn mock_upstream.app:app --port 9000 --no-server-header

run:  ## (sin Docker) Arranca el gateway en :8000 con el perfil de .env.profile
	uvicorn app.main:create_app --factory --port 8000 --no-server-header

baseline:  ## Cambia a perfil baseline (sin controles)
	./scripts/switch_profile.sh baseline

secure:  ## Cambia a perfil secure (controles activos)
	./scripts/switch_profile.sh secure

reset:  ## Reinicia contadores (mock, Redis) y el gateway
	@curl -s -X POST localhost:9000/_reset >/dev/null && echo "mock reiniciado"
	@if docker compose ps -q gateway 2>/dev/null | grep -q .; then \
	  docker compose exec -T redis redis-cli FLUSHALL >/dev/null && \
	  ./scripts/switch_profile.sh $$(sed -n 's/GATEWAY_PROFILE=//p' .env.profile) $$(grep -q SEC_SANITIZER_ENABLED=false .env.profile && echo --no-sanitizer); \
	else echo "Sin Docker: reinicia 'make run' para limpiar cuotas y circuit breaker"; fi

mock-mode:  ## Fija el modo del mock: make mock-mode MOCK_MODE=ok|timeout|500|429|401|503
	@curl -s -X POST localhost:9000/_mode -H 'Content-Type: application/json' -d '{"mode":"$(MOCK_MODE)"}'; echo

test:  ## Suite completa (unitarias, seguridad antes/despues, resiliencia)
	$(PY) -m pytest -v

evidence:  ## Ejecuta toda la suite y genera evidence/<fecha>/*.json
	$(PY) -m pytest -v tests/security tests/resilience
	$(PY) scripts/report.py

report:  ## Resume la ultima evidencia en evidence/REPORT.md
	$(PY) scripts/report.py

attack-llm10:  ## Ataque LLM10 contra el gateway en ejecucion (PROFILE=baseline|secure)
	./scripts/switch_profile.sh $(PROFILE) && $(MAKE) -s reset && ./attacks/llm10_burst.sh

attack-llm01:  ## Ataque LLM01 (PROFILE=baseline|secure)
	./scripts/switch_profile.sh $(PROFILE) && $(MAKE) -s reset && ./attacks/llm01_injection.sh

attack-llm02:  ## Ataque LLM02 (PROFILE=baseline|secure)
	./scripts/switch_profile.sh $(PROFILE) && $(MAKE) -s reset && : > logs/gateway.log && ./attacks/llm02_disclosure.sh

attack-llm07:  ## Ataque LLM07; en secure desactiva el sanitizador para aislar la guardia de salida
	@if [ "$(PROFILE)" = "secure" ]; then ./scripts/switch_profile.sh secure --no-sanitizer; else ./scripts/switch_profile.sh baseline; fi
	$(MAKE) -s reset && : > logs/gateway.log && ./attacks/llm07_leak.sh

attack-upstream:  ## Fallos upstream y circuit breaker (PROFILE=baseline|secure)
	./scripts/switch_profile.sh $(PROFILE) && $(MAKE) -s reset && ./attacks/upstream_failures.sh

attack-extra:  ## Casos complementarios TC-* de docs/CASOS_DE_PRUEBA.md (PROFILE=baseline|secure)
	./scripts/switch_profile.sh $(PROFILE) && $(MAKE) -s reset && ./attacks/casos_extra.sh

test-casos:  ## Solo los casos TC-* automatizados (antes/despues)
	$(PY) -m pytest -v -rxX tests/casos

demo-local:  ## Demo completa antes/despues SIN Docker (uvicorn local)
	./scripts/local_demo.sh

attacks-all:  ## Todas las demos, antes y despues
	@for c in llm10 llm01 llm02 llm07; do for p in baseline secure; do $(MAKE) -s attack-$$c PROFILE=$$p; done; done
	./scripts/switch_profile.sh secure

scan:  ## gitleaks sobre el historial git completo y sobre logs/
	gitleaks detect --source . --config .gitleaks.toml --log-opts="--all" --redact -v
	gitleaks detect --no-git --source logs/ --config .gitleaks.toml --redact -v

clean-logs:  ## Borra logs (obligatorio tras demos en baseline)
	: > logs/gateway.log
