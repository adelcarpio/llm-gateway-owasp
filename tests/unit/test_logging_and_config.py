import pytest

from app.config import Settings
from app.observability.secure_logger import AuditEvent, redact
from app.security.auth import ClientRegistry, hash_key


def test_audit_event_rejects_undeclared_fields():
    with pytest.raises(Exception):
        AuditEvent(request_id="r", route="/v1/chat", method="POST", status=200,
                   outcome="allowed", latency_ms=1, profile="secure",
                   prompt="dato sensible")  # campo no permitido


def test_redaction_masks_credentials():
    text = "Authorization: Bearer sk-ant-api03-abcdefghijklmnopqrstuvwxyz x-gateway-key: gk_secretvalue123"
    out = redact(text)
    assert "sk-ant" not in out and "gk_secretvalue123" not in out
    assert "[REDACTED]" in out


def test_secret_not_in_repr():
    s = Settings(_env_file=None, upstream_api_key="sk-ant-api03-supersecretvalue1234")
    assert "supersecret" not in repr(s) and "supersecret" not in str(s.model_dump())


def test_baseline_cannot_start_in_production():
    with pytest.raises(ValueError, match="produccion"):
        Settings(_env_file=None, environment="production", gateway_profile="baseline",
                 client_key_pepper="p")


def test_single_flag_disabled_blocks_production():
    with pytest.raises(ValueError):
        Settings(_env_file=None, environment="production", sec_sanitizer_enabled=False,
                 client_key_pepper="p")


def test_client_keys_are_hashed_and_pseudonymized():
    pepper, key = "pepper", "gk_test_key"
    s = Settings(_env_file=None, client_key_pepper=pepper,
                 client_key_hashes=f"app1:{hash_key(pepper, key)}")
    ident = ClientRegistry(s).authenticate(key)
    assert ident and ident.name == "app1" and ident.client_id.startswith("cli_")
    assert ClientRegistry(s).authenticate("otra") is None
