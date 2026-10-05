"""Genera .env, .env.profile y .demo_keys (todos gitignored) para la demo local.

- Pepper aleatorio y dos keys de cliente; en .env solo se guardan sus HMAC.
- Las keys en claro van a .demo_keys (para exportarlas en la terminal de demo).
- UPSTREAM_API_KEY es FICTICIA con formato realista: el mock no la valida y
  permite que gitleaks la detecte en la linea base (demo LLM02).
"""
from __future__ import annotations

import secrets
import string
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.security.auth import hash_key  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def main(force: bool) -> None:
    env, keys_file, profile = ROOT / ".env", ROOT / ".demo_keys", ROOT / ".env.profile"
    if env.exists() and not force:
        print(".env ya existe. Usa `python scripts/bootstrap_env.py --force` para regenerarlo.")
        return
    pepper = secrets.token_hex(32)
    key_a, key_b = "gk_" + secrets.token_urlsafe(32), "gk_" + secrets.token_urlsafe(32)
    alphabet = string.ascii_letters + string.digits
    fake_upstream = "sk-ant-api03-" + "".join(secrets.choice(alphabet) for _ in range(93)) + "AA"
    template = (ROOT / ".env.example").read_text()
    lines = []
    for line in template.splitlines():
        key = line.split("=", 1)[0]
        if key == "CLIENT_KEY_PEPPER":
            line = f"CLIENT_KEY_PEPPER={pepper}"
        elif key == "CLIENT_KEY_HASHES":
            line = f"CLIENT_KEY_HASHES=cliente_a:{hash_key(pepper, key_a)},cliente_b:{hash_key(pepper, key_b)}"
        elif key == "UPSTREAM_API_KEY":
            line = f"UPSTREAM_API_KEY={fake_upstream}"
        lines.append(line)
    env.write_text("\n".join(lines) + "\n")
    keys_file.write_text(f"export DEMO_CLIENT_KEY_A={key_a}\nexport DEMO_CLIENT_KEY_B={key_b}\n")
    profile.write_text("GATEWAY_PROFILE=secure\n")
    for f in (env, keys_file, profile):
        f.chmod(0o600)
    print("Generados .env, .env.profile y .demo_keys (gitignored). Ejecuta: source .demo_keys")


if __name__ == "__main__":
    main(force="--force" in sys.argv)
