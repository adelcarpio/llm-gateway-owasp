"""LLM02 Sensitive Information Disclosure: credenciales y datos en logs, trazas y repositorio."""
import re
import subprocess
from pathlib import Path

from mock_upstream.app import STATE as MOCK
from tests.conftest import FAKE_UPSTREAM_KEY, chat_body

ROOT = Path(__file__).resolve().parents[2]
SECRET_RE = re.compile(r"sk-ant-api03-[A-Za-z0-9_\-]{93}AA|sk-[A-Za-z0-9]{32,}")
PII_PROMPT = "Mi DNI es 40123456, revisa mi contrato"


async def _run(gw, keys, mode):
    MOCK["mode"] = mode
    return await gw.post("/v1/chat", json=chat_body(PII_PROMPT), headers={"X-Gateway-Key": keys["A"]})


async def test_baseline_leaks_credentials_traces_and_pii(gateway_factory, keys, evidence):
    gw = await gateway_factory("baseline")
    ok = await _run(gw, keys, "ok")
    err = await _run(gw, keys, "401")
    log = gw.log_file.read_text()
    findings = {"trace_in_response": "Traceback" in err.text,
                "upstream_host_in_response": "mock-upstream" in err.text,
                "credential_in_log": FAKE_UPSTREAM_KEY in log,
                "client_key_in_log": keys["A"] in log,
                "pii_in_log": "40123456" in log}
    evidence("LLM02", "baseline", {"ok_status": ok.status_code, "error_status": err.status_code,
                                   **findings})
    assert err.status_code == 500
    assert all(findings.values())                     # la linea base filtra todo


async def test_secure_leaks_nothing(gateway_factory, keys, evidence):
    gw = await gateway_factory("secure")
    ok = await _run(gw, keys, "ok")
    err = await _run(gw, keys, "401")
    log = gw.log_file.read_text()
    findings = {"trace_in_response": "Traceback" in err.text,
                "upstream_host_in_response": "mock-upstream" in err.text,
                "credential_in_log": bool(SECRET_RE.search(log)),
                "client_key_in_log": keys["A"] in log,
                "pii_in_log": "40123456" in log}
    evidence("LLM02", "secure", {"ok_status": ok.status_code, "error_status": err.status_code,
                                 "error_body": err.json(), **findings,
                                 "operator_alert_logged": "ALERTA" in log})
    assert ok.status_code == 200
    assert err.status_code == 502 and err.json()["code"] == "UPSTREAM_UNAVAILABLE"
    assert err.headers["content-type"].startswith("application/problem+json")
    assert not any(findings.values())
    assert "ALERTA" in log                            # el operador si se entera


def test_no_secrets_in_tracked_source():
    """Equivalente local de gitleaks: todo lo que se versionaria (respeta .gitignore)."""
    try:
        files = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"], cwd=ROOT, capture_output=True,
                               text=True, check=True).stdout.split()
    except (subprocess.CalledProcessError, FileNotFoundError):
        files = [str(p.relative_to(ROOT)) for p in ROOT.rglob("*")
                 if p.is_file() and not p.name.startswith((".env", ".demo_keys"))
                 and not any(x in p.parts for x in (".git", "logs", "evidence", ".venv", "__pycache__", ".pytest_cache"))]
    offenders = [f for f in files if (ROOT / f).is_file()
                 and SECRET_RE.search((ROOT / f).read_text(errors="ignore"))]
    assert offenders == []
