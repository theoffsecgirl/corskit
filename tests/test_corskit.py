import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import corskit  # noqa: E402

TARGET = "https://api.example.com/v1/me"


# --- Backends simulados: politica CORS -> cabeceras de respuesta ---

def reflect_all(origin):
    return {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"}


def allowlist_exact(origin):
    return reflect_all(origin) if origin == "https://api.example.com" else {}


def regex_unescaped_dot(origin):
    # Bug clasico: /^https:\/\/api.example.com$/ con el punto sin escapar
    return reflect_all(origin) if re.match(r"^https://api.example.com$", origin) else {}


def endswith_base(origin):
    return reflect_all(origin) if origin.endswith("example.com") else {}


def startswith_host(origin):
    return reflect_all(origin) if origin.startswith("https://api.example.com") else {}


def subdomains_only(origin):
    return reflect_all(origin) if re.match(r"^https://[a-z0-9-]+\.example\.com$", origin) else {}


def run_policy(policy):
    out = []
    for case in corskit.generate_origins(TARGET):
        out += corskit.analyze(TARGET, case, policy(case.origin), 200, "simple")
    return out


def techniques(findings, severity=None):
    return {f.technique for f in findings if severity is None or f.severity == severity}


def test_legit_origin_not_generated_nor_flagged():
    origins = [c.origin for c in corskit.generate_origins(TARGET)]
    assert "https://api.example.com" not in origins
    assert run_policy(allowlist_exact) == []


def test_reflect_all_is_critical():
    f = run_policy(reflect_all)
    assert "origin arbitrario" in techniques(f, "critical")
    assert "origin null" in techniques(f, "critical")


def test_unescaped_dot_bypass_detected():
    f = run_policy(regex_unescaped_dot)
    assert techniques(f, "critical") == {"punto sin escapar en regex"}


def test_endswith_bypass_detected():
    f = run_policy(endswith_base)
    assert "sufijo sin punto (endswith)" in techniques(f, "critical")


def test_startswith_bypass_detected():
    f = run_policy(startswith_host)
    assert "prefijo (startswith)" in techniques(f, "critical")


def test_subdomain_trust_is_medium_not_critical():
    f = run_policy(subdomains_only)
    assert f and all(x.severity == "medium" for x in f)
    assert all(x.kind == "subdomain" for x in f)


def test_wildcard_without_creds_is_not_a_finding():
    case = corskit.OriginCase("https://evil.com", "attacker", "origin arbitrario")
    assert corskit.analyze(TARGET, case, {"Access-Control-Allow-Origin": "*"}, 200, "simple") == []


def test_preflight_dangerous_methods():
    case = corskit.OriginCase("https://evil.com", "attacker", "origin arbitrario")
    hdrs = {"Access-Control-Allow-Origin": "https://evil.com", "Access-Control-Allow-Methods": "GET, PUT, DELETE"}
    f = corskit.analyze(TARGET, case, hdrs, 204, "preflight")
    assert any(x.extra.get("methods") == ["DELETE", "PUT"] for x in f)


# --- Integracion: comprueba que el Origin y las cabeceras extra llegan de verdad ---

@pytest.fixture()
def server():
    seen = []

    class H(BaseHTTPRequestHandler):
        def _reply(self):
            seen.append(dict(self.headers))
            origin = self.headers.get("Origin", "")
            self.send_response(204 if self.command == "OPTIONS" else 200)
            if origin == "http://evil.com":
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()

        do_GET = do_OPTIONS = _reply

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}/api", seen
    srv.shutdown()


def test_cli_end_to_end(server, capsys):
    url, seen = server
    code = corskit.main(["-u", url, "-H", "X-Bugbounty: theoffsecgirl", "--format", "jsonl", "--threads", "1"])
    assert code == 1  # hay hallazgo high/critical
    sent = {h.get("Origin") for h in seen}
    assert "http://evil.com" in sent and "null" in sent
    assert all(h.get("X-Bugbounty") == "theoffsecgirl" for h in seen)
    assert any(h.get("Access-Control-Request-Method") == "PUT" for h in seen)
    out = capsys.readouterr().out
    assert '"severity": "critical"' in out and '"origin": "http://evil.com"' in out
