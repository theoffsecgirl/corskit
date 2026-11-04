#!/usr/bin/env python3
"""corskit - escaner CLI de misconfiguraciones CORS.

Por que una CLI y no solo el HTML: los navegadores NO permiten fijar la
cabecera `Origin` (ni `Access-Control-Request-*`) desde fetch()/XHR. Son
"forbidden header names": el navegador las descarta en silencio y envia el
origin real de la pagina. Desde cors_toolkit.html, por tanto, los origins
generados nunca llegan al servidor. Aqui si: requests envia el Origin que
elegimos.

Logica de origins y analisis portada de cors_toolkit.html, con dos cambios:
  - El reflejo del origin legitimo del propio target no es un hallazgo.
  - La severidad depende de quien controla el origin aceptado (atacante,
    subdominio de la organizacion, mismo host).

Usalo solo contra objetivos en scope / con autorizacion.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from urllib.parse import urlparse

import requests

__version__ = "2.0.0"

DANGEROUS_METHODS = {"DELETE", "PUT", "PATCH", "CONNECT", "TRACE"}
SENSITIVE_HEADERS = ("authorization", "x-api-key", "x-auth-token", "cookie", "x-csrf-token")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Clases de origin -> severidad (con credenciales, sin credenciales).
#   attacker  : dominio que un atacante puede registrar o controlar.
#   null      : explotable desde iframe sandbox / data: / file:.
#   subdomain : subdominio de la organizacion; requiere XSS o takeover en el.
#   downgrade : mismo host por http; requiere posicion de red (MITM).
#   same_host : mismo host con otro puerto o capitalizacion; validacion laxa,
#               normalmente no explotable por si sola.
SEVERITY_BY_KIND = {
    "attacker": ("critical", "high"),
    "null": ("critical", "high"),
    "subdomain": ("medium", "low"),
    "downgrade": ("medium", "low"),
    "same_host": ("low", "info"),
}


@dataclass
class OriginCase:
    origin: str
    kind: str
    technique: str


@dataclass
class Finding:
    url: str
    origin: str
    technique: str
    kind: str
    check: str  # "simple" | "preflight"
    severity: str
    title: str
    status: int
    acao: str
    acac: str
    extra: dict = field(default_factory=dict)


def target_origin(url: str) -> str:
    p = urlparse(url)
    default = {"http": 80, "https": 443}.get(p.scheme)
    port = f":{p.port}" if p.port and p.port != default else ""
    return f"{p.scheme}://{p.hostname}{port}"


def generate_origins(url: str) -> list[OriginCase]:
    p = urlparse(url)
    host = p.hostname or ""
    proto = p.scheme or "https"
    parts = host.split(".")
    base = ".".join(parts[-2:]) if len(parts) >= 2 else host

    cases = [
        OriginCase(f"{proto}://evil.com", "attacker", "origin arbitrario"),
        OriginCase("null", "null", "origin null"),
        OriginCase(f"{proto}://{host}.attacker.com", "attacker", "prefijo (startswith)"),
        OriginCase(f"{proto}://attacker{base}", "attacker", "sufijo sin punto (endswith)"),
        OriginCase(f"{proto}://{host}..attacker.com", "attacker", "caracter especial (..)"),
        OriginCase(f"{proto}://{host}%60.attacker.com", "attacker", "caracter especial (%60)"),
        OriginCase(f"{proto}://{host}_.attacker.com", "attacker", "caracter especial (_)"),
        OriginCase(f"{proto}://sub.{host}", "subdomain", "subdominio arbitrario"),
    ]
    if base != host:
        cases.append(OriginCase(f"{proto}://attacker.{base}", "subdomain", "subdominio del dominio base"))
    # Punto sin escapar en el regex de validacion: /^api.example.com$/ acepta apiXexample.com,
    # un dominio registrable por cualquiera.
    if len(parts) >= 2:
        dotless = f"{parts[0]}X{'.'.join(parts[1:])}"
        cases.append(OriginCase(f"{proto}://{dotless}", "attacker", "punto sin escapar en regex"))
    case_variant = host[:1].upper() + host[1:]
    if case_variant != host:
        cases.append(OriginCase(f"{proto}://{case_variant}", "same_host", "capitalizacion distinta"))
    cases.append(OriginCase(f"{proto}://{host}:8443", "same_host", "puerto no estandar"))
    if proto == "https":
        cases.append(OriginCase(f"http://{host}", "downgrade", "downgrade a http"))

    legit = target_origin(url).lower()
    seen: set[str] = set()
    out = []
    for c in cases:
        if c.origin.lower() == legit or c.origin in seen:
            continue
        seen.add(c.origin)
        out.append(c)
    return out


def _accepted(acao: str, origin: str) -> bool:
    if origin == "null":
        return acao == "null"
    return acao == origin


def analyze(url: str, case: OriginCase, resp_headers: dict, status: int, check: str) -> list[Finding]:
    h = {k.lower(): v for k, v in resp_headers.items()}
    acao = h.get("access-control-allow-origin", "").strip()
    acac = h.get("access-control-allow-credentials", "").strip()
    creds = acac.lower() == "true"
    findings: list[Finding] = []

    def add(sev: str, title: str, **extra) -> None:
        findings.append(
            Finding(url, case.origin, case.technique, case.kind, check, sev, title, status, acao, acac, extra)
        )

    if _accepted(acao, case.origin):
        sev = SEVERITY_BY_KIND[case.kind][0 if creds else 1]
        title = f"Origin aceptado ({case.technique})" + (" + credenciales" if creds else "")
        add(sev, title)

        if check == "preflight":
            acam = h.get("access-control-allow-methods", "")
            acah = h.get("access-control-allow-headers", "")
            dangerous = sorted({m.strip().upper() for m in acam.split(",")} & DANGEROUS_METHODS)
            if dangerous:
                add(sev, "Metodos peligrosos permitidos al origin aceptado", methods=dangerous)
            sensitive = [x.strip() for x in acah.lower().split(",") if any(s in x for s in SENSITIVE_HEADERS)]
            if sensitive or acah.strip() == "*":
                add(sev, "Cabeceras sensibles permitidas al origin aceptado", headers=sensitive or ["*"])
    elif acao == "*" and creds:
        # Los navegadores rechazan esta combinacion: no es explotable, pero indica config rota.
        add("info", "ACAO * con credenciales (config rota, el navegador la rechaza)")
    return findings


class Scanner:
    def __init__(self, headers: dict, proxy: str | None, timeout: int, delay: float, verify: bool):
        self.base_headers = headers
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.timeout = timeout
        self.delay = delay
        self.verify = verify
        self._lock = threading.Lock()
        self._last = 0.0
        self._local = threading.local()

    def _session(self) -> requests.Session:
        s = getattr(self._local, "s", None)
        if s is None:
            s = requests.Session()
            s.headers.update({"User-Agent": f"corskit/{__version__} (+https://github.com/theoffsecgirl/corskit)"})
            s.headers.update(self.base_headers)
            self._local.s = s
        return s

    def _throttle(self) -> None:
        if self.delay <= 0:
            return
        with self._lock:
            wait = self._last + self.delay - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()

    def _send(self, method: str, url: str, headers: dict) -> requests.Response | None:
        self._throttle()
        try:
            return self._session().request(
                method, url, headers=headers, timeout=self.timeout,
                proxies=self.proxies, verify=self.verify, allow_redirects=False,
            )
        except requests.RequestException as e:
            log(f"[x] {method} {url} ({headers.get('Origin')}): {e}")
            return None

    def scan_url(self, url: str, method: str, preflight: bool) -> list[Finding]:
        findings: list[Finding] = []
        for case in generate_origins(url):
            r = self._send(method, url, {"Origin": case.origin})
            if r is not None:
                findings += analyze(url, case, r.headers, r.status_code, "simple")
            if preflight:
                r = self._send("OPTIONS", url, {
                    "Origin": case.origin,
                    "Access-Control-Request-Method": "PUT",
                    "Access-Control-Request-Headers": "authorization,content-type",
                })
                if r is not None:
                    findings += analyze(url, case, r.headers, r.status_code, "preflight")
        return findings


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


def parse_header(raw: str) -> tuple[str, str]:
    if ":" not in raw:
        raise argparse.ArgumentTypeError(f"cabecera invalida (usa 'Nombre: valor'): {raw}")
    k, v = raw.split(":", 1)
    return k.strip(), v.strip()


def load_targets(args: argparse.Namespace) -> list[str]:
    targets = list(args.url or [])
    if args.list:
        with open(args.list, encoding="utf-8") as f:
            targets += [line.strip() for line in f if line.strip() and not line.startswith("#")]
    if not targets and not sys.stdin.isatty():
        targets += [line.strip() for line in sys.stdin if line.strip()]
    norm = []
    for t in targets:
        if not t.startswith(("http://", "https://")):
            t = "https://" + t
        norm.append(t)
    return list(dict.fromkeys(norm))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="corskit", description="Escaner CLI de misconfiguraciones CORS")
    p.add_argument("-u", "--url", action="append", help="URL objetivo (repetible)")
    p.add_argument("-l", "--list", help="Fichero con URLs (una por linea). Tambien acepta stdin")
    p.add_argument("-m", "--method", default="GET", help="Metodo de la peticion simple (default: GET)")
    p.add_argument("-H", "--header", action="append", type=parse_header, default=[],
                   help="Cabecera extra, repetible (ej: 'Authorization: Bearer x', 'X-Bugbounty: user')")
    p.add_argument("-c", "--cookie", help="Cookies para endpoints autenticados ('a=1; b=2')")
    p.add_argument("-x", "--proxy", help="Proxy HTTP(S), ej: http://127.0.0.1:8080 (Burp)")
    p.add_argument("-k", "--insecure", action="store_true", help="No verificar TLS (util con Burp)")
    p.add_argument("--no-preflight", action="store_true", help="No probar preflight OPTIONS")
    p.add_argument("-t", "--timeout", type=int, default=10, help="Timeout por peticion en segundos (default: 10)")
    p.add_argument("--threads", type=int, default=5, help="URLs en paralelo (default: 5)")
    p.add_argument("--rate", type=float, default=0, help="Maximo de peticiones/segundo en total (default: sin limite)")
    p.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="low",
                   help="Severidad minima a mostrar (default: low)")
    p.add_argument("--format", choices=["text", "json", "jsonl"], default="text")
    p.add_argument("-o", "--output", help="Guardar resultados en fichero (formato de --format)")
    p.add_argument("-V", "--version", action="version", version=f"corskit {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    targets = load_targets(args)
    if not targets:
        log("[x] Sin objetivos: usa -u, -l o stdin")
        return 2

    headers = dict(args.header)
    if args.cookie:
        headers["Cookie"] = args.cookie
    if args.insecure:
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
    scanner = Scanner(headers, args.proxy, args.timeout, 1 / args.rate if args.rate > 0 else 0, not args.insecure)

    log(f"[+] corskit {__version__} - {len(targets)} objetivo(s)")
    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as pool:
        results = list(pool.map(lambda u: scanner.scan_url(u, args.method.upper(), not args.no_preflight), targets))

    min_sev = SEVERITY_ORDER[args.min_severity]
    findings = [f for fs in results for f in fs if SEVERITY_ORDER[f.severity] >= min_sev]
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.url, f.check))

    if args.format == "json":
        out = json.dumps({"tool": "corskit", "version": __version__, "targets": targets,
                          "findings": [asdict(f) for f in findings]}, indent=2, ensure_ascii=False)
    elif args.format == "jsonl":
        out = "\n".join(json.dumps({"tool": "corskit", **asdict(f)}, ensure_ascii=False) for f in findings)
    else:
        lines = [f"[{f.severity.upper():8}] {f.url}  [{f.check}]  Origin: {f.origin}\n"
                 f"           {f.title} | ACAO: {f.acao or '-'} | ACAC: {f.acac or '-'}" for f in findings]
        out = "\n".join(lines) if lines else "Sin misconfiguraciones con la severidad minima indicada."

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
        log(f"[+] Resultados guardados en {args.output}")
    else:
        print(out)

    log(f"[+] {len(findings)} hallazgo(s)")
    return 1 if any(SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER["high"] for f in findings) else 0


def main_entry() -> None:
    sys.exit(main())


if __name__ == "__main__":
    main_entry()
