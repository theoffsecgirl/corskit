<div align="center">

# corskit

**CORS misconfiguration tester — herramienta web ofensiva**

![Language](https://img.shields.io/badge/Python%20%2B%20HTML-CLI%20%2B%20Browser-9E4AFF?style=flat-square&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/version-2.0.0-9E4AFF?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-9E4AFF?style=flat-square)
![Category](https://img.shields.io/badge/Category-Bug%20Bounty%20%7C%20Pentesting-111111?style=flat-square)

*by [theoffsecgirl](https://github.com/theoffsecgirl)*

> 🇬🇧 [English version](README.md)

</div>

---

## ¿Qué hace?

Detecta misconfiguraciones CORS en endpoints web. Tiene dos partes:

- **`corskit` (CLI, Python)** — el escáner. Envía de verdad cada `Origin` generado, más un preflight `OPTIONS`, y clasifica lo que acepta el servidor.
- **`cors_toolkit.html` (navegador)** — solo para la PoC. Los navegadores no dejan que una página fije la cabecera `Origin` (es una *forbidden header name*): las peticiones salen siempre con el origin real de la página, así que el HTML **no puede descubrir** misconfiguraciones. Úsalo para confirmar la explotación desde el origin que reportó la CLI.

---

## Funcionalidades (CLI)

- Origins generados por objetivo: arbitrario, `null`, prefijo (`startswith`), sufijo (`endswith`), punto sin escapar en regex (`apiXexample.com`), caracteres especiales (`..`, `%60`, `_`), subdominios, capitalización, puerto no estándar, downgrade `https`→`http`
- Petición simple + preflight `OPTIONS` (métodos peligrosos / cabeceras sensibles permitidas al origin aceptado)
- Severidad según **quién controla el origin aceptado**: registrable por un atacante → `critical`/`high`; subdominio de la organización (requiere XSS/takeover) → `medium`/`low`; mismo host → `low`/`info`. El origin legítimo del propio objetivo nunca se reporta
- Lista para bug bounty: `-H` cabeceras propias, `-c` cookies, `-x` proxy (Burp), `--rate` límite de peticiones/s, `--threads`
- Entrada: `-u` (repetible), `-l` fichero o stdin
- Salida: texto, `--format json|jsonl`, `-o` fichero. Código de salida `1` si hay algún `high`/`critical`

---

## Instalación

```bash
pipx install git+https://github.com/theoffsecgirl/corskit
# o
git clone https://github.com/theoffsecgirl/corskit.git && cd corskit && pip install -e .
```

---

## Uso

```bash
corskit -u https://api.target.com/v1/me -c "session=..." -H "X-Bugbounty: miusuario" --rate 5
cat endpoints.txt | corskit --format jsonl -o cors.jsonl
corskit -u https://api.target.com/v1/me -x http://127.0.0.1:8080 -k   # a través de Burp
```

### PoC en el navegador

Sirve `cors_toolkit.html` **desde el origin que la CLI reportó como aceptado** y comprueba que puedes leer la respuesta autenticada.

---

## Archivos

- `corskit.py` — escáner CLI
- `cors_toolkit.html` — página autocontenida para la PoC

---

## Uso ético

Solo para bug bounty, laboratorios y auditorías autorizadas.

---

## Licencia

MIT · [theoffsecgirl](https://theoffsecgirl.com)
