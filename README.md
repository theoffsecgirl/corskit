<div align="center">

# corskit

**CORS misconfiguration tester — offensive web tool**

![Language](https://img.shields.io/badge/Python%20%2B%20HTML-CLI%20%2B%20Browser-9E4AFF?style=flat-square&logo=python&logoColor=white)
![Version](https://img.shields.io/badge/version-2.0.0-9E4AFF?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-9E4AFF?style=flat-square)
![Category](https://img.shields.io/badge/Category-Bug%20Bounty%20%7C%20Pentesting-111111?style=flat-square)

*by [theoffsecgirl](https://github.com/theoffsecgirl)*

> 🇪🇸 [Versión en español](README.es.md)

</div>

---

## What does it do?

Detects CORS misconfigurations in web endpoints. It has two parts:

- **`corskit` (CLI, Python)** — the scanner. Sends each generated `Origin` for real, plus a preflight `OPTIONS`, and classifies what the server accepts.
- **`cors_toolkit.html` (browser)** — PoC helper only. Browsers do not let a page set the `Origin` header (it is a forbidden header name): requests from the page always carry the page's real origin, so the HTML **cannot discover** misconfigurations. Use it to confirm exploitation from the origin the CLI reported.

---

## Features (CLI)

- Origins generated per target: arbitrary, `null`, prefix (`startswith`), suffix (`endswith`), unescaped-dot regex bypass (`apiXexample.com`), special chars (`..`, `%60`, `_`), subdomains, case, non-standard port, `https`→`http` downgrade
- Simple request + preflight `OPTIONS` (dangerous methods / sensitive headers allowed to the accepted origin)
- Severity based on **who controls the accepted origin**: attacker-registrable → `critical`/`high`; org subdomain (needs XSS/takeover) → `medium`/`low`; same host → `low`/`info`. The target's own legitimate origin is never reported
- Bug bounty ready: `-H` custom headers, `-c` cookies, `-x` proxy (Burp), `--rate` req/s limit, `--threads`
- Input: `-u` (repeatable), `-l` file or stdin
- Output: text, `--format json|jsonl`, `-o` file. Exit code `1` if any `high`/`critical`

---

## Installation

```bash
pipx install git+https://github.com/theoffsecgirl/corskit
# or
git clone https://github.com/theoffsecgirl/corskit.git && cd corskit && pip install -e .
```

---

## Usage

```bash
corskit -u https://api.target.com/v1/me -c "session=..." -H "X-Bugbounty: myuser" --rate 5
cat endpoints.txt | corskit --format jsonl -o cors.jsonl
corskit -u https://api.target.com/v1/me -x http://127.0.0.1:8080 -k   # through Burp
```

### PoC in the browser

Serve `cors_toolkit.html` **from the origin the CLI reported as accepted** and check that the authenticated response can be read.

---

## Files

- `corskit.py` — CLI scanner
- `cors_toolkit.html` — self-contained browser PoC helper

---

## Ethical use

For bug bounty, labs and authorized audits only.

---

## License

MIT · [theoffsecgirl](https://theoffsecgirl.com)
