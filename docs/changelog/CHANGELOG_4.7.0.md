## 4.7.0 — web-hardening auditors, network & scheduling helpers
- **`/csp`** audits a Content-Security-Policy (unsafe-inline/eval, wildcards, JSONP-prone hosts, missing object-src/base-uri/frame-ancestors/form-action) with a 0–100 score and A–F grade.
- **`/cookie`** audits a `Set-Cookie` line (Secure, HttpOnly, SameSite, `__Host-`/`__Secure-` prefix rules, lifetime, Domain scope). The cookie value is never echoed or stored.
- **`/secheaders`** grades a pasted HTTP response header block: HSTS, CSP, nosniff, framing, Referrer/Permissions/COOP/CORP, CORS misconfigurations, version leaks, weak cookies.
- **`/subnet`** CIDR calculator (IPv4/IPv6, netmask form, wildcard, range, usable hosts) with splitting: `/subnet 10.0.0.0/24 /26`.
- **`/cron`** explains a 5-field cron expression or `@macro` and lists the next runs (UTC), with standard day-of-month/day-of-week OR semantics.
- All five are offline, rate-limited, available as menu buttons (🧮 Extra tools), accept the replied-to message, and run on the public `/t` web page and the panel tools page.
- Tests: +30 (`tests/test_v470.py`).

