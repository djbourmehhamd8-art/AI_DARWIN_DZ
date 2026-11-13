"""Defensive network intelligence: DNS (DoH), domain age (RDAP), TLS certificate, HTTP security headers and a public
handle footprint check. Every target is validated; connections only go to PUBLIC addresses (pinned to the validated IP);
only public, non-personal metadata is read. Nothing here scans ports or probes for vulnerabilities."""
from __future__ import annotations

import re
import socket
import ssl
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import requests

from . import websearch

UA = "Mozilla/5.0 (compatible; DarwinBot/4.2; defensive-security)"
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
TYPES = {"A": 1, "NS": 2, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}


# ====================================================================================== validation
def valid_domain(text: str):
    """Return a clean lowercase (punycode) domain, or None. Accepts a URL or a bare domain; rejects IPs and localhost."""
    s = (text or "").strip().lower()
    if "://" in s:
        s = urllib.parse.urlsplit(s).hostname or ""
    s = s.split("/")[0].split("?")[0].split("#")[0].rstrip(".")
    if not s or len(s) > 253 or s in ("localhost",) or re.fullmatch(r"[\d.]+", s) or ":" in s:
        return None
    try:
        s = s.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = s.split(".")
    if len(labels) < 2 or not all(_LABEL.match(x) for x in labels) or not re.fullmatch(r"[a-z]{2,63}|xn--[a-z0-9-]{2,59}", labels[-1]):
        return None
    return s


def valid_username(text: str):
    """Public handle only: letters, digits, dot, underscore, hyphen, 3-32 chars. No emails, phones or numeric-only IDs."""
    s = (text or "").strip().lstrip("@")
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,32}", s) or s.isdigit() or re.fullmatch(r"[\d._-]+", s):
        return None
    return s


# ====================================================================================== DNS over HTTPS
def doh(name: str, rtype: str, http=requests, timeout: float = 6) -> list:
    r = http.get("https://cloudflare-dns.com/dns-query", params={"name": name, "type": rtype},
                 headers={"accept": "application/dns-json", "User-Agent": UA}, timeout=timeout)
    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code}")
    want = TYPES[rtype]
    return [a.get("data", "") for a in (r.json().get("Answer") or []) if a.get("type") == want]


def dns_report(domain: str, http=requests) -> dict:
    jobs = [(domain, t) for t in ("A", "AAAA", "MX", "NS", "TXT", "CAA")] + [(f"_dmarc.{domain}", "TXT")]

    def one(job):
        try:
            return doh(job[0], job[1], http)
        except Exception as e:                                       # noqa: BLE001 - report the gap, never crash
            return [f"(error: {type(e).__name__})"]
    with ThreadPoolExecutor(max_workers=7) as ex:
        res = list(ex.map(one, jobs))
    rec = {t: res[i] for i, (_, t) in enumerate(jobs[:6])}
    dmarc_txt = [x.strip('"') for x in res[6]]
    spf = [x.strip('"') for x in rec["TXT"] if "v=spf1" in x.lower()]
    dmarc = [x for x in dmarc_txt if x.lower().startswith("v=dmarc1")]
    findings = []
    if not spf:
        findings.append(("high", "no_spf"))
    elif spf[0].rstrip().endswith("+all") or spf[0].rstrip().endswith(" all"):
        findings.append(("high", "spf_open"))
    elif spf[0].rstrip().endswith("?all"):
        findings.append(("medium", "spf_neutral"))
    elif spf[0].rstrip().endswith("~all"):
        findings.append(("low", "spf_soft"))
    if not dmarc:
        findings.append(("high", "no_dmarc"))
    else:
        m = re.search(r"\bp=(\w+)", dmarc[0], re.I)
        pol = (m.group(1).lower() if m else "none")
        if pol == "none":
            findings.append(("medium", "dmarc_none"))
    if not rec["CAA"] or rec["CAA"][0].startswith("(error"):
        findings.append(("low", "no_caa"))
    if not rec["MX"] and not rec["A"] and not rec["AAAA"]:
        findings.append(("info", "no_records"))
    return {"records": rec, "spf": spf, "dmarc": dmarc, "findings": findings}


# ====================================================================================== RDAP (domain age)
def rdap_domain(domain: str, http=requests, timeout: float = 8, now=None) -> dict:
    url = f"https://rdap.org/domain/{domain}"
    for _ in range(4):                                                # follow the bootstrap redirect by hand, https only
        if not websearch.is_safe_url(url) or not url.startswith("https://"):
            return {"ok": False, "error": "blocked"}
        r = http.get(url, headers={"Accept": "application/rdap+json", "User-Agent": UA}, timeout=timeout, allow_redirects=False)
        if r.status_code in (301, 302, 303, 307, 308):
            url = urllib.parse.urljoin(url, r.headers.get("Location", ""))
            continue
        break
    else:
        return {"ok": False, "error": "too many redirects"}
    if r.status_code == 404:
        return {"ok": False, "error": "not_found"}
    if r.status_code != 200:
        return {"ok": False, "error": f"HTTP {r.status_code}"}
    j = r.json()
    ev = {e.get("eventAction"): e.get("eventDate") for e in j.get("events", [])}

    def ts(x):
        try:
            return datetime.fromisoformat(x.replace("Z", "+00:00")).timestamp()
        except (ValueError, AttributeError):
            return None
    created, expires, changed = ts(ev.get("registration")), ts(ev.get("expiration")), ts(ev.get("last changed"))
    registrar = ""
    for ent in j.get("entities", []):
        if "registrar" in ent.get("roles", []):
            for item in (ent.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "fn":
                    registrar = str(item[3])
    clock = now or time.time()
    out = {"ok": True, "registrar": registrar, "status": j.get("status", []), "created": created, "expires": expires,
           "changed": changed, "nameservers": [n.get("ldhName", "").lower() for n in j.get("nameservers", [])][:6],
           "age_days": int((clock - created) // 86400) if created else None,
           "expires_in": int((expires - clock) // 86400) if expires else None}
    flags = []
    if out["age_days"] is not None and out["age_days"] < 30:
        flags.append(("high", "very_new"))
    elif out["age_days"] is not None and out["age_days"] < 180:
        flags.append(("medium", "new"))
    if out["expires_in"] is not None and 0 <= out["expires_in"] < 30:
        flags.append(("medium", "expiring"))
    out["flags"] = flags
    return out


# ====================================================================================== TLS certificate
def tls_info(domain: str, resolve=websearch.resolve_public, connect=socket.create_connection, timeout: float = 6, now=None) -> dict:
    ip = resolve(domain)
    if not ip:
        return {"ok": False, "error": "unresolvable_or_private"}
    ctx = ssl.create_default_context()
    try:
        with connect((ip, 443), timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as s:
                cert, proto, cipher = s.getpeercert(), s.version(), s.cipher()
    except ssl.SSLCertVerificationError as e:
        return {"ok": False, "error": "verify_failed", "detail": getattr(e, "verify_message", str(e))}
    except (OSError, ssl.SSLError) as e:
        return {"ok": False, "error": "connect_failed", "detail": type(e).__name__}
    clock = now or time.time()

    def name(rdn):
        return {k: v for t in rdn for k, v in t}
    subj, iss = name(cert.get("subject", ())), name(cert.get("issuer", ()))
    not_after = ssl.cert_time_to_seconds(cert["notAfter"])
    not_before = ssl.cert_time_to_seconds(cert["notBefore"])
    days = int((not_after - clock) // 86400)
    san = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    flags = []
    if days < 0:
        flags.append(("high", "expired"))
    elif days < 14:
        flags.append(("high", "expiring_soon"))
    elif days < 30:
        flags.append(("medium", "expiring"))
    if proto in ("TLSv1", "TLSv1.1"):
        flags.append(("high", "old_tls"))
    if any(x.startswith("*.") for x in san):
        flags.append(("info", "wildcard"))
    return {"ok": True, "cn": subj.get("commonName", ""), "issuer": iss.get("organizationName") or iss.get("commonName", ""),
            "not_before": not_before, "not_after": not_after, "days_left": days, "san": san[:12], "san_count": len(san),
            "protocol": proto, "cipher": cipher[0] if cipher else "", "flags": flags}


# ====================================================================================== HTTP security headers
def _fetch_headers(url: str, get=websearch.pinned_get, resolve=websearch.resolve_public, timeout: float = 8):
    for _ in range(4):
        p = urllib.parse.urlparse(url)
        if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password or p.port not in (None, 80, 443):
            return None
        ip = resolve(p.hostname)
        if not ip:
            return None
        r = get(url, ip=ip, headers={"User-Agent": UA, "Accept": "text/html,*/*"}, timeout=timeout)
        try:
            if r.status_code in (301, 302, 303, 307, 308):
                url = urllib.parse.urljoin(url, r.headers.get("Location", ""))
                continue
            raw = getattr(getattr(r, "raw", None), "headers", None)
            cookies = raw.get_all("Set-Cookie") if raw is not None and hasattr(raw, "get_all") else \
                ([r.headers["Set-Cookie"]] if "Set-Cookie" in r.headers else [])
            return {"url": url, "status": r.status_code, "headers": {k.lower(): v for k, v in r.headers.items()}, "cookies": cookies or []}
        finally:
            r.close()
    return None


def sec_headers(url: str, **kw) -> dict:
    if "://" not in url:
        url = "https://" + url.strip()
    res = _fetch_headers(url, **kw)
    if not res:
        return {"ok": False, "error": "unreachable_or_blocked"}
    h, https = res["headers"], res["url"].startswith("https://")
    checks = []                                                       # (key, ok, weight)

    def add(key, ok, weight):
        checks.append((key, bool(ok), weight))
    add("hsts", (not https) or "strict-transport-security" in h, 2)
    csp = h.get("content-security-policy", "")
    add("csp", bool(csp), 3)
    add("frame", "x-frame-options" in h or "frame-ancestors" in csp, 1)
    add("nosniff", h.get("x-content-type-options", "").lower() == "nosniff", 1)
    add("referrer", "referrer-policy" in h, 1)
    add("permissions", "permissions-policy" in h, 1)
    leaks = []
    if re.search(r"\d", h.get("server", "")):
        leaks.append(f"Server: {h['server'][:60]}")
    if "x-powered-by" in h:
        leaks.append(f"X-Powered-By: {h['x-powered-by'][:60]}")
    bad_cookies = []
    for c in res["cookies"]:
        low = c.lower()
        flags = [f for f, ok in (("Secure", "secure" in low), ("HttpOnly", "httponly" in low), ("SameSite", "samesite" in low)) if not ok]
        if flags:
            bad_cookies.append(f"{c.split('=')[0][:30]}: missing {', '.join(flags)}")
    total = sum(w for _, _, w in checks)
    got = sum(w for _, ok, w in checks if ok) - min(2, len(leaks)) - min(2, len(bad_cookies))
    pct = max(0, got) / total
    grade = "A" if pct >= 0.9 else "B" if pct >= 0.75 else "C" if pct >= 0.55 else "D" if pct >= 0.35 else "F"
    return {"ok": True, "url": res["url"], "status": res["status"], "https": https, "checks": checks, "leaks": leaks,
            "cookies": bad_cookies, "grade": grade}


# ====================================================================================== public handle footprint
# (name, url template, profile url template, kind) — kinds define how "exists" is decided. Public existence only.
PLATFORMS = [
    ("GitHub", "https://api.github.com/users/{u}", "https://github.com/{u}", "status"),
    ("GitLab", "https://gitlab.com/api/v4/users?username={u}", "https://gitlab.com/{u}", "list"),
    ("Codeberg", "https://codeberg.org/api/v1/users/{u}", "https://codeberg.org/{u}", "status"),
    ("Keybase", "https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}", "https://keybase.io/{u}", "keybase"),
    ("Docker Hub", "https://hub.docker.com/v2/users/{u}/", "https://hub.docker.com/u/{u}", "status"),
    ("PyPI", "https://pypi.org/user/{u}/", "https://pypi.org/user/{u}/", "status"),
    ("npm", "https://registry.npmjs.org/-/user/org.couchdb.user:{u}", "https://www.npmjs.com/~{u}", "status"),
    ("Dev.to", "https://dev.to/api/users/by_username?url={u}", "https://dev.to/{u}", "status"),
    ("Hacker News", "https://hacker-news.firebaseio.com/v0/user/{u}.json", "https://news.ycombinator.com/user?id={u}", "hn"),
    ("Chess.com", "https://api.chess.com/pub/player/{u}", "https://www.chess.com/member/{u}", "status"),
    ("Lichess", "https://lichess.org/api/user/{u}", "https://lichess.org/@/{u}", "status"),
    ("Gravatar", "https://en.gravatar.com/{u}.json", "https://gravatar.com/{u}", "status"),
    ("Reddit", "https://www.reddit.com/user/{u}/about.json", "https://www.reddit.com/user/{u}", "status"),
    ("Mastodon.social", "https://mastodon.social/api/v1/accounts/lookup?acct={u}", "https://mastodon.social/@{u}", "status"),
    ("Bluesky", "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={u}.bsky.social", "https://bsky.app/profile/{u}.bsky.social", "status"),
    ("Wikipedia", "https://en.wikipedia.org/w/api.php?action=query&list=users&ususers={u}&format=json", "https://en.wikipedia.org/wiki/User:{u}", "wiki"),
    ("Pastebin", "https://pastebin.com/u/{u}", "https://pastebin.com/u/{u}", "status"),
    ("Medium", "https://medium.com/@{u}", "https://medium.com/@{u}", "status"),
    ("HackerOne", "https://hackerone.com/{u}", "https://hackerone.com/{u}", "status"),
]


def _judge(kind: str, r) -> str:
    code = r.status_code
    try:
        if kind == "status":
            return "found" if code == 200 else "missing" if code in (404, 410) else "unknown"
        if code != 200:
            return "missing" if code == 404 else "unknown"
        if kind == "list":
            return "found" if r.json() else "missing"
        if kind == "keybase":
            return "found" if (r.json().get("them") or [None])[0] else "missing"
        if kind == "hn":
            return "found" if r.text.strip() not in ("null", "") else "missing"
        if kind == "wiki":
            u = (r.json().get("query", {}).get("users") or [{}])[0]
            return "missing" if "missing" in u or "invalid" in u else "found"
    except ValueError:
        return "unknown"
    return "unknown"


def footprint(username: str, http=requests, timeout: float = 6) -> dict:
    """Check which well-known PUBLIC platforms have this handle. Reads only the HTTP status/existence — never bios,
    photos, followers or any personal content."""
    u = urllib.parse.quote(username, safe="._-")

    def one(p):
        name, probe, profile, kind = p
        try:
            r = http.get(probe.format(u=u), timeout=timeout, headers={"User-Agent": UA, "Accept": "application/json,text/html"},
                         allow_redirects=False)
            return name, profile.format(u=u), _judge(kind, r)
        except Exception:                                            # noqa: BLE001 - one site down never breaks the report
            return name, profile.format(u=u), "unknown"
    with ThreadPoolExecutor(max_workers=8) as ex:
        res = list(ex.map(one, PLATFORMS))
    return {"found": [(n, url) for n, url, s in res if s == "found"],
            "missing": [n for n, _, s in res if s == "missing"],
            "unknown": [n for n, _, s in res if s == "unknown"], "checked": len(res)}


# ====================================================================================== extra passive intelligence
import ipaddress as _ip      # noqa: E402


def public_ip(text: str):
    """A public IPv4/IPv6 address as a string, or None (private, loopback, link-local, reserved, malformed)."""
    try:
        ip = _ip.ip_address((text or "").strip().strip("[]"))
    except ValueError:
        return None
    return str(ip) if (ip.is_global and not ip.is_multicast) else None


def subdomains(domain: str, http=requests, timeout: float = 20) -> dict:
    """Passive subdomain discovery from certificate-transparency logs (crt.sh). Nothing is sent to the target."""
    try:
        r = http.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, headers={"User-Agent": UA}, timeout=timeout)
        if r.status_code != 200:
            return {"ok": False, "error": f"crt.sh HTTP {r.status_code}"}
        names = set()
        for row in r.json():
            for n in str(row.get("name_value", "")).lower().split("\n"):
                n = n.strip().lstrip("*.")
                if n.endswith("." + domain) or n == domain:
                    names.add(n)
        names.discard(domain)
        return {"ok": True, "names": sorted(names), "count": len(names)}
    except Exception as e:                                           # noqa: BLE001
        return {"ok": False, "error": type(e).__name__}


def asn_info(target: str, http=requests, timeout: float = 10) -> dict:
    """ASN, announced prefix, holder and abuse contact for an IP (RIPEstat)."""
    ip = public_ip(target)
    if not ip:
        return {"ok": False, "error": "not_public_ip"}
    try:
        o = http.get("https://stat.ripe.net/data/prefix-overview/data.json", params={"resource": ip}, headers={"User-Agent": UA}, timeout=timeout).json()["data"]
        asns = o.get("asns") or []
        out = {"ok": True, "ip": ip, "prefix": o.get("resource", ""), "announced": o.get("announced"),
               "asn": asns[0].get("asn") if asns else None, "holder": asns[0].get("holder", "") if asns else "", "abuse": []}
        try:
            a = http.get("https://stat.ripe.net/data/abuse-contact-finder/data.json", params={"resource": ip}, headers={"User-Agent": UA}, timeout=timeout).json()
            out["abuse"] = (a.get("data", {}).get("abuse_contacts") or [])[:2]
        except Exception:                                            # noqa: BLE001 - optional
            pass
        return out
    except Exception as e:                                           # noqa: BLE001
        return {"ok": False, "error": type(e).__name__}


def reverse_dns(ip: str, http=requests) -> dict:
    addr = public_ip(ip)
    if not addr:
        return {"ok": False, "error": "not_public_ip"}
    name = _ip.ip_address(addr).reverse_pointer
    try:
        r = http.get("https://cloudflare-dns.com/dns-query", params={"name": name, "type": "PTR"}, headers={"accept": "application/dns-json", "User-Agent": UA}, timeout=6)
        names = [a.get("data", "").rstrip(".") for a in (r.json().get("Answer") or []) if a.get("type") == 12]
        return {"ok": True, "ip": addr, "names": names}
    except Exception as e:                                           # noqa: BLE001
        return {"ok": False, "error": type(e).__name__}


def mac_vendor(mac: str, http=requests) -> dict:
    """Vendor of a MAC address. Only the 3-byte OUI prefix is sent to the lookup service, never the full address."""
    hexes = re.sub(r"[^0-9a-fA-F]", "", mac or "")
    if len(hexes) < 6 or len(hexes) > 12 or not re.fullmatch(r"[0-9a-fA-F:.\-]{6,17}", (mac or "").strip()):
        return {"ok": False, "error": "invalid"}
    oui = hexes[:6].upper()
    first = int(hexes[:2], 16)
    flags = {"random": bool(first & 0x02), "multicast": bool(first & 0x01)}
    try:
        r = http.get(f"https://api.macvendors.com/{oui}", headers={"User-Agent": UA}, timeout=6)
        if r.status_code == 404:
            return {"ok": True, "oui": oui, "vendor": "", **flags}
        if r.status_code != 200:
            return {"ok": False, "error": f"HTTP {r.status_code}", "oui": oui, **flags}
        return {"ok": True, "oui": oui, "vendor": r.text.strip()[:100], **flags}
    except Exception as e:                                           # noqa: BLE001
        return {"ok": False, "error": type(e).__name__, "oui": oui, **flags}


def exposure(target: str, http=requests, resolve_a=None) -> dict:
    """What the internet already knows about a PUBLIC address (Shodan InternetDB: open ports, hostnames, CPEs, known CVEs).
    Passive: no packet is sent to the target. Use it on your own assets."""
    ip = public_ip(target)
    if not ip and valid_domain(target):
        try:
            ips = (resolve_a or (lambda d: doh(d, "A", http)))(valid_domain(target))
            ip = next((public_ip(x) for x in ips if public_ip(x)), None)
        except Exception:                                            # noqa: BLE001
            ip = None
    if not ip:
        return {"ok": False, "error": "not_public"}
    try:
        r = http.get(f"https://internetdb.shodan.io/{ip}", headers={"User-Agent": UA}, timeout=10)
        if r.status_code == 404:
            return {"ok": True, "ip": ip, "known": False, "ports": [], "hostnames": [], "cpes": [], "vulns": [], "tags": []}
        if r.status_code != 200:
            return {"ok": False, "error": f"HTTP {r.status_code}"}
        j = r.json()
        return {"ok": True, "ip": ip, "known": True, "ports": sorted(j.get("ports", [])), "hostnames": j.get("hostnames", [])[:8],
                "cpes": j.get("cpes", [])[:8], "vulns": sorted(j.get("vulns", []))[:20], "tags": j.get("tags", [])}
    except Exception as e:                                           # noqa: BLE001
        return {"ok": False, "error": type(e).__name__}
