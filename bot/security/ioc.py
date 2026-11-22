"""Indicator-of-compromise extraction, defanging and re-fanging."""
from __future__ import annotations

import ipaddress
import re

_URL = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`)\]}]+", re.I)
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_EMAIL = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b")
# Host candidates are tokenised first and validated label by label (a single nested-quantifier regex
# backtracks catastrophically on inputs like "a.a.a.a...").
_HOST_TOKEN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?")
_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
MAX_INPUT = 50_000
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_HASH = {
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.I),
    "sha1": re.compile(r"\b[a-f0-9]{40}\b", re.I),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.I),
}

# A curated TLD list keeps file names such as `main.py` or `notes.md` out of the domain results.
TLDS = frozenset("""com net org info biz io co me us uk de fr es it nl ru cn jp kr in br au ca ch se no fi pl tr ir
sa ae eg dz ma tn ly iq sy jo lb ps kw qa bh om ye sd gov edu mil int xyz top site online store shop app dev cloud
tech club live click link work support help icu cc ws pw su tk ml ga cf gq to tv fm ly gl vip cyou rest cam bid
monster zip mov onion""".split())

SHORTENERS = frozenset("""bit.ly tinyurl.com t.co goo.gl ow.ly is.gd buff.ly cutt.ly rb.gy shorturl.at tiny.cc
rebrand.ly t.ly s.id v.gd lnkd.in""".split())


def refang(text: str) -> str:
    """Undo common defanging: hxxp, [.], (.), [:], [@], [at]."""
    t = re.sub(r"\bhxxp(s?)\b", r"http\1", text, flags=re.I)
    t = re.sub(r"\bfxp\b", "ftp", t, flags=re.I)
    t = re.sub(r"[\[\(\{]\s*\.\s*[\]\)\}]", ".", t)
    t = re.sub(r"[\[\(\{]\s*dot\s*[\]\)\}]", ".", t, flags=re.I)
    t = re.sub(r"[\[\(\{]\s*:\s*[\]\)\}]", ":", t)
    t = re.sub(r"[\[\(\{]\s*(?:@|at)\s*[\]\)\}]", "@", t, flags=re.I)
    return t


def defang(value: str) -> str:
    """Make an indicator non-clickable and safe to paste in tickets/chats."""
    v = re.sub(r"^http", "hxxp", value, flags=re.I)
    v = v.replace("://", "[:]//") if "hxxp" in v.lower() else v
    return v.replace(".", "[.]").replace("@", "[@]")


def _valid_ip(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False


def _uniq(items) -> list:
    seen, out = set(), []
    for x in items:
        k = x.lower()
        if k not in seen:
            seen.add(k)
            out.append(x)
    return out


def extract(text: str) -> dict:
    """Return {kind: [unique indicators]} for urls, ips, domains, emails, hashes and CVEs."""
    t = refang(text[:MAX_INPUT])
    urls = _uniq(u.rstrip(".,;:!?") for u in _URL.findall(t))
    emails = _uniq(_EMAIL.findall(t))
    ips = _uniq(i for i in _IPV4.findall(t) if _valid_ip(i))
    ip_set = set(ips)
    domains = []
    for tok in _HOST_TOKEN.findall(t):
        if "." not in tok or len(tok) > 253:
            continue
        labels = tok.lower().split(".")
        if len(labels) < 2 or not all(_LABEL.fullmatch(x) for x in labels):
            continue
        if labels[-1] in TLDS and tok.lower() not in ip_set:
            domains.append(tok.lower())
    email_domains = {e.split("@", 1)[1].lower() for e in emails}
    domains = [d for d in _uniq(domains) if d not in email_domains]
    hashes = {}
    taken = set()
    for kind in ("sha256", "sha1", "md5"):
        found = [h for h in _HASH[kind].findall(t) if h.lower() not in taken]
        # a 64-char hex string also contains a 32-char run only when separated, so \b boundaries suffice
        hashes[kind] = _uniq(found)
        taken.update(h.lower() for h in found)
    cves = _uniq(c.upper() for c in _CVE.findall(t))
    return {"urls": urls, "ips": ips, "domains": domains, "emails": emails,
            "sha256": hashes["sha256"], "sha1": hashes["sha1"], "md5": hashes["md5"], "cves": cves}


def is_private_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
    except ValueError:
        return False


def defang_text(text: str) -> str:
    """Defang every URL/IP/domain/e-mail found inside `text`, leaving the rest untouched."""
    found = extract(text)
    items = sorted({v for k in ("urls", "emails", "ips", "domains") for v in found[k]}, key=len, reverse=True)
    out = refang(text)
    for v in items:
        out = out.replace(v, defang(v))
    return out
