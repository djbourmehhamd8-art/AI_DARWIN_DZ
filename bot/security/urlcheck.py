"""Offline heuristic URL risk analysis. Never visits the URL."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qs, urlparse

from .ioc import SHORTENERS, refang

# code -> (weight, Arabic, English)
RULES = {
    "scheme_bad": (50, "بروتوكول خطير (javascript/data)", "Dangerous scheme (javascript/data)"),
    "no_https": (10, "اتصال غير مشفّر (HTTP)", "Unencrypted connection (HTTP)"),
    "ip_host": (25, "العنوان رقم IP بدل اسم نطاق", "Host is a raw IP address"),
    "obf_ip": (30, "IP مموّه (عشري/سداسي عشري)", "Obfuscated IP (decimal/hex)"),
    "userinfo": (30, "حيلة @ لإخفاء الوجهة الحقيقية", "'@' trick hides the real destination"),
    "punycode": (25, "نطاق Punycode (قد يكون تقليداً بحروف مشابهة)", "Punycode domain (possible homograph)"),
    "non_ascii": (25, "حروف غير لاتينية في النطاق", "Non-ASCII characters in host"),
    "shortener": (15, "رابط مختصر يخفي الوجهة", "URL shortener hides the destination"),
    "bad_tld": (15, "نطاق علوي شائع في الاحتيال", "TLD frequently abused for phishing"),
    "deep_sub": (10, "مستويات نطاق فرعي كثيرة", "Excessive subdomain depth"),
    "long_url": (8, "رابط طويل جداً", "Very long URL"),
    "keywords": (12, "كلمات استدراج (login/verify/...)", "Lure keywords (login/verify/...)"),
    "brand_spoof": (30, "ينتحل اسم علامة معروفة", "Impersonates a well-known brand"),
    "odd_port": (10, "منفذ غير معتاد", "Unusual port"),
    "exec_dl": (20, "تحميل ملف تنفيذي/خطير", "Executable / risky file download"),
    "redirect_param": (10, "يحتوي إعادة توجيه لرابط آخر", "Contains redirect to another URL"),
    "hyphens": (8, "شرطات كثيرة في النطاق", "Many hyphens in domain"),
}

BAD_TLDS = frozenset("tk ml ga cf gq xyz top zip mov click icu cyou rest cam bid monster work support country".split())
LURE = ("login", "signin", "verify", "secure", "account", "update", "wallet", "bank", "password", "otp",
        "confirm", "suspend", "unlock", "gift", "free", "bonus", "claim", "recover", "support", "billing")
BRANDS = ("paypal", "google", "apple", "microsoft", "facebook", "instagram", "telegram", "whatsapp", "binance",
          "amazon", "netflix", "twitter", "linkedin", "dropbox", "outlook", "office365", "icloud", "metamask",
          "coinbase", "steam", "discord", "tiktok", "youtube", "algerie", "ooredoo", "djezzy", "mobilis", "poste")
OFFICIAL = {"paypal": {"paypal.com"}, "google": {"google.com", "google.dz"}, "apple": {"apple.com", "icloud.com"},
            "microsoft": {"microsoft.com", "live.com", "office.com"}, "facebook": {"facebook.com", "fb.com"},
            "instagram": {"instagram.com"}, "telegram": {"telegram.org", "t.me", "telegram.me"},
            "whatsapp": {"whatsapp.com", "whatsapp.net"}, "binance": {"binance.com"}, "amazon": {"amazon.com"},
            "netflix": {"netflix.com"}, "twitter": {"twitter.com", "x.com"}, "linkedin": {"linkedin.com"},
            "dropbox": {"dropbox.com"}, "outlook": {"outlook.com", "live.com"}, "office365": {"office.com"},
            "icloud": {"icloud.com", "apple.com"}, "metamask": {"metamask.io"}, "coinbase": {"coinbase.com"},
            "steam": {"steampowered.com", "steamcommunity.com"}, "discord": {"discord.com", "discord.gg"},
            "tiktok": {"tiktok.com"}, "youtube": {"youtube.com", "youtu.be"}, "algerie": set(),
            "ooredoo": {"ooredoo.dz", "ooredoo.com"}, "djezzy": {"djezzy.dz"}, "mobilis": {"mobilis.dz"},
            "poste": {"poste.dz", "poste.it"}}
RISKY_EXT = (".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".apk", ".iso", ".lnk",
             ".hta", ".dll", ".docm", ".xlsm", ".zip", ".rar", ".7z")
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "edu", "ac"}
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t", "$": "s"})


def registered_domain(host: str) -> str:
    labels = host.lower().strip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _normalize(s: str) -> str:
    return s.translate(_LEET).replace("vv", "w").replace("rn", "m")


def _host_is_obfuscated_ip(host: str) -> bool:
    if re.fullmatch(r"0x[0-9a-f]+", host, re.I) or re.fullmatch(r"\d{8,10}", host):
        return True
    return bool(re.fullmatch(r"(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){1,3}", host, re.I)
                and any(p.lower().startswith("0x") or (len(p) > 1 and p.startswith("0")) for p in host.split(".")))


def analyze(url: str) -> dict:
    """Return {url, host, score, level, findings:[code,...]}. level: low|medium|high|critical."""
    raw = refang(url.strip())
    if re.match(r"^(javascript|data|vbscript):", raw, re.I):
        return _result(raw, "", ["scheme_bad"])
    if not re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I):
        raw = "http://" + raw
    try:
        p = urlparse(raw)
        host = (p.hostname or "").lower()
        port = p.port
    except ValueError:
        return _result(raw, "", ["userinfo"])
    f = []
    if p.scheme == "http":
        f.append("no_https")
    if "@" in p.netloc:
        f.append("userinfo")
    ip = None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    if ip is not None:
        f.append("ip_host")
    elif _host_is_obfuscated_ip(host):
        f.append("obf_ip")
    else:
        if host.startswith("xn--") or ".xn--" in host:
            f.append("punycode")
        if any(ord(c) > 127 for c in host):
            f.append("non_ascii")
        reg = registered_domain(host)
        if reg in SHORTENERS or host in SHORTENERS:
            f.append("shortener")
        if host.rsplit(".", 1)[-1] in BAD_TLDS:
            f.append("bad_tld")
        if host.count(".") >= 4:
            f.append("deep_sub")
        if host.replace("xn--", "").count("-") >= 3:
            f.append("hyphens")
        if any(k in host for k in LURE) or any(k in p.path.lower() for k in LURE):
            f.append("keywords")
        label_blob = _normalize(host.replace("-", "").replace(".", ""))
        for brand in BRANDS:
            if brand in label_blob and reg not in OFFICIAL.get(brand, set()):
                # real brand domains and their subdomains are fine; everything else is suspicious
                if brand == "algerie" and not label_blob.count("algerie"):
                    continue
                f.append("brand_spoof")
                break
    if len(raw) > 200:
        f.append("long_url")
    if port and port not in (80, 443, 8080):
        f.append("odd_port")
    if p.path.lower().endswith(RISKY_EXT):
        f.append("exec_dl")
    qs = parse_qs(p.query)
    if any(re.match(r"^https?://", v, re.I) for vals in qs.values() for v in vals) or "%3a%2f%2f" in p.query.lower():
        f.append("redirect_param")
    return _result(raw, host, f)


def _result(url, host, findings) -> dict:
    score = min(100, sum(RULES[c][0] for c in findings))
    level = "low" if score < 20 else "medium" if score < 45 else "high" if score < 70 else "critical"
    return {"url": url, "host": host, "score": score, "level": level, "findings": findings}


def describe(res: dict, lang: str) -> str:
    from .ioc import defang
    idx = 1 if lang == "ar" else 2
    icon = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}[res["level"]]
    names = {"ar": {"low": "منخفض", "medium": "متوسط", "high": "مرتفع", "critical": "حرج"},
             "en": {"low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"}}[lang]
    head = ("🔗 تحليل الرابط" if lang == "ar" else "🔗 URL analysis")
    lines = [f"{head}: {defang(res['url'])[:160]}",
             (f"{icon} الخطورة: {names[res['level']]} ({res['score']}/100)" if lang == "ar"
              else f"{icon} Risk: {names[res['level']]} ({res['score']}/100)")]
    for c in res["findings"]:
        lines.append(f"• {RULES[c][idx]}")
    if not res["findings"]:
        lines.append("• " + ("لا مؤشرات واضحة" if lang == "ar" else "No obvious indicators"))
    lines.append("ℹ️ " + ("فحص محلي إرشادي دون زيارة الرابط، وغياب المؤشرات لا يعني أنه آمن." if lang == "ar"
                         else "Offline heuristic check, the URL was not visited. No findings does not mean safe."))
    return "\n".join(lines)
