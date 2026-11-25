"""Offline analysers for web hardening: Content-Security-Policy, Set-Cookie and HTTP response security headers.

Pure functions, stdlib only, no network. Findings are (severity, arabic, english) tuples so the Telegram bot
(per-user language) and the web panel can both render them. Cookie values are never echoed back.
"""
from __future__ import annotations

import re

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3, "good": 4}
SEV_ICON = {"high": "🔴", "medium": "🟠", "low": "🟡", "info": "🔵", "good": "🟢"}
_PENALTY = {"high": 25, "medium": 10, "low": 4, "info": 0, "good": 0}
MAX_INPUT = 20000

# Hosts that commonly serve JSONP / Angular / user-controlled scripts and so defeat a script-src allow-list.
_BYPASS_HOSTS = (
    "ajax.googleapis.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com", "code.jquery.com",
    "www.google.com", "accounts.google.com", "googletagmanager.com", "www.googletagmanager.com",
    "raw.githubusercontent.com", "gist.githubusercontent.com", "s3.amazonaws.com", "storage.googleapis.com",
    "cdn.rawgit.com", "rawgit.com", "netlify.app", "herokuapp.com", "firebaseapp.com", "web.app", "github.io",
)


def _sorted(findings: list) -> list:
    return sorted(findings, key=lambda f: SEV_ORDER[f[0]])


def _score(findings: list, fatal: bool = False) -> int:
    """100 minus penalties. One high finding caps the score at 69 (grade C), two at 49 (D); `fatal` (the control is
    effectively off, e.g. SPF +all) caps it at 30 (F), so a long list of small wins can never hide a serious hole."""
    sc = max(0, 100 - sum(_PENALTY[s] for s, *_ in findings))
    highs = sum(1 for s, *_ in findings if s == "high")
    if highs >= 2:
        sc = min(sc, 49)
    elif highs == 1:
        sc = min(sc, 69)
    return min(sc, 30) if fatal else sc


def grade(score: int) -> str:
    return "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"


# ---------------------------------------------------------------- Content-Security-Policy
def parse_csp(policy: str) -> dict:
    out: dict = {}
    for part in policy.split(";"):
        bits = part.strip().split()
        if not bits:
            continue
        name = bits[0].lower()
        if name not in out:                       # the first occurrence wins (as in browsers)
            out[name] = bits[1:]
    return out


def analyze_csp(policy: str) -> dict:
    policy = (policy or "").strip()
    policy = re.sub(r"^content-security-policy(?:-report-only)?\s*:\s*", "", policy, flags=re.I)
    policy = " ".join(policy.split())[:MAX_INPUT]
    if not policy:
        raise ValueError("empty policy")
    d = parse_csp(policy)
    if not d:
        raise ValueError("no directives found")
    F: list = []

    def eff(name: str):
        """Value list of a fetch directive including the default-src fallback (None when neither exists)."""
        return d.get(name, d.get("default-src"))

    low = lambda vs: [v.lower() for v in vs]            # noqa: E731
    script = eff("script-src")
    if script is None:
        F.append(("high", "لا يوجد script-src ولا default-src: السكربتات غير مقيّدة.",
                  "No script-src or default-src: scripts are unrestricted."))
    else:
        s = low(script)
        has_nonce = any(v.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for v in s)
        strict_dyn = "'strict-dynamic'" in s
        if "'unsafe-inline'" in s and not (has_nonce or strict_dyn):
            F.append(("high", "'unsafe-inline' في السكربتات يلغي حماية CSP من XSS. استخدم nonce أو hash.",
                      "'unsafe-inline' in scripts defeats CSP's XSS protection. Use a nonce or hash."))
        elif "'unsafe-inline'" in s:
            F.append(("info", "'unsafe-inline' موجود لكن المتصفحات الحديثة تتجاهله مع nonce/hash/strict-dynamic.",
                      "'unsafe-inline' is present but modern browsers ignore it next to a nonce/hash/strict-dynamic."))
        if "'unsafe-eval'" in s:
            F.append(("medium", "'unsafe-eval' يسمح بـ eval() وما يشبهه.", "'unsafe-eval' allows eval() and friends."))
        if "*" in s:
            F.append(("high", "علامة * في السكربتات تسمح بالتحميل من أي مصدر.", "A bare * in scripts allows loading from any origin."))
        for scheme in ("http:", "https:", "data:", "blob:", "filesystem:"):
            if scheme in s:
                sev = "high" if scheme in ("http:", "https:", "data:") else "medium"
                F.append((sev, f"المخطط {scheme} في السكربتات واسع جداً.", f"The {scheme} scheme in scripts is far too broad."))
        hit = sorted({h for v in s for h in _BYPASS_HOSTS if v.replace("https://", "").replace("http://", "").lstrip("*.").split("/")[0].endswith(h)})
        if hit and not strict_dyn:
            F.append(("medium", "مضيفون معروفون بإمكانية تجاوز القائمة البيضاء (JSONP/ملفات مستخدمين): " + ", ".join(hit[:5]),
                      "Hosts known to bypass allow-lists (JSONP / user content): " + ", ".join(hit[:5])))
        if any(v.startswith("http://") for v in s):
            F.append(("medium", "مصدر سكربت عبر HTTP غير مشفّر.", "A script source over plain HTTP."))

    if "default-src" in d and any(v == "*" for v in d["default-src"]):
        F.append(("medium", "default-src * واسع جداً.", "default-src * is very broad."))
    if eff("object-src") is None or ("'none'" not in low(eff("object-src")) and "object-src" not in d):
        F.append(("medium", "object-src غير مضبوط. الأفضل 'none' (يغلق ثغرات الإضافات).", "object-src is not set. Prefer 'none' (closes plugin-based bypasses)."))
    elif "object-src" in d and "'none'" not in low(d["object-src"]):
        F.append(("low", "object-src ليس 'none'.", "object-src is not 'none'."))
    if "base-uri" not in d:
        F.append(("medium", "base-uri مفقود: يمكن حقن <base> لإعادة توجيه الروابط النسبية. استخدم 'self' أو 'none'.",
                  "base-uri is missing: an injected <base> can hijack relative URLs. Use 'self' or 'none'."))
    if "frame-ancestors" not in d:
        F.append(("medium", "frame-ancestors مفقود: الصفحة قابلة للتضمين (Clickjacking). X-Frame-Options وحده قديم.",
                  "frame-ancestors is missing: the page can be framed (clickjacking). X-Frame-Options alone is legacy."))
    elif "*" in d["frame-ancestors"]:
        F.append(("medium", "frame-ancestors * يسمح لأي موقع بتضمين الصفحة.", "frame-ancestors * lets any site frame the page."))
    if "form-action" not in d:
        F.append(("low", "form-action مفقود: النماذج المحقونة قد ترسل البيانات لأي جهة.", "form-action is missing: injected forms can post anywhere."))
    style = eff("style-src")
    if style is not None and "'unsafe-inline'" in low(style):
        F.append(("low", "'unsafe-inline' في الأنماط (خطر أقل لكنه حقيقي).", "'unsafe-inline' in styles (lower risk, still real)."))
    if "upgrade-insecure-requests" not in d and "block-all-mixed-content" not in d:
        F.append(("low", "لا يوجد upgrade-insecure-requests لترقية المحتوى المختلط.", "No upgrade-insecure-requests to upgrade mixed content."))
    if "report-uri" not in d and "report-to" not in d:
        F.append(("info", "لا يوجد report-to/report-uri: لن تصلك تقارير الانتهاكات.", "No report-to/report-uri: you will not receive violation reports."))
    if not any(s in ("high", "medium") for s, *_ in F):
        F.append(("good", "السياسة لا تحتوي على أخطاء كبيرة.", "No major weaknesses found."))
    F = _sorted(F)
    sc = _score(F)
    return {"directives": d, "findings": F, "score": sc, "grade": grade(sc)}


# ---------------------------------------------------------------- Set-Cookie
_SESSION_NAME = re.compile(r"sess|sid\b|token|auth|jwt|login|csrf|xsrf|remember", re.I)


def analyze_cookie(line: str) -> dict:
    line = (line or "").strip().splitlines()[0] if (line or "").strip() else ""
    line = re.sub(r"^set-cookie\s*:\s*", "", line, flags=re.I).strip()[:MAX_INPUT]
    parts = [p.strip() for p in line.split(";")]
    if not parts or "=" not in parts[0]:
        raise ValueError("expected name=value; attributes")
    name, value = parts[0].split("=", 1)
    name = name.strip()
    if not name:
        raise ValueError("cookie name is empty")
    attrs: dict = {}
    for p in parts[1:]:
        if not p:
            continue
        k, _, v = p.partition("=")
        attrs.setdefault(k.strip().lower(), v.strip())
    F: list = []
    secure, httponly = "secure" in attrs, "httponly" in attrs
    samesite = attrs.get("samesite", "").lower() if "samesite" in attrs else None
    sensitive = bool(_SESSION_NAME.search(name))
    if not secure:
        F.append(("high" if (sensitive or samesite == "none") else "medium", "لا توجد خاصية Secure: يمكن إرسال الكوكي عبر HTTP.",
                  "No Secure flag: the cookie can travel over plain HTTP."))
    if not httponly:
        F.append(("high" if sensitive else "low", "لا توجد HttpOnly: يمكن لـ JavaScript (وبالتالي XSS) قراءته.",
                  "No HttpOnly: JavaScript (and so any XSS) can read it."))
    if samesite is None:
        F.append(("medium" if sensitive else "low", "لا توجد SameSite: السلوك يعتمد على المتصفح. استخدم Lax أو Strict.",
                  "No SameSite: behaviour depends on the browser. Use Lax or Strict."))
    elif samesite == "none":
        F.append(("high" if not secure else "medium", "SameSite=None يرسل الكوكي مع الطلبات عبر المواقع (CSRF/تتبّع)" + (" وبدون Secure سيرفضه المتصفح." if not secure else "."),
                  "SameSite=None sends the cookie on cross-site requests (CSRF/tracking)" + (" and without Secure browsers reject it." if not secure else ".")))
    elif samesite not in ("lax", "strict"):
        F.append(("low", f"قيمة SameSite غير معروفة: {samesite[:20]}", f"Unknown SameSite value: {samesite[:20]}"))
    low_name = name.lower()
    if low_name.startswith("__host-"):
        if not (secure and attrs.get("path") == "/" and "domain" not in attrs):
            F.append(("high", "البادئة __Host- تتطلب Secure و Path=/ وبدون Domain، وإلا يرفضه المتصفح.",
                      "The __Host- prefix requires Secure, Path=/ and no Domain, otherwise browsers reject it."))
    elif low_name.startswith("__secure-") and not secure:
        F.append(("high", "البادئة __Secure- تتطلب Secure.", "The __Secure- prefix requires Secure."))
    elif sensitive and secure and httponly:
        F.append(("info", "فكّر في البادئة __Host- لتثبيت الكوكي على هذا النطاق فقط.", "Consider the __Host- prefix to pin it to this exact host."))
    dom = attrs.get("domain")
    if dom:
        F.append(("low", f"Domain={dom.lstrip('.')[:60]} يشارك الكوكي مع كل النطاقات الفرعية. احذفه إن لم تحتجه.",
                  f"Domain={dom.lstrip('.')[:60]} shares the cookie with every subdomain. Drop it unless needed."))
    life = None
    if "max-age" in attrs:
        try:
            life = int(attrs["max-age"])
        except ValueError:
            F.append(("low", "قيمة Max-Age ليست رقماً.", "Max-Age is not a number."))
    if life is not None and life > 365 * 86400:
        F.append(("low" if not sensitive else "medium", f"عمر الكوكي {life // 86400} يوماً. الجلسات الحسّاسة يجب أن تكون أقصر.",
                  f"Lifetime is {life // 86400} days. Sensitive sessions should be shorter."))
    elif sensitive and life is None and "expires" not in attrs:
        F.append(("info", "كوكي جلسة (ينتهي بإغلاق المتصفح).", "Session cookie (ends when the browser closes)."))
    if len(value) < 16 and sensitive:
        F.append(("medium", "قيمة قصيرة لكوكي يبدو حسّاساً: تأكد أنها عشوائية وطويلة (128 بت على الأقل).",
                  "Short value for a sensitive-looking cookie: make sure it is random and long (128 bits+)."))
    if not any(s in ("high", "medium", "low") for s, *_ in F):
        F.append(("good", "الخصائص الأساسية سليمة.", "The core attributes look right."))
    F = _sorted(F)
    sc = _score(F)
    return {"name": name[:80], "value_len": len(value), "attrs": sorted(attrs), "findings": F, "score": sc, "grade": grade(sc)}


# ---------------------------------------------------------------- response headers
def parse_headers(raw: str) -> tuple:
    """Return (headers dict lower-name -> list of values, number of lines parsed). The status line is ignored."""
    hs: dict = {}
    n = 0
    for ln in (raw or "")[:MAX_INPUT].splitlines():
        ln = ln.rstrip()
        if not ln or re.match(r"^HTTP/\d(?:\.\d)?\s+\d{3}", ln, re.I):
            continue
        if ln[0] in " \t" and hs:                           # folded continuation line
            last = next(reversed(hs))
            hs[last][-1] += " " + ln.strip()
            continue
        k, sep, v = ln.partition(":")
        if not sep or not re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+", k.strip()):
            continue
        hs.setdefault(k.strip().lower(), []).append(v.strip())
        n += 1
    return hs, n


def analyze_headers(raw: str) -> dict:
    hs, n = parse_headers(raw)
    if not n:
        raise ValueError("no headers found")
    F: list = []
    first = lambda k: (hs.get(k) or [""])[0]        # noqa: E731

    hsts = first("strict-transport-security")
    if not hsts:
        F.append(("high", "Strict-Transport-Security مفقود (يسهّل هجمات التنزيل إلى HTTP).", "Strict-Transport-Security is missing (allows SSL-stripping downgrades)."))
    else:
        m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
        age = int(m.group(1)) if m else 0
        if age < 15552000:
            F.append(("medium", f"HSTS max-age={age} أقل من 180 يوماً. الموصى به سنة (31536000).", f"HSTS max-age={age} is under 180 days. One year (31536000) is recommended."))
        if "includesubdomains" not in hsts.lower():
            F.append(("low", "HSTS بدون includeSubDomains.", "HSTS without includeSubDomains."))
        if age >= 15552000:
            F.append(("good", "HSTS مضبوط جيداً.", "HSTS is well configured."))
    csp = first("content-security-policy")
    csp_res = None
    if not csp:
        F.append(("high", "Content-Security-Policy مفقود.", "Content-Security-Policy is missing."))
    else:
        try:
            csp_res = analyze_csp(csp)
            worst = [f for f in csp_res["findings"] if f[0] in ("high", "medium")]
            if worst:
                F.append(("medium", f"CSP موجود لكن فيه {len(worst)} ملاحظة مهمة (استخدم /csp للتفاصيل).", f"CSP is present but has {len(worst)} notable issue(s) (run /csp for details)."))
            else:
                F.append(("good", "CSP موجود وقوي.", "CSP is present and solid."))
        except ValueError:
            F.append(("medium", "CSP غير قابل للقراءة.", "CSP could not be parsed."))
    if "nosniff" not in first("x-content-type-options").lower():
        F.append(("medium", "X-Content-Type-Options: nosniff مفقود.", "X-Content-Type-Options: nosniff is missing."))
    fa = csp_res and "frame-ancestors" in csp_res["directives"]
    if not first("x-frame-options") and not fa:
        F.append(("medium", "لا حماية من التضمين: X-Frame-Options ولا frame-ancestors.", "No framing protection: neither X-Frame-Options nor frame-ancestors."))
    if not first("referrer-policy"):
        F.append(("low", "Referrer-Policy مفقود (استخدم strict-origin-when-cross-origin).", "Referrer-Policy is missing (use strict-origin-when-cross-origin)."))
    elif first("referrer-policy").lower() in ("unsafe-url", "no-referrer-when-downgrade"):
        F.append(("medium", "Referrer-Policy يسرّب المسارات الكاملة.", "Referrer-Policy leaks full URLs."))
    if not first("permissions-policy") and not first("feature-policy"):
        F.append(("low", "Permissions-Policy مفقود (قيّد الكاميرا والموقع…).", "Permissions-Policy is missing (restrict camera, geolocation…)."))
    if not first("cross-origin-opener-policy"):
        F.append(("low", "Cross-Origin-Opener-Policy مفقود.", "Cross-Origin-Opener-Policy is missing."))
    if not first("cross-origin-resource-policy") and not first("cross-origin-embedder-policy"):
        F.append(("info", "لا توجد سياسات Cross-Origin-Resource/Embedder.", "No Cross-Origin-Resource/Embedder policies."))
    acao, acac = first("access-control-allow-origin"), first("access-control-allow-credentials").lower()
    if acao == "null":
        F.append(("high", "Access-Control-Allow-Origin: null قابل للاستغلال من iframe sandbox.", "Access-Control-Allow-Origin: null is exploitable from a sandboxed iframe."))
    elif acao == "*" and acac == "true":
        F.append(("high", "CORS: * مع Allow-Credentials خطأ إعداد (المتصفح يرفضه لكنه يدل على انعكاس Origin محتمل).", "CORS: * with Allow-Credentials is a misconfiguration (browsers reject it, but it hints at Origin reflection)."))
    elif acao == "*":
        F.append(("info", "CORS مفتوح لكل الأصول (مقبول للمحتوى العام فقط).", "CORS is open to every origin (fine for public content only)."))
    srv = first("server")
    if re.search(r"\d+\.\d+", srv):
        F.append(("low", f"الترويسة Server تكشف الإصدار: {srv[:60]}", f"The Server header discloses a version: {srv[:60]}"))
    for h in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        if first(h):
            F.append(("low", f"{h} يكشف التقنية: {first(h)[:60]}", f"{h} reveals the stack: {first(h)[:60]}"))
    cookies = hs.get("set-cookie", [])
    bad = 0
    for c in cookies[:20]:
        try:
            if any(s in ("high", "medium") for s, *_ in analyze_cookie(c)["findings"]):
                bad += 1
        except ValueError:
            bad += 1
    if bad:
        F.append(("medium", f"{bad} من {len(cookies)} كوكي بخصائص ضعيفة (استخدم /cookie).", f"{bad} of {len(cookies)} cookie(s) have weak attributes (run /cookie)."))
    F = _sorted(F)
    sc = _score(F)
    return {"count": n, "findings": F, "score": sc, "grade": grade(sc)}


def render_plain(res: dict, lang: str = "ar") -> str:
    """Plain-text report (used by the web panel)."""
    i = 1 if lang == "ar" else 2
    head = f"{res['grade']}  ({res['score']}/100)"
    return head + "\n" + "\n".join(f"{SEV_ICON[f[0]]} [{f[0]}] {f[i]}" for f in res["findings"])
