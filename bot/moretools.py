"""Extra offline tools shared by the web panel and the web chat (pure standard library, nothing stored, no network).

Every function takes the user's text and returns plain text, or raises ValueError with a short Arabic message.
`run(kind, text)` is the dispatcher used by `webext.run_web_tool`; it returns None for kinds it does not know.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import http
import ipaddress
import math
import re
import struct
import time
import unicodedata
from collections import Counter
from urllib.parse import parse_qsl, urlsplit

EXTRA_TOOLS = (
    ("entropy", "📈 إنتروبيا نص (كشف العشوائية والمفاتيح)"),
    ("homoglyph", "🔤 كاشف النطاقات المخادعة (Homograph / IDN)"),
    ("urlparse", "🔗 تشريح رابط + علامات الخطر"),
    ("base", "🔢 محوّل الأنظمة العددية (2/8/10/16)"),
    ("totp", "🔑 مولّد TOTP (سر base32 أو otpauth://)"),
    ("port", "🔌 منافذ وخدمات (رقم أو مجال أو اسم)"),
    ("httpstatus", "📡 رموز HTTP (رقم أو كلمة)"),
    ("hmac", "✍️ HMAC (المفتاح :: الرسالة)"),
    ("hexdump", "🧬 Hex dump لنص"),
)

# ------------------------------------------------------------------ entropy


def entropy(text: str) -> str:
    if not text:
        raise ValueError("اكتب نصاً لقياس عشوائيته.")
    n = len(text)
    counts = Counter(text)
    h = -sum(c / n * math.log2(c / n) for c in counts.values())
    t = text.strip()
    if re.fullmatch(r"[0-9a-fA-F]{16,}", t):
        kind, alphabet = "hex (هاش أو مفتاح؟)", 4.0
    elif re.fullmatch(r"[A-Za-z0-9+/_-]{16,}={0,2}", t):
        kind, alphabet = "base64/base64url (توكن أو مفتاح؟)", 6.0
    else:
        kind, alphabet = "نص عام", math.log2(max(len(counts), 2))
    best = min(math.log2(n), alphabet) if n > 1 else 1.0          # the most a string of this length/alphabet could reach
    ratio = h / best if best else 0.0
    if ratio >= 0.9 and n >= 16:
        verdict = "🔴 عالية: يبدو عشوائياً (مفتاح/توكن/مضغوط/مشفّر) — إن وجدته داخل ملف فافحصه كسرّ محتمل"
    elif ratio >= 0.9:
        verdict = "🟡 قصيرة جداً للحكم الدقيق، لكن التوزيع منتظم"
    elif ratio >= 0.7:
        verdict = "🟡 متوسطة: خليط بين نص منظَّم وعشوائي"
    else:
        verdict = "🟢 منخفضة: نمط متكرر أو لغة طبيعية"
    return (f"الطول: {n} · رموز مختلفة: {len(counts)}\n"
            f"إنتروبيا شانون: {h:.3f} بت/رمز (الأقصى لهذا الطول والنوع ≈ {best:.3f})\n"
            f"إجمالي تقريبي: {h * n:.0f} بت\nالنوع: {kind}\n{verdict}")


# ------------------------------------------------------------------ homograph / IDN

_CONFUSABLE = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ԍ": "g", "һ": "h",
    "ο": "o", "α": "a", "ν": "v", "ρ": "p", "ι": "i", "κ": "k", "τ": "t", "ı": "i", "ℓ": "l", "ⅼ": "l", "ǀ": "l",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X", "Ζ": "Z",
}


def _script(ch: str) -> str:
    if not ch.isalpha():
        return ""
    return (unicodedata.name(ch, "UNKNOWN").split(" ")[0]) or "UNKNOWN"


def _host_of(line: str) -> str:
    line = line.strip()
    if "://" in line:
        try:
            return urlsplit(line).hostname or ""
        except ValueError:
            return ""
    return line.split("/")[0]


def homoglyph(text: str) -> str:
    lines = [x for x in (s.strip() for s in text.splitlines()) if x][:20]
    if not lines:
        raise ValueError("اكتب نطاقاً أو رابطاً (سطر لكل نطاق).")
    out = []
    for raw in lines:
        host = _host_of(raw)
        if not host:
            out.append(f"❓ {raw[:80]} — لا أستطيع استخراج اسم مضيف")
            continue
        shown = host
        if "xn--" in host.lower():
            try:
                shown = host.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                out.append(f"⚠️ {host} — Punycode غير صالح")
                continue
        norm = unicodedata.normalize("NFKC", shown)
        scripts = sorted({s for s in map(_script, norm) if s})
        non_ascii = [c for c in shown if ord(c) > 127]
        skeleton = "".join(_CONFUSABLE.get(c, c) for c in norm)
        try:
            puny = shown.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            puny = "(تعذّر)"
        flags = []
        if len(scripts) > 1:
            flags.append("⚠️ خلط بين أنظمة كتابة: " + " + ".join(scripts))
        if non_ascii and skeleton.isascii() and skeleton != norm:
            flags.append(f"🚨 يشبه النطاق «{skeleton}» بصرياً — احتمال انتحال")
        if norm != shown:
            flags.append("⚠️ يتغير شكله بعد التطبيع (حروف عريضة/مركّبة)")
        head = "✅" if not non_ascii and not flags else ("🚨" if any(f.startswith("🚨") for f in flags) else "⚠️")
        block = [f"{head} {shown}", f"   Punycode: {puny}", f"   أنظمة الكتابة: {' + '.join(scripts) or '—'}"]
        block += [f"   {f}" for f in flags]
        for c in non_ascii[:8]:
            block.append(f"   U+{ord(c):04X} {unicodedata.name(c, '?')}" + (f" ← يشبه '{_CONFUSABLE[c]}'" if c in _CONFUSABLE else ""))
        if not non_ascii and not flags:
            block.append("   ASCII فقط: لا حيل ترميز ظاهرة (تحقق من التهجئة نفسها).")
        out.append("\n".join(block))
    return "\n\n".join(out)


# ------------------------------------------------------------------ URL breakdown

_SPECIAL_SCHEMES = re.compile(r"^(javascript|data|vbscript|file|mailto|tel|blob|about):", re.I)


def url_breakdown(text: str) -> str:
    raw = (text.strip().splitlines() or [""])[0].strip()
    if not raw:
        raise ValueError("اكتب رابطاً.")
    flags = []
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw) or raw.startswith("//") or _SPECIAL_SCHEMES.match(raw):
        full = raw
    else:
        full = "http://" + raw
        flags.append("ℹ️ لا يوجد بروتوكول؛ افترضت http://")
    try:
        p = urlsplit(full)
        port = p.port
        host = p.hostname or ""
    except ValueError:
        raise ValueError("رابط غير صالح.")
    lines = [f"البروتوكول: {p.scheme or '—'}"]
    if p.username is not None or p.password is not None:
        lines.append(f"بيانات المستخدم: {p.username or ''}{':***' if p.password else ''}")
        flags.append(f"🚨 يحتوي «@»: المضيف الحقيقي هو «{host}» وما قبله مجرد تمويه")
    lines.append(f"المضيف: {host or '—'}" + (f" · المنفذ: {port}" if port else ""))
    lines.append(f"المسار: {p.path or '/'}")
    if p.fragment:
        lines.append(f"المقطع (#): {p.fragment[:120]}")
    if p.scheme.lower() in ("javascript", "data", "vbscript"):
        flags.append(f"🚨 بروتوكول «{p.scheme}» ينفّذ محتوى بدل فتح موقع")
    elif p.scheme.lower() not in ("http", "https", "ftp", "mailto", "tel", "file", "blob", "about", ""):
        flags.append(f"⚠️ بروتوكول غير معتاد: {p.scheme}")
    if p.scheme.lower() == "http":
        flags.append("⚠️ بدون تشفير (http)")
    if host and (host.isdigit() or host.lower().startswith("0x") or re.fullmatch(r"(?:0\d+|0x[0-9a-f]+)(?:\.(?:0\d+|0x[0-9a-f]+|\d+)){0,3}", host.lower())):
        flags.append("🚨 عنوان IP مموَّه (عشري/سداسي عشر/ثماني)")
    else:
        try:
            ipaddress.ip_address(host)
            flags.append("⚠️ المضيف عنوان IP مباشر وليس اسماً")
        except ValueError:
            pass
    if "xn--" in host.lower():
        flags.append("⚠️ Punycode (نطاق دولي): افحصه بأداة النطاقات المخادعة")
    if any(ord(c) > 127 for c in host):
        flags.append("⚠️ أحرف غير ASCII في المضيف")
    if port and port not in (80, 443):
        flags.append(f"⚠️ منفذ غير قياسي: {port}")
    if "\\" in raw:
        flags.append("⚠️ يحتوي «\\» وهو يُفسَّر «/» في بعض المتصفحات")
    if len(raw) > 2000:
        flags.append("⚠️ رابط طويل جداً")
    params = parse_qsl(p.query, keep_blank_values=True)[:30]
    if params:
        lines.append("المعاملات:")
        for k, v in params:
            lines.append(f"  {k[:60]} = {v[:150]}")
            low = v.lower()
            if low.startswith(("http://", "https://", "//")):
                flags.append(f"⚠️ المعامل «{k[:30]}» يحمل رابطاً (إعادة توجيه مفتوحة محتملة)")
            if "<script" in low or low.startswith("javascript:"):
                flags.append(f"🚨 المعامل «{k[:30]}» يشبه حقن سكربت")
    if "%25" in raw:
        flags.append("⚠️ ترميز مزدوج (%25) — تقنية شائعة لتجاوز المرشحات")
    seen = set()
    flags = [f for f in flags if not (f in seen or seen.add(f))]
    return "\n".join(lines + ([""] + flags if flags else ["", "✅ لا علامات خطر ظاهرة في الشكل (هذا فحص شكلي وليس سمعة)."]))


# ------------------------------------------------------------------ number bases


def base_convert(text: str) -> str:
    s = text.strip().lower().replace("_", "").replace(",", "").replace(" ", "")
    if not s:
        raise ValueError("اكتب عدداً: 255 أو 0xff أو 0b1010 أو 0o17")
    if len(s) > 700:
        raise ValueError("العدد طويل جداً.")
    try:
        sign = -1 if s.startswith("-") else 1
        body = s.lstrip("+-")
        if body.startswith("0x"):
            n = int(body, 16)
        elif body.startswith("0b"):
            n = int(body, 2)
        elif body.startswith("0o"):
            n = int(body, 8)
        else:
            n = int(body, 10)
        n *= sign
    except ValueError:
        raise ValueError("اكتب عدداً: 255 أو 0xff أو 0b1010 أو 0o17")
    if abs(n).bit_length() > 2048:
        raise ValueError("العدد أكبر من 2048 بت.")
    b = bin(n)
    lines = [f"عشري: {n}", f"سداسي عشر: {hex(n)}", f"ثماني: {oct(n)}", f"ثنائي: {b if len(b) <= 140 else b[:137] + '…'}",
             f"عدد البتات: {abs(n).bit_length()}"]
    if 0 <= n < 2 ** 32:
        lines.append(f"كعنوان IPv4: {ipaddress.IPv4Address(n)}")
    if 32 <= n < 127:
        lines.append(f"كحرف ASCII: {chr(n)!r}")
    return "\n".join(lines)


# ------------------------------------------------------------------ TOTP (RFC 6238)

_ALGOS = ("sha1", "sha256", "sha512")


def totp_code(key: bytes, t: float, digits: int = 6, step: int = 30, algo: str = "sha1") -> str:
    counter = max(0, int(t // step))                      # t - step can be negative near the epoch: struct would refuse it
    mac = hmac.new(key, struct.pack(">Q", counter), getattr(hashlib, algo)).digest()
    off = mac[-1] & 15
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp_tool(text: str, now: float | None = None) -> str:
    text = text.strip()
    digits, step, algo = 6, 30, "sha1"
    try:
        if text.lower().startswith("otpauth://"):
            q = dict(parse_qsl(urlsplit(text).query))
            secret = q.get("secret", "")
            digits, step, algo = int(q.get("digits", 6)), int(q.get("period", 30)), q.get("algorithm", "SHA1").lower()
        else:
            parts = text.split()
            secret = parts[0] if parts else ""
            digits = int(parts[1]) if len(parts) > 1 else 6
            step = int(parts[2]) if len(parts) > 2 else 30
    except (ValueError, IndexError):
        raise ValueError("الصيغة: السر [عدد الأرقام] [المدة] أو رابط otpauth://")
    if digits not in (6, 7, 8) or not 10 <= step <= 300 or algo not in _ALGOS:
        raise ValueError("إعدادات غير مدعومة: الأرقام 6-8، المدة 10-300 ثانية، الخوارزمية sha1/sha256/sha512.")
    clean = re.sub(r"[\s-]", "", secret).upper()
    try:
        key = base64.b32decode(clean + "=" * (-len(clean) % 8))
    except (binascii.Error, ValueError):
        raise ValueError("السر ليس base32 صالحاً (حروف A-Z والأرقام 2-7).")
    if not key:
        raise ValueError("السر فارغ.")
    t = time.time() if now is None else now
    left = step - int(t % step)
    return (f"الرمز الحالي: {totp_code(key, t, digits, step, algo)}  (يتغير بعد {left} ث)\n"
            f"السابق: {totp_code(key, t - step, digits, step, algo)} · التالي: {totp_code(key, t + step, digits, step, algo)}\n"
            f"{algo.upper()} · {digits} أرقام · كل {step} ث\n"
            "⚠️ لا تدخل هنا إلا أسرار تجريبية أو أسراراً تثق بخادمك فيها؛ لا شيء يُخزَّن.")


# ------------------------------------------------------------------ ports / HTTP status


def port_info(text: str) -> str:
    from .security import ports as PT
    items = PT.lookup(text)
    if not items:
        raise ValueError("لم أجد شيئاً. اكتب رقماً (443) أو مجالاً (20-25) أو اسم خدمة (ssh).")
    return "\n".join(f"{PT.RISK[risk]} {p} · {svc} — {ar}" for p, (svc, risk, ar, _en) in items)


_HTTP_CLASS = {1: "معلومات", 2: "نجاح", 3: "إعادة توجيه", 4: "خطأ من العميل", 5: "خطأ من الخادم"}
_HTTP_NOTE = {
    401: "غير مصادَق (لا هوية): يحتاج بيانات دخول.", 403: "مصادَق لكن غير مخوَّل: الهوية معروفة والصلاحية ناقصة.",
    429: "حدّ المعدّل: ينتظر العميل حسب Retry-After.", 301: "نقل دائم (يُخزَّن في المتصفح).", 302: "نقل مؤقت.",
    307: "نقل مؤقت يحفظ نوع الطلب.", 308: "نقل دائم يحفظ نوع الطلب.", 502: "بوابة سيئة: المنبع ردّ بشكل غير صالح.",
    503: "الخدمة غير متاحة مؤقتاً.", 504: "مهلة البوابة: المنبع تأخر.",
}


def http_status(text: str) -> str:
    t = text.strip()
    if not t:
        raise ValueError("اكتب رمزاً (404) أو كلمة (redirect).")
    if t.isdigit():
        try:
            found = [http.HTTPStatus(int(t))]
        except ValueError:
            found = []
    else:
        q = t.lower().replace("-", " ").replace("_", " ")
        found = [s for s in http.HTTPStatus if q in s.phrase.lower() or q in s.name.lower().replace("_", " ")][:12]
    if not found:
        raise ValueError("لا يوجد رمز قياسي مطابق.")
    out = []
    for s in found:
        note = _HTTP_NOTE.get(s.value)
        out.append(f"{s.value} {s.phrase} · {_HTTP_CLASS.get(s.value // 100, '?')}\n   {s.description}" + (f"\n   {note}" if note else ""))
    return "\n".join(out)


# ------------------------------------------------------------------ HMAC / hexdump


def hmac_tool(text: str) -> str:
    if " :: " not in text:
        raise ValueError("الصيغة: المفتاح :: الرسالة")
    key, msg = text.split(" :: ", 1)
    key, msg = key.strip(), msg.lstrip(" ")
    if not key:
        raise ValueError("المفتاح فارغ.")
    k, m = key.encode("utf-8"), msg.encode("utf-8")
    sha256 = hmac.new(k, m, hashlib.sha256)
    return (f"HMAC-SHA256: {sha256.hexdigest()}\nHMAC-SHA1:   {hmac.new(k, m, hashlib.sha1).hexdigest()}\n"
            f"HMAC-SHA512: {hmac.new(k, m, hashlib.sha512).hexdigest()}\nSHA256 (base64): {base64.b64encode(sha256.digest()).decode()}")


def hexdump(text: str) -> str:
    data = text.encode("utf-8")
    if not data:
        raise ValueError("اكتب نصاً.")
    cut = data[:1024]
    rows = []
    for off in range(0, len(cut), 16):
        chunk = cut[off:off + 16]
        hx = " ".join(f"{b:02x}" for b in chunk[:8]) + "  " + " ".join(f"{b:02x}" for b in chunk[8:])
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append(f"{off:08x}  {hx:<49} |{asc}|")
    rows.append(f"{len(cut):08x}" + (f"  (اقتُطع من {len(data)} بايت)" if len(data) > len(cut) else ""))
    return "\n".join(rows)


_RUN = {"entropy": entropy, "homoglyph": homoglyph, "urlparse": url_breakdown, "base": base_convert, "totp": totp_tool,
        "port": port_info, "httpstatus": http_status, "hmac": hmac_tool, "hexdump": hexdump}


def run(kind: str, text: str):
    fn = _RUN.get(kind)
    return fn(text or "") if fn else None
