"""Password strength estimation, secure generation and k-anonymity breach lookup."""
from __future__ import annotations

import hashlib
import math
import re
import secrets
import string

COMMON = frozenset("""password 123456 12345678 qwerty abc123 111111 123123 admin letmein welcome monkey dragon
iloveyou football master login passw0rd azerty algerie 123456789 000000 1q2w3e4r qwertyuiop sunshine princess
trustno1 whatever hello freedom shadow""".split())
_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "azertyuiop", "1234567890")


def _pool(pw: str) -> int:
    pool = 0
    if re.search(r"[a-z]", pw):
        pool += 26
    if re.search(r"[A-Z]", pw):
        pool += 26
    if re.search(r"\d", pw):
        pool += 10
    if re.search(r"[^\w\s]", pw):
        pool += 33
    if re.search(r"[^\x00-\x7f]", pw):
        pool += 100
    return pool or 1


def _patterns(pw: str) -> list:
    low, found = pw.lower(), []
    if low in COMMON or re.sub(r"\d+$", "", low) in COMMON:
        found.append("common")
    if re.search(r"(.)\1{2,}", pw):
        found.append("repeat")
    for row in _ROWS:
        for i in range(len(row) - 3):
            if row[i:i + 4] in low or row[i:i + 4][::-1] in low:
                found.append("keyboard")
                break
        if "keyboard" in found:
            break
    if re.search(r"(?:19|20)\d{2}", pw):
        found.append("year")
    if pw.isalpha() or pw.isdigit():
        found.append("one_class")
    if len(pw) < 12:
        found.append("short")
    return found


def analyze(pw: str) -> dict:
    """Return entropy bits, 0-4 score, crack-time estimate and a list of issue codes."""
    if not pw:
        return {"bits": 0.0, "score": 0, "issues": ["short"], "crack": "instant", "length": 0}
    bits = len(pw) * math.log2(_pool(pw))
    issues = _patterns(pw)
    if "common" in issues:
        bits = min(bits, 10)
    if "repeat" in issues:
        bits *= 0.75
    if "keyboard" in issues:
        bits *= 0.7
    if "year" in issues:
        bits -= 8
    bits = max(0.0, bits)
    score = 0 if bits < 28 else 1 if bits < 40 else 2 if bits < 60 else 3 if bits < 80 else 4
    return {"bits": round(bits, 1), "score": score, "issues": issues, "crack": _crack_time(bits), "length": len(pw)}


def _crack_time(bits: float, rate: float = 1e10) -> str:
    """Average time for an offline attacker doing `rate` guesses/s against a fast hash."""
    sec = (2 ** max(bits, 0) / 2) / rate
    for unit, size in (("years", 31_557_600), ("days", 86400), ("hours", 3600), ("minutes", 60)):
        if sec >= size:
            n = sec / size
            return f">1e6 {unit}" if n > 1e6 else f"{n:,.0f} {unit}"
    return "<1 min"


def generate(length: int = 20, symbols: bool = True) -> str:
    """Cryptographically secure random password containing every selected class."""
    length = max(8, min(int(length), 128))
    classes = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        classes.append("!@#$%^&*()-_=+[]{};:,.?")
    alphabet = "".join(classes)
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in cls for c in pw) for cls in classes):
            return pw


def pwned_count(pw: str, fetch) -> int:
    """Have I Been Pwned range API. Only the first 5 hex chars of the SHA-1 leave this machine.

    `fetch(prefix) -> str` returns the raw range response; returns -1 if the lookup failed.
    """
    digest = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    try:
        body = fetch(prefix)
    except Exception:
        return -1
    for line in (body or "").splitlines():
        h, _, n = line.partition(":")
        if h.strip() == suffix:
            return int(n.strip() or 0)
    return 0


ISSUE_TEXT = {
    "common": ("كلمة مرور شائعة جداً", "Very common password"),
    "repeat": ("أحرف مكررة", "Repeated characters"),
    "keyboard": ("تسلسل لوحة مفاتيح", "Keyboard pattern"),
    "year": ("تحتوي سنة", "Contains a year"),
    "one_class": ("نوع واحد من الأحرف", "Single character class"),
    "short": ("أقل من 12 حرفاً", "Shorter than 12 characters"),
}


def describe(res: dict, lang: str, pwned: int | None = None) -> str:
    labels = (["حرجة", "ضعيفة", "مقبولة", "قوية", "ممتازة"] if lang == "ar"
              else ["Critical", "Weak", "Fair", "Strong", "Excellent"])
    icons = ["🔴", "🟠", "🟡", "🟢", "💎"]
    i = 0 if lang == "ar" else 1
    lines = [("🔐 تحليل كلمة المرور" if lang == "ar" else "🔐 Password analysis"),
             (f"{icons[res['score']]} القوة: {labels[res['score']]}" if lang == "ar"
              else f"{icons[res['score']]} Strength: {labels[res['score']]}"),
             (f"الطول: {res['length']} · الإنتروبيا: {res['bits']} بت · كسرها دون اتصال ≈ {res['crack']}" if lang == "ar"
              else f"Length: {res['length']} · Entropy: {res['bits']} bits · offline crack ≈ {res['crack']}")]
    lines += [f"• {ISSUE_TEXT[c][i]}" for c in res["issues"]]
    if pwned is not None:
        if pwned > 0:
            lines.append(f"🚨 " + (f"ظهرت في تسريبات {pwned:,} مرة. لا تستخدمها أبداً." if lang == "ar"
                                  else f"Found in breaches {pwned:,} times. Never use it."))
        elif pwned == 0:
            lines.append("✅ " + ("غير موجودة في التسريبات المعروفة." if lang == "ar" else "Not found in known breaches."))
    lines.append("🧹 " + ("حذفتُ رسالتك ولم أحفظها. الأفضل ألا ترسل كلمة مرور حقيقية لأي بوت." if lang == "ar"
                          else "I removed your message and did not store it. Avoid sending real passwords to any bot."))
    return "\n".join(lines)
