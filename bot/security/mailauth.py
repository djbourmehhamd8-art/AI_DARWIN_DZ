"""Offline auditors for email-authentication DNS records (SPF, DMARC) and a scanner for leaked secrets.

Findings are (severity, arabic, english) tuples, the same shape as webconfig.py, so the bot and web panel share rendering.
Secrets are always masked in the output: the scanner never prints a full credential.
"""
from __future__ import annotations

import re

from .webconfig import _score, _sorted, grade

MAX_INPUT = 20000


def _strip_quotes(txt: str) -> str:
    """TXT records arrive as "v=spf1 ..." "...more" split in 255-byte chunks: join them."""
    parts = re.findall(r'"([^"]*)"', txt)
    return "".join(parts) if parts else txt.strip()


# ---------------------------------------------------------------- SPF
def analyze_spf(record: str) -> dict:
    rec = " ".join(_strip_quotes((record or "")[:MAX_INPUT]).split())
    rec = re.sub(r"^(?:[\w.-]+\s+)?(?:IN\s+)?TXT\s+", "", rec, flags=re.I)       # tolerate a pasted zone line
    if not re.match(r"^v=spf1(\s|$)", rec, re.I):
        raise ValueError("an SPF record starts with v=spf1")
    terms = rec.split()[1:]
    F: list = []
    lookups, mechs = 0, []
    all_q = None
    for t in terms:
        low = t.lower()
        q = low[0] if low[0] in "+-~?" else "+"
        body = low.lstrip("+-~?")
        name = re.split(r"[:=/]", body, maxsplit=1)[0]
        mechs.append(name)
        if name in ("include", "a", "mx", "ptr", "exists", "redirect"):
            lookups += 1
        if name == "all":
            all_q = q
        if name == "ptr":
            F.append(("medium", "الآلية ptr مهملة وبطيئة وغير موثوقة (RFC 7208).", "The ptr mechanism is deprecated, slow and unreliable (RFC 7208)."))
        if name.startswith("ip4") or name.startswith("ip6"):
            m = re.match(r"ip[46]:(\S+)", body)
            if m and re.fullmatch(r"(?:0\.0\.0\.0/0|::/0)", m.group(1)):
                F.append(("high", "ip4:0.0.0.0/0 يسمح لأي خادم في العالم بإرسال بريد باسمك.", "ip4:0.0.0.0/0 lets every server on earth send as you."))
            elif m and "/" in m.group(1):
                try:
                    pref = int(m.group(1).rsplit("/", 1)[1])
                    if (name == "ip4" and pref < 16) or (name == "ip6" and pref < 32):
                        F.append(("medium", f"نطاق IP واسع جداً: {m.group(1)[:50]}", f"Very wide IP range: {m.group(1)[:50]}"))
                except ValueError:
                    pass
    if all_q is None and not any(m == "redirect" for m in mechs):
        F.append(("high", "لا يوجد all ولا redirect: السياسة بلا قاعدة افتراضية. أنهِ السجل بـ -all أو ~all.", "No all or redirect: the policy has no default. End the record with -all or ~all."))
    elif all_q == "+":
        F.append(("high", "+all يسمح لأي مرسل: السجل بلا فائدة.", "+all allows any sender: the record is useless."))
    elif all_q == "?":
        F.append(("medium", "?all محايد: لا حماية فعلية. استخدم ~all أو -all.", "?all is neutral: no real protection. Use ~all or -all."))
    elif all_q == "~":
        F.append(("low", "~all (softfail) مقبول أثناء الانتقال، والهدف النهائي -all مع DMARC صارم.", "~all (softfail) is fine while transitioning; aim for -all with a strict DMARC."))
    elif all_q == "-":
        F.append(("good", "-all (فشل صارم) مضبوط.", "-all (hard fail) is set."))
    if lookups > 10:
        F.append(("high", f"{lookups} عمليات بحث DNS تتجاوز الحد 10: سيعطي المستقبِل permerror ويفشل SPF.", f"{lookups} DNS lookups exceed the limit of 10: receivers return permerror and SPF fails."))
    elif lookups >= 8:
        F.append(("medium", f"{lookups} من 10 عمليات بحث: قريب من الحد. فكّر في تسطيح include.", f"{lookups} of 10 lookups used: close to the limit. Consider flattening includes."))
    if len(rec) > 450:
        F.append(("low", f"السجل طويل ({len(rec)} حرفاً): قد يتجاوز حد UDP/الأجزاء 255 بايت إن لم يُقسَّم صحيحاً.", f"Long record ({len(rec)} chars): may break UDP limits / 255-byte chunks if not split correctly."))
    if mechs.count("all") > 1 or (all_q is not None and "all" in mechs and mechs.index("all") != len(mechs) - 1 and "redirect" not in mechs):
        F.append(("medium", "الآليات بعد all تُتجاهل: ضع all أخيراً.", "Mechanisms after all are ignored: put all last."))
    if "redirect" in mechs and "all" in mechs:
        F.append(("low", "redirect يُتجاهل عند وجود all.", "redirect is ignored when all is present."))
    F = _sorted(F)
    fatal = all_q == "+" or any(m.startswith("ip4:0.0.0.0/0") for m in map(str.lower, terms)) or lookups > 10
    sc = _score(F, fatal)
    return {"record": rec[:300], "lookups": lookups, "mechanisms": mechs, "findings": F, "score": sc, "grade": grade(sc)}


# ---------------------------------------------------------------- DMARC
def analyze_dmarc(record: str) -> dict:
    rec = " ".join(_strip_quotes((record or "")[:MAX_INPUT]).split())
    rec = re.sub(r"^(?:_dmarc[\w.-]*\s+)?(?:IN\s+)?TXT\s+", "", rec, flags=re.I)
    if not re.match(r"^v=DMARC1\s*;?", rec, re.I):
        raise ValueError("a DMARC record starts with v=DMARC1;")
    tags: dict = {}
    for part in rec.split(";"):
        k, sep, v = part.strip().partition("=")
        if sep and k.strip().lower() not in tags:
            tags[k.strip().lower()] = v.strip()
    F: list = []
    p = tags.get("p", "").lower()
    if p not in ("none", "quarantine", "reject"):
        F.append(("high", "الوسم p مفقود أو غير صالح (none / quarantine / reject).", "The p tag is missing or invalid (none / quarantine / reject)."))
    elif p == "none":
        F.append(("high", "p=none مراقبة فقط: لا يمنع انتحال نطاقك. انتقل تدريجياً إلى quarantine ثم reject.", "p=none is monitor-only: it does not stop spoofing. Move to quarantine, then reject."))
    elif p == "quarantine":
        F.append(("low", "p=quarantine جيد؛ الهدف النهائي p=reject.", "p=quarantine is good; the end goal is p=reject."))
    else:
        F.append(("good", "p=reject أقوى سياسة.", "p=reject is the strongest policy."))
    sp = tags.get("sp", "").lower()
    if sp == "none" and p in ("quarantine", "reject"):
        F.append(("medium", "sp=none يترك النطاقات الفرعية بلا حماية.", "sp=none leaves subdomains unprotected."))
    pct = tags.get("pct")
    if pct is not None:
        if not pct.isdigit() or not 0 <= int(pct) <= 100:
            F.append(("medium", f"قيمة pct غير صالحة: {pct[:10]}", f"Invalid pct value: {pct[:10]}"))
        elif int(pct) < 100 and p in ("quarantine", "reject"):
            F.append(("medium", f"pct={pct}: السياسة تُطبَّق على جزء من الرسائل فقط.", f"pct={pct}: the policy applies to only part of the mail."))
    if "rua" not in tags:
        F.append(("medium", "لا يوجد rua: لن تصلك تقارير تجميعية لمعرفة من يرسل باسمك.", "No rua: you will not get aggregate reports showing who sends as you."))
    elif not re.match(r"^mailto:", tags["rua"], re.I):
        F.append(("low", "rua يجب أن يبدأ بـ mailto:", "rua must start with mailto:"))
    if "ruf" in tags:
        F.append(("info", "ruf (تقارير جنائية) نادراً ما تُرسَل وقد تحوي بيانات شخصية.", "ruf (forensic reports) are rarely sent and may contain personal data."))
    for tag, label in (("adkim", "DKIM"), ("aspf", "SPF")):
        v = tags.get(tag, "r").lower()
        if v not in ("r", "s"):
            F.append(("low", f"{tag} يجب أن يكون r أو s.", f"{tag} must be r or s."))
        elif v == "r":
            F.append(("info", f"{tag}=r (متساهل) للمحاذاة مع {label}. s أشد.", f"{tag}=r (relaxed) {label} alignment. s is stricter."))
    F = _sorted(F)
    sc = _score(F)
    return {"tags": {k: v[:120] for k, v in tags.items()}, "findings": F, "score": sc, "grade": grade(sc)}


# ---------------------------------------------------------------- secret scanner
# name, regex, severity. Patterns are deliberately specific (prefixes / structure) to keep false positives low.
_PATTERNS = (
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b"), "high"),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b"), "high"),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), "high"),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "high"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "high"),
    ("Stripe secret key", re.compile(r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b"), "high"),
    ("Telegram bot token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"), "high"),
    ("OpenAI-style key", re.compile(r"\bsk-(?:proj-|live-)?[A-Za-z0-9_-]{32,}\b"), "high"),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"), "high"),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*\b"), "medium"),
    ("Credentials in URL", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/:@]{1,64}:[^\s/@]{3,}@[^\s/]+", re.I), "high"),
    ("Bearer token", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}", re.I), "medium"),
    ("Password assignment", re.compile(r"(?i)\b(?:pass(?:word|wd)?|pwd|secret|api[_-]?key|token)\b\s*[:=]\s*['\"]?([^\s'\"#]{6,})"), "medium"),
)
_PLACEHOLDER = re.compile(r"^(?:x{3,}|\*{3,}|<[^>]*>|\$\{?\w+\}?|\{\{.*\}\}|your[_-]?\w*|changeme|example|password|null|none|true|false|\d{1,2})$", re.I)


def mask(secret: str) -> str:
    s = secret.strip()
    if len(s) <= 8:
        return s[:1] + "…" * 1 + f" ({len(s)})"
    return f"{s[:4]}…{s[-2:]} ({len(s)})"


def scan_secrets(text: str) -> dict:
    text = (text or "")[:MAX_INPUT * 5]
    if not text.strip():
        raise ValueError("empty input")
    hits, seen = [], set()
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 4000:
            line = line[:4000]
        for name, rx, sev in _PATTERNS:
            for m in rx.finditer(line):
                val = m.group(1) if (rx.groups and m.group(1)) else m.group(0)
                if _PLACEHOLDER.match(val):
                    continue
                key = (name, val)
                if key in seen:
                    continue
                seen.add(key)
                shown = "-----BEGIN … PRIVATE KEY-----" if name == "Private key block" else mask(val)
                hits.append({"type": name, "severity": sev, "line": lineno, "masked": shown})
    hits.sort(key=lambda h: (0 if h["severity"] == "high" else 1, h["line"]))
    return {"count": len(hits), "hits": hits[:50], "truncated": len(hits) > 50, "high": sum(1 for h in hits if h["severity"] == "high")}
