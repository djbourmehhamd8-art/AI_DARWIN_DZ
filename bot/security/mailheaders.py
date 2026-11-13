"""Phishing-oriented analysis of raw email headers."""
from __future__ import annotations

import re
from email.parser import HeaderParser
from email.utils import getaddresses

_IP = re.compile(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?")


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip(" >") if "@" in addr else ""


def _addr(header: str | None) -> str:
    pairs = getaddresses([header or ""])
    return pairs[0][1].lower() if pairs and pairs[0][1] else ""


def _auth(value: str, key: str) -> str:
    m = re.search(rf"\b{key}\s*=\s*(\w+)", value, re.I)
    return m.group(1).lower() if m else "none"


def analyze(raw: str) -> dict:
    msg = HeaderParser().parsestr(raw.strip() + "\n\n")
    if not msg.keys():
        return {"ok": False}
    frm, reply, ret = _addr(msg["From"]), _addr(msg["Reply-To"]), _addr(msg["Return-Path"])
    auth = " ".join(msg.get_all("Authentication-Results") or []) + " " + " ".join(msg.get_all("Received-SPF") or [])
    spf, dkim, dmarc = _auth(auth, "spf"), _auth(auth, "dkim"), _auth(auth, "dmarc")
    if spf == "none":
        m = re.match(r"\s*(pass|fail|softfail|neutral|none)", " ".join(msg.get_all("Received-SPF") or []), re.I)
        spf = m.group(1).lower() if m else "none"
    received = msg.get_all("Received") or []
    hops = [(_IP.findall(r) or [""])[0] for r in received]
    mid = _domain(re.sub(r"[<>]", "", msg["Message-ID"] or ""))
    flags = []
    if spf in ("fail", "softfail"):
        flags.append("spf_fail")
    elif spf == "none":
        flags.append("spf_missing")
    if dkim in ("fail", "none"):
        flags.append("dkim_bad")
    if dmarc in ("fail", "none"):
        flags.append("dmarc_bad")
    if reply and _domain(reply) != _domain(frm):
        flags.append("reply_mismatch")
    if ret and frm and _domain(ret) != _domain(frm):
        flags.append("return_mismatch")
    if mid and frm and _domain(mid) != _domain(frm):
        flags.append("msgid_mismatch")
    if re.search(r"[^\x00-\x7f]", msg["From"] or "") or "xn--" in (msg["From"] or "").lower():
        flags.append("from_unicode")
    disp = re.sub(r"<.*?>", "", msg["From"] or "")
    if "@" in disp:
        flags.append("display_spoof")
    return {"ok": True, "from": frm, "reply_to": reply, "return_path": ret, "spf": spf, "dkim": dkim,
            "dmarc": dmarc, "hops": len(received), "origin_ip": next((h for h in reversed(hops) if h), ""),
            "subject": (msg["Subject"] or "")[:120], "flags": flags}


FLAG_TEXT = {
    "spf_fail": ("🔴 SPF فشل: الخادم المرسل غير مخوّل.", "🔴 SPF failed: sender not authorized."),
    "spf_missing": ("🟡 لا توجد نتيجة SPF.", "🟡 No SPF result."),
    "dkim_bad": ("🟠 DKIM فاشل أو غائب.", "🟠 DKIM failed or missing."),
    "dmarc_bad": ("🟠 DMARC فاشل أو غائب.", "🟠 DMARC failed or missing."),
    "reply_mismatch": ("🔴 Reply-To بنطاق مختلف عن From (نمط احتيال شائع).", "🔴 Reply-To domain differs from From (classic fraud pattern)."),
    "return_mismatch": ("🟡 Return-Path بنطاق مختلف عن From.", "🟡 Return-Path domain differs from From."),
    "msgid_mismatch": ("🟡 Message-ID من نطاق مختلف.", "🟡 Message-ID from a different domain."),
    "from_unicode": ("🟠 المرسل يحتوي حروفاً غير لاتينية/Punycode.", "🟠 Sender contains non-Latin chars/Punycode."),
    "display_spoof": ("🔴 الاسم الظاهر يحتوي بريداً مزيفاً.", "🔴 Display name embeds a fake address."),
}


def describe(res: dict, lang: str) -> str:
    from .ioc import defang
    i = 0 if lang == "ar" else 1
    lines = ["📧 " + ("تحليل ترويسة البريد" if lang == "ar" else "Email header analysis"),
             f"From: {defang(res['from'])}  |  Reply-To: {defang(res['reply_to'] or '-')}",
             f"SPF: {res['spf']} · DKIM: {res['dkim']} · DMARC: {res['dmarc']}",
             ("القفزات: " if lang == "ar" else "Hops: ") + str(res["hops"])
             + (f" · IP: {defang(res['origin_ip'])}" if res["origin_ip"] else "")]
    lines += [FLAG_TEXT[f][i] for f in res["flags"]]
    if not res["flags"]:
        lines.append("✅ " + ("لا مؤشرات واضحة في الترويسة." if lang == "ar" else "No obvious header red flags."))
    return "\n".join(lines)
