"""Decode and audit a JWT without verifying it (never trust the claims, only inspect them)."""
from __future__ import annotations

import base64
import json
import re
import time


def _b64json(part: str):
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


def inspect(token: str, now: float | None = None) -> dict:
    token = re.sub(r"^(?:bearer\s+)", "", token.strip(), flags=re.I)
    parts = token.split(".")
    if len(parts) != 3 or not all(re.fullmatch(r"[A-Za-z0-9_-]*", p) for p in parts):
        return {"ok": False}
    try:
        header, payload = _b64json(parts[0]), _b64json(parts[1])
    except Exception:
        return {"ok": False}
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return {"ok": False}
    now = now or time.time()
    flags = []
    alg = str(header.get("alg", ""))
    if alg.lower() in ("none", ""):
        flags.append("alg_none")
    elif alg.startswith("HS"):
        flags.append("hs_shared")
    if not parts[2]:
        flags.append("no_sig")
    for k in ("jku", "x5u", "jwk"):
        if k in header:
            flags.append("key_url")
            break
    if "kid" in header:
        flags.append("kid")
    exp, iat = payload.get("exp"), payload.get("iat")
    if isinstance(exp, (int, float)):
        if exp < now:
            flags.append("expired")
        elif isinstance(iat, (int, float)) and exp - iat > 30 * 86400:
            flags.append("long_lived")
    else:
        flags.append("no_exp")
    nbf = payload.get("nbf")
    if isinstance(nbf, (int, float)) and nbf > now:
        flags.append("not_yet")
    for k in ("aud", "iss"):
        if k not in payload:
            flags.append(f"no_{k}")
    return {"ok": True, "header": header, "payload": payload, "flags": flags}


FLAG_TEXT = {
    "alg_none": ("🔴 الخوارزمية none: أي شخص يستطيع تزوير التوكن.", "🔴 alg=none: anyone can forge this token."),
    "no_sig": ("🔴 لا يوجد توقيع.", "🔴 No signature present."),
    "hs_shared": ("🟡 HS*: سر مشترك، تأكد أنه طويل وعشوائي وأن الخادم يثبّت الخوارزمية.",
                  "🟡 HS*: shared secret, ensure it is long/random and the server pins the algorithm."),
    "key_url": ("🟠 الترويسة تشير لمفتاح خارجي (jku/x5u/jwk): خطر حقن مفتاح.",
                "🟠 Header points to an external key (jku/x5u/jwk): key-injection risk."),
    "kid": ("🟡 وجود kid: تحقق من تعقيمه (حقن SQL/مسارات).", "🟡 kid present: make sure it is sanitized (SQLi/path traversal)."),
    "expired": ("⏰ التوكن منتهي الصلاحية.", "⏰ Token is expired."),
    "long_lived": ("🟡 عمر التوكن أكثر من 30 يوماً.", "🟡 Lifetime longer than 30 days."),
    "no_exp": ("🟠 لا يوجد exp: التوكن لا ينتهي.", "🟠 No exp claim: token never expires."),
    "not_yet": ("⏳ التوكن غير صالح بعد (nbf).", "⏳ Not valid yet (nbf)."),
    "no_aud": ("🟡 لا يوجد aud.", "🟡 No aud claim."),
    "no_iss": ("🟡 لا يوجد iss.", "🟡 No iss claim."),
}


def describe(res: dict, lang: str) -> str:
    i = 0 if lang == "ar" else 1
    dump = lambda o: json.dumps(o, ensure_ascii=False, indent=1)[:900]
    out = ["🪪 JWT", "Header:\n" + dump(res["header"]), "Payload:\n" + dump(res["payload"])]
    for k in ("exp", "iat", "nbf"):
        v = res["payload"].get(k)
        if isinstance(v, (int, float)):
            out.append(f"{k}: " + time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(v)))
    out += [FLAG_TEXT[f][i] for f in res["flags"] if f in FLAG_TEXT]
    out.append("ℹ️ " + ("لم يُتحقق من التوقيع. لا تثق بأي ادعاء قبل التحقق." if lang == "ar"
                         else "Signature NOT verified. Do not trust claims until verified."))
    return "\n".join(out)
