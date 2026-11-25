"""Web panel extras: offline tools, audit log and system status pages (mixin for WebPanel).

Same security model as the rest of the panel: token login, CSRF on every POST, no JavaScript, every value escaped.
The AI chat is NOT here any more: it is its own website (bot/webchat.py).
"""
from __future__ import annotations

import html
import logging
import time

from . import moretools as MT
from . import proutils as P
from .utils import safe_int
from . import __version__

log = logging.getLogger("bot.web")

PUBLIC_RATE = 30                    # public tool runs per minute per IP

WEB_TOOLS = (
    ("calc", "🧮 حاسبة"), ("unit", "📏 محوّل وحدات"), ("pct", "％ نسبة مئوية"), ("json", "🧾 منسّق JSON"),
    ("regex", "🧩 مختبر Regex (النمط :: النص)"), ("textstat", "🔤 إحصاءات نص"), ("uniq", "🧹 إزالة التكرار"),
    ("b64", "🔓 Base64 ترميز/فك"), ("urlenc", "🔗 ترميز URL"), ("color", "🎨 محوّل ألوان"),
    ("caseconv", "🔡 تحويل الحالة"), ("slug", "🏷 Slug"), ("roll", "🎲 نرد / عشوائي"), ("uuid", "🆔 UUID"),
    ("genpass", "🎲 مولّد كلمة مرور (الطول)"),
    ("hash", "#️⃣ بصمات Hash (MD5/SHA…) + تعريف نوع hash"), ("pass", "🔐 قوة كلمة المرور (لا تُخزَّن)"),
    ("jwt", "🪪 فحص JWT (بلا تحقق من التوقيع)"), ("cvss", "📊 حاسبة CVSS 3.x (المتجه)"),
    ("decode", "🕵️ فك ترميز متعدد الطبقات"), ("ts", "🕒 محوّل الطوابع الزمنية"), ("ioc", "🎯 استخراج مؤشرات IOC"),
    ("csp", "🛡 فاحص CSP"), ("cookie", "🍪 فاحص Set-Cookie"), ("secheaders", "🧱 تقييم ترويسات الأمان"),
    ("subnet", "🕸 حاسبة الشبكات الفرعية"), ("cron", "⏰ مفسّر Cron"),
    ("spf", "📨 فاحص SPF"), ("dmarc", "📬 فاحص DMARC"), ("secrets", "🕵️ كاشف الأسرار المسرّبة"), ("sri", "🔒 هاش SRI"),
    ("chmod", "🔑 حاسبة chmod"), ("cidrmatch", "🎯 هل IP ضمن نطاق؟ (IP in CIDR)"), ("ipconv", "🔁 تحويل IP"),
    ("useragent", "🧑‍💻 محلّل User-Agent"), ("diff", "🔀 مقارنة نصين (--- بينهما)"), ("date", "📅 حاسبة التواريخ"),
) + MT.EXTRA_TOOLS
# tools offered on the PUBLIC page (no login): pure offline computation, nothing is stored or sent anywhere
PUBLIC_TOOLS = tuple(k for k, _ in WEB_TOOLS)


def _e(x) -> str:
    return html.escape(str(x if x is not None else ""), quote=True)


def run_web_tool(kind: str, text: str) -> str:
    """Run one offline tool; returns plain text (raises ValueError with a short message on bad input)."""
    text = (text or "")[:P.MAX_INPUT]
    if kind == "calc":
        return f"{text.strip()} = {P.calc(text)}"
    if kind == "unit":
        r = P.convert_units(text)
        return f"{r['value']:g} {r['from']} = {r['result']:g} {r['to']}  ({r['group']})"
    if kind == "pct":
        return P.percent(text)["text"]
    if kind == "json":
        r = P.json_pretty(text)
        return f"✅ valid JSON · {r['type']} · {r['size']}\n\n{r['pretty']}\n\n— compact —\n{r['compact']}"
    if kind == "regex":
        r = P.regex_test(text)
        lines = [f"{r['count']} match(es) for {r['pattern']}"]
        for i, m in enumerate(r["matches"], 1):
            lines.append(f"{i}. {m['text']!r} @ {m['span'][0]}-{m['span'][1]}" + (f"  groups={m['groups']}" if m["groups"] else ""))
        return "\n".join(lines)
    if kind == "textstat":
        r = P.text_stats(text)
        top = " · ".join(f"{w}×{n}" for w, n in r["top"]) or "-"
        return (f"words {r['words']} ({r['unique_words']} unique) · chars {r['chars']} ({r['chars_no_space']} without spaces) · "
                f"bytes {r['bytes']} · lines {r['lines']} · ~{r['read_minutes']} min\ntop: {top}")
    if kind == "uniq":
        r = P.dedupe_sort(text)
        return f"{r['total']} → {r['unique']} (removed {r['removed']})\n\n{r['result']}"
    if kind == "b64":
        r = P.b64(text)
        return f"{r['mode']}:\n{r['result']}"
    if kind == "urlenc":
        r = P.url_codec(text)
        return f"{r['mode']}:\n{r['result']}"
    if kind == "color":
        r = P.color_convert(text)
        return f"{r['hex']}\n{r['rgb']}\n{r['hsl']}"
    if kind == "caseconv":
        return "\n".join(f"{k}: {v}" for k, v in P.case_convert(text))
    if kind == "slug":
        return P.slugify(text)
    if kind == "roll":
        r = P.rand_roll(text)
        return str(r["result"]) if r["kind"] != "dice" else f"{' + '.join(map(str, r['rolls']))} = {r['result']}"
    if kind == "uuid":
        n = safe_int(text, 3)
        return "\n".join(P.make_uuids(n))
    if kind == "genpass":
        n = safe_int(text, 20)
        return P.make_password(n)
    if kind == "hash":
        from .security import hashing as H
        d = "\n".join(f"{k.upper():9} {v}" for k, v in H.digests(text).items())
        ident = H.identify(text.strip()) if H.looks_like_hash(text.strip()) else []
        return d + (("\n\nيشبه: " + " / ".join(ident)) if ident else "")
    if kind == "pass":
        from .security import password as PW
        return "\n".join(x for x in PW.describe(PW.analyze(text), "ar").splitlines() if not x.startswith("🧹"))
    if kind == "jwt":
        from .security import jwt_tool as J
        res = J.inspect(text.strip())
        if not res["ok"]:
            raise ValueError("ليس JWT صالحاً (يجب أن يكون header.payload.signature بترميز base64url)")
        return J.describe(res, "ar")
    if kind == "cvss":
        from .security import cvss as C
        r = C.calculate(text.strip())
        if not r["ok"]:
            raise ValueError("متجه CVSS غير صالح. مثال: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        return C.describe(r, "ar")
    if kind == "decode":
        from .security import decoder as D
        chain = D.decode_chain(text)
        if not chain:
            return "لا توجد طبقات ترميز معروفة (url / hex / base64).\nROT13: " + D.rot13(text)
        return "\n".join(f"{i}. {n}: {v[:500]}" for i, (n, v) in enumerate(chain, 1))
    if kind == "ts":
        from .security import timestamps as T
        r = T.analyze(text)
        if not r["ok"]:
            raise ValueError("اكتب رقماً (Unix/FILETIME) أو تاريخاً ISO مثل 2026-11-22T10:00:00Z")
        return "\n".join(f"{n}: {v}" for n, v in r["items"])
    if kind == "ioc":
        from .security import ioc as I
        r = I.extract(text)
        lines = [f"{k}: {len(v)}\n  " + "\n  ".join(I.defang(x) if k in ("urls", "domains", "ips", "emails") else x for x in v[:50])
                 for k, v in r.items() if v]
        return "\n".join(lines) or "لم يُعثر على مؤشرات."
    if kind in ("csp", "cookie", "secheaders"):
        from .security import webconfig as W
        fn = {"csp": W.analyze_csp, "cookie": W.analyze_cookie, "secheaders": W.analyze_headers}[kind]
        return W.render_plain(fn(text), "ar")
    if kind == "subnet":
        r = P.subnet_calc(text)
        lines = [f"{r['cidr']} (IPv{r['version']})", f"netmask {r['netmask']}" + (f" · wildcard {r['wildcard']}" if r["wildcard"] else ""),
                 f"range {r['first']} -> {r['last']}" + (f" · broadcast {r['broadcast']}" if r["broadcast"] else ""),
                 f"usable hosts {r['hosts']:,} of {r['addresses']:,} · {'private' if r['private'] else 'public'}"]
        if r["subnets"]:
            lines += [f"{r['subnet_count']} subnets:"] + r["subnets"]
        return "\n".join(lines)
    if kind == "cron":
        r = P.cron_explain(text)
        return "\n".join([r["expr"]] + [x["phrase"][0] for x in r["fields"]] + ["", "Next runs:"] + (r["next"] or ["-"]))
    if kind in ("spf", "dmarc"):
        from .security import mailauth as M
        from .security import webconfig as W
        return W.render_plain((M.analyze_spf if kind == "spf" else M.analyze_dmarc)(text), "ar")
    if kind == "secrets":
        from .security import mailauth as M
        r = M.scan_secrets(text)
        if not r["count"]:
            return "لم أجد أسراراً معروفة (الفحص يعتمد على أنماط محددة)."
        return f"{r['count']} سرّ محتمل ({r['high']} عالي الخطورة)\n" + "\n".join(f"[{h['severity']}] {h['type']} · سطر {h['line']}: {h['masked']}" for h in r["hits"])
    if kind == "sri":
        from . import devtools as DV
        r = DV.sri_hash(text)
        return "\n".join(f"{k}: {v}" for k, v in r["hashes"].items()) + "\n\n" + r["tag"]
    if kind == "chmod":
        from . import devtools as DV
        r = DV.chmod_calc(text)
        return f"{r['octal']}  {r['symbolic']}  (umask {r['umask']})" + "".join(f"\n[{n[0]}] {n[1]}" for n in r["notes"])
    if kind == "cidrmatch":
        from . import devtools as DV
        r = DV.cidr_match(text)
        return f"{r['matched']}/{r['total']} ضمن النطاقات\n" + "\n".join(f"{'✅' if x['match'] else '❌'} {x['ip']}" + (f" ⊂ {', '.join(x['match'])}" if x["match"] else "") for x in r["rows"])
    if kind == "ipconv":
        from . import devtools as DV
        return "\n".join(f"{k}: {v}" for k, v in DV.ip_convert(text))
    if kind == "useragent":
        from . import devtools as DV
        r = DV.parse_user_agent(text)
        return f"{r['browser']} {r['browser_version']} · {r['os']} {r['os_version']}" + (" · mobile" if r["mobile"] else "") + "".join(f"\n[{f[0]}] {f[1]}" for f in r["flags"])
    if kind == "diff":
        from . import devtools as DV
        r = DV.text_diff(text)
        return "النصان متطابقان." if r["identical"] else f"+{r['added']} −{r['removed']} · تشابه ≈ {r['similarity']}%\n\n{r['diff']}"
    if kind == "date":
        from . import devtools as DV
        return "\n".join(f"{k}: {v}" for k, v in DV.date_calc(text).items())
    out = MT.run(kind, text)
    if out is not None:
        return out
    raise ValueError("unknown tool")


class WebExtMixin:
    # ================================================================== navigation
    def nav(self, active: str, csrf: str) -> str:
        from .webui import sidebar
        counts = self.db.web_counts()
        rep = self.db.report_counts()["open"]
        badges = {"reports": (rep, "bad"), "users": (counts["pending"], "warn")}
        return ('<input type="checkbox" id="nv" class="navtoggle" aria-label="القائمة"><label class="scrim" for="nv"></label>'
                f'<aside class="side" aria-label="التنقل">{sidebar(active, badges)}</aside>'
                '<header class="top"><label class="burger" for="nv" aria-hidden="true">☰</label>'
                '<form class="gsearch" method="get" action="/" role="search"><input type="search" name="q" maxlength="64" '
                'placeholder="🔎 بحث سريع عن مستخدم: معرّف أو @اسم أو اسم" aria-label="بحث"><button>بحث</button></form><span class="sp"></span>'
                f'<form method="post" action="/logout"><input type="hidden" name="csrf" value="{_e(csrf)}"><button>خروج</button></form></header>')

    _BAD_FLASH = ("🔍", "🚫", "🛡", "☑️", "✍️", "⚠️", "⏳", "قيمة", "إجراء", "تعذّر", "لا ", "فعّل")

    def _flash(self, sess: dict) -> str:
        flash, sess["flash"] = sess.get("flash") or "", ""
        if not flash:
            return ""
        cls = "bad" if flash.startswith(self._BAD_FLASH[:3] + ("⚠️",)) else "warn" if flash.startswith(self._BAD_FLASH[3:]) else ""
        return f'<div class="flash {cls}" role="status">{_e(flash)}</div>'

    # ================================================================== tools page
    def tools_page(self, sess: dict) -> bytes:
        csrf = sess["csrf"]
        cur = sess.get("tool") if sess.get("tool") in dict(WEB_TOOLS) else "calc"
        opts = "".join(f'<option value="{k}"{" selected" if k == cur else ""}>{_e(t)}</option>' for k, t in WEB_TOOLS)
        out = sess.get("tool_out") or ""
        out_html = f'<pre class="out">{_e(out)}</pre>' if out else ""
        form = (f'<form class="chatform" method="post" action="/tools/run"><input type="hidden" name="csrf" value="{_e(csrf)}">'
                f'<select name="tool">{opts}</select><textarea name="text" rows="5" maxlength="{P.MAX_INPUT}" '
                f'placeholder="أدخل النص أو العملية…">{_e(sess.get("tool_in") or "")}</textarea>'
                f'<div class="row"><button class="p">تشغيل ▶️</button></div></form>')
        body = (f'{self.nav("tools", csrf)}<main>{self._flash(sess)}<h2>🧰 أدوات سريعة (تعمل دون إنترنت)</h2>{form}{out_html}'
                f'<p class="mut">أمثلة: حاسبة <code>(12+8)*3</code> · وحدات <code>10 km to mi</code> · regex <code>\\d+ :: abc 123</code></p></main>')
        return self.page(body, "الأدوات")

    def tools_run(self, sess: dict, kind: str, text: str) -> None:
        sess["tool"], sess["tool_in"] = kind, (text or "")[:2000]
        if kind not in dict(WEB_TOOLS):
            sess["tool_out"] = "أداة غير معروفة."
            return
        try:
            sess["tool_out"] = run_web_tool(kind, text)
        except ValueError as e:
            sess["tool_out"] = f"⚠️ {e}"

    # ================================================================== public tools (no login)
    def public_tools_page(self, kind: str = "calc", text: str = "", out: str = "", error: str = "") -> bytes:
        kind = kind if kind in PUBLIC_TOOLS else "calc"
        opts = "".join(f'<option value="{k}"{" selected" if k == kind else ""}>{_e(t)}</option>' for k, t in WEB_TOOLS)
        err = f'<div class="flash bad">{_e(error)}</div>' if error else ""
        out_html = f'<pre class="out">{_e(out)}</pre>' if out else ""
        form = (f'<form class="chatform" method="post" action="/t"><select name="tool">{opts}</select>'
                f'<textarea name="text" rows="5" maxlength="{P.MAX_INPUT}" placeholder="أدخل النص أو العملية…">{_e(text)}</textarea>'
                f'<div class="row"><button class="p">تشغيل ▶️</button></div></form>')
        body = (f'<header><h1>🛡 DARWIN DZ</h1><nav class="tabs nav"><a href="/">الرئيسية</a><a class="on" href="/t">🧰 الأدوات</a></nav></header>'
                f'<main><h2>🧰 أدوات مجانية (تعمل على الخادم دون حفظ شيء)</h2>{err}{form}{out_html}'
                f'<p class="mut">لا تُخزَّن المدخلات ولا النتائج. أمثلة: حاسبة <code>(12+8)*3</code> · وحدات <code>10 km to mi</code> · '
                f'regex <code>\\d+ :: abc 123</code>. تجنّب إدخال كلمات مرور حقيقية.</p></main>')
        return self.page(body, "الأدوات")

    def public_tools_run(self, ip: str, kind: str, text: str) -> tuple:
        """-> (status, page). Per-IP rate limited; never raises."""
        now = time.time()
        with self._lock:
            hits = [t for t in self.pub_hits.get(ip, []) if now - t < 60]
            if len(hits) >= PUBLIC_RATE:
                self.pub_hits[ip] = hits
                return 429, self.public_tools_page(kind, text[:2000], error="طلبات كثيرة. انتظر دقيقة.")
            hits.append(now)
            self.pub_hits[ip] = hits
            if len(self.pub_hits) > 2000:
                self.pub_hits = {k: v for k, v in self.pub_hits.items() if v and now - v[-1] < 60}
        if kind not in PUBLIC_TOOLS:
            return 400, self.public_tools_page("calc", text[:2000], error="أداة غير معروفة.")
        try:
            return 200, self.public_tools_page(kind, text[:2000], out=run_web_tool(kind, text))
        except ValueError as e:
            return 200, self.public_tools_page(kind, text[:2000], error=f"⚠️ {e}")
        except Exception:                                   # a tool bug must never take the page down
            log.exception("public tool failed: %s", kind)
            return 500, self.public_tools_page(kind, text[:2000], error="تعذّر تنفيذ الأداة.")

    # ================================================================== audit / system
    def system_page(self, sess: dict) -> bytes:
        from .utils import fmt_duration
        import platform
        counts = self.db.web_counts()
        keys = self.app.ai.pool.status()
        key_rows = "".join(
            f'<tr><td><code>{_e(k["key"])}</code></td><td><span class="b {"ok" if k["ok"] else "bad"}">{"🟢 متاح" if k["ok"] else "🔴 معطّل"}</span></td>'
            f'<td>{_e(k["last"])}</td><td>{k["fails"]}</td><td>{fmt_duration(k["retry_in"]) if not k["ok"] else "-"}</td></tr>' for k in keys)
        st_code, st_text = getattr(self.app, "tg_state", ("ok", ""))
        tg_label = {"ok": "🟢 متصل", "starting": "🟡 يبدأ", "token_rejected": "🔴 التوكن مرفوض (401)",
                    "conflict": "🔴 نسخة أخرى تعمل بنفس التوكن (409)"}.get(st_code, "🟠 مشكلة اتصال")
        hint = {"token_rejected": "ضع توكن صحيحاً في TELEGRAM_TOKEN (أنشئ/أعد توليد التوكن من @BotFather) ثم أعد النشر.",
                "conflict": "أوقف أي نسخة أخرى من البوت (Termux أو سيرفر آخر أو نشر ثانٍ) أو أعد توليد التوكن من @BotFather."}.get(st_code, "")
        info = (("تيليجرام", tg_label), ("الإصدار", __version__), ("Python", platform.python_version()), ("النموذج", self.cfg.model),
                ("مدة التشغيل", fmt_duration(time.time() - self.app.started)), ("الوضع", "مفتوح PUBLIC" if self.cfg.public else "خاص"),
                ("الصيانة", "تعمل" if self.app.maintenance else "متوقفة"), ("المستخدمون", counts["all"]),
                ("مفاتيح API المتاحة", f'{sum(1 for k in keys if k["ok"])}/{len(keys)}'))
        stats = "".join(f'<div class="stat"><b>{_e(v)}</b><span>{_e(k)}</span></div>' for k, v in info)
        table = ('<div class="wrap"><table style="min-width:500px"><thead><tr><th>المفتاح</th><th>الحالة</th><th>آخر كود</th><th>إخفاقات</th><th>إعادة بعد</th></tr></thead><tbody>'
                 + (key_rows or '<tr><td colspan="5" class="mut">لا توجد مفاتيح.</td></tr>') + '</tbody></table></div>')
        hint_html = f'<div class="flash bad">{_e(st_text)} {_e(hint)}</div>' if hint else ""
        return self.page(f'{self.nav("system", sess["csrf"])}<main>{self._flash(sess)}<h2>🩺 حالة النظام</h2>{hint_html}<div class="stats">{stats}</div>'
                         f'<h3>🔑 مفاتيح API</h3>{table}</main>', "النظام")
