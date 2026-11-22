"""Web panel extras: AI chat, offline tools, audit log and system status pages (mixin for WebPanel).

Same security model as the rest of the panel: token login, CSRF on every POST, no JavaScript, every value escaped.
The chat history lives only in the logged-in session (memory), it is never written to the database.
"""
from __future__ import annotations

import html
import logging
import time

from . import proutils as P
from .utils import safe_int
from .ai_client import APIError
from .brand import CORE_PROMPT
from .hardening import SAFETY_TAIL
from .personas import PERSONAS
from . import __version__

log = logging.getLogger("bot.web")

CHAT_MAX_MSGS = 24                  # messages kept in a web chat session
CHAT_MAX_CHARS = 24000              # context size sent to the model
CHAT_MAX_INPUT = 4000
CHAT_RATE = (12, 60)                # messages per window (seconds) per session

WEB_TOOLS = (
    ("calc", "🧮 حاسبة"), ("unit", "📏 محوّل وحدات"), ("pct", "％ نسبة مئوية"), ("json", "🧾 منسّق JSON"),
    ("regex", "🧩 مختبر Regex (النمط :: النص)"), ("textstat", "🔤 إحصاءات نص"), ("uniq", "🧹 إزالة التكرار"),
    ("b64", "🔓 Base64 ترميز/فك"), ("urlenc", "🔗 ترميز URL"), ("color", "🎨 محوّل ألوان"),
    ("caseconv", "🔡 تحويل الحالة"), ("slug", "🏷 Slug"), ("roll", "🎲 نرد / عشوائي"), ("uuid", "🆔 UUID"),
    ("genpass", "🎲 مولّد كلمة مرور (الطول)"),
)


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
    raise ValueError("unknown tool")


class WebExtMixin:
    # ================================================================== navigation
    def nav(self, active: str, csrf: str) -> str:
        items = (("/", "users", "👥 المستخدمون"), ("/chat", "chat", "💬 دردشة AI"), ("/tools", "tools", "🧰 الأدوات"),
                 ("/audit", "audit", "🧾 السجل"), ("/system", "system", "🩺 النظام"))
        links = "".join(f'<a class="{"on" if k == active else ""}" href="{h}">{t}</a>' for h, k, t in items)
        return (f'<header><h1>🛡 DARWIN DZ</h1><nav class="tabs nav">{links}</nav><form method="post" action="/logout">'
                f'<input type="hidden" name="csrf" value="{_e(csrf)}"><button>خروج</button></form></header>')

    def _flash(self, sess: dict) -> str:
        flash, sess["flash"] = sess.get("flash") or "", ""
        return f'<div class="flash">{_e(flash)}</div>' if flash else ""

    # ================================================================== AI chat
    def persona_options(self, current: str) -> str:
        return "".join(f'<option value="{_e(k)}"{" selected" if k == current else ""}>{_e(p["ar"])}</option>'
                       for k, p in PERSONAS.items())

    def chat_page(self, sess: dict) -> bytes:
        csrf, hist = sess["csrf"], sess.get("chat") or []
        persona = sess.get("persona") if sess.get("persona") in PERSONAS else "default"
        bubbles = []
        for m in hist:
            who, cls = ("أنت", "me") if m["role"] == "user" else ("DARWIN DZ", "ai")
            bubbles.append(f'<div class="msg {cls}"><b>{who}</b><div class="txt">{_e(m["content"])}</div></div>')
        empty = '<p class="mut">ابدأ المحادثة: اكتب سؤالك أدناه. الرد يصل بعد اكتماله (قد يستغرق حتى دقيقة).</p>' if not bubbles else ""
        form = (f'<form class="chatform" method="post" action="/chat/send"><input type="hidden" name="csrf" value="{_e(csrf)}">'
                f'<select name="persona">{self.persona_options(persona)}</select>'
                f'<textarea name="msg" rows="4" maxlength="{CHAT_MAX_INPUT}" placeholder="اكتب رسالتك…" required autofocus></textarea>'
                f'<div class="row"><button class="p">إرسال ⬆️</button></div></form>')
        clear = (f'<form method="post" action="/chat/clear"><input type="hidden" name="csrf" value="{_e(csrf)}">'
                 f'<button>🗑 محادثة جديدة</button></form>')
        body = (f'{self.nav("chat", csrf)}<main>{self._flash(sess)}<h2>💬 التواصل مع الذكاء الاصطناعي</h2>'
                f'<div class="chat">{empty}{"".join(bubbles)}</div>{form}<div class="row">{clear}</div>'
                f'<p class="mut">المحادثة تُحفظ في جلسة الدخول فقط ولا تُخزَّن في قاعدة البيانات.</p></main>')
        return self.page(body, "دردشة AI")

    def chat_send(self, sess: dict, persona: str, text: str) -> str:
        """-> error text ('' on success). Sync call to the model (the HTTP server is threaded)."""
        text = (text or "").strip()[:CHAT_MAX_INPUT]
        if not text:
            return "اكتب رسالة أولاً."
        now = time.time()
        sess["chat_times"] = [t for t in sess.get("chat_times", []) if now - t < CHAT_RATE[1]]
        if len(sess["chat_times"]) >= CHAT_RATE[0]:
            return "رسائل كثيرة بسرعة. انتظر قليلاً."
        if sess.get("chat_busy"):
            return "ما زال الرد السابق قيد المعالجة."
        persona = persona if persona in PERSONAS else "default"
        sess["persona"] = persona
        p = PERSONAS[persona]
        system = "\n\n".join(x for x in (CORE_PROMPT if p.get("core") else "", self.cfg.system_prompt, p["prompt"],
                                         SAFETY_TAIL if p.get("core") else "") if x)
        hist = list(sess.get("chat") or [])
        hist.append({"role": "user", "content": text})
        kept, total = [], 0
        for m in reversed(hist[-CHAT_MAX_MSGS:]):
            total += len(m["content"])
            if total > CHAT_MAX_CHARS and kept:
                break
            kept.append(m)
        kept.reverse()
        msgs = ([{"role": "system", "content": system}] if system else []) + kept
        sess["chat_times"].append(now)
        sess["chat_busy"] = True
        try:
            reply, usage = self.app.ai.chat(msgs, self.cfg.default_temp, stream=False)
        except APIError as e:
            return self.app._err_text("ar", e).replace("<b>", "").replace("</b>", "")
        except Exception:
            log.exception("web chat failed")
            return "تعذّر الاتصال بالذكاء الاصطناعي الآن."
        finally:
            sess["chat_busy"] = False
        hist.append({"role": "assistant", "content": reply})
        sess["chat"] = hist[-CHAT_MAX_MSGS:]
        try:
            self.db.add_usage(next(iter(sorted(self.cfg.admin_ids)), 0), int(usage.get("prompt_tokens", 0)), int(usage.get("completion_tokens", 0)))
        except Exception:                                   # accounting must never break the chat
            log.debug("web chat usage not recorded", exc_info=True)
        return ""

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

    # ================================================================== audit / system
    def audit_page(self, sess: dict) -> bytes:
        rows = self.db.list_audit(150)
        trs = "".join(f'<tr><td>{_e(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"])))}</td><td><code>{_e(r["user_id"])}</code></td>'
                      f'<td>{_e(r["action"])}</td><td class="mut">{_e((r["detail"] or "")[:120])}</td></tr>' for r in rows)
        table = ('<div class="wrap"><table style="min-width:600px"><thead><tr><th>الوقت</th><th>المنفِّذ</th><th>الإجراء</th><th>تفاصيل</th></tr></thead><tbody>'
                 + (trs or '<tr><td colspan="4" class="mut">لا توجد سجلات.</td></tr>') + '</tbody></table></div>')
        return self.page(f'{self.nav("audit", sess["csrf"])}<main>{self._flash(sess)}<h2>🧾 سجل التدقيق (آخر 150)</h2>{table}</main>', "السجل")

    def system_page(self, sess: dict) -> bytes:
        from .utils import fmt_duration
        import platform
        counts = self.db.web_counts()
        keys = self.app.ai.pool.status()
        key_rows = "".join(
            f'<tr><td><code>{_e(k["key"])}</code></td><td><span class="b {"ok" if k["ok"] else "bad"}">{"🟢 متاح" if k["ok"] else "🔴 معطّل"}</span></td>'
            f'<td>{_e(k["last"])}</td><td>{k["fails"]}</td><td>{fmt_duration(k["retry_in"]) if not k["ok"] else "-"}</td></tr>' for k in keys)
        info = (("الإصدار", __version__), ("Python", platform.python_version()), ("النموذج", self.cfg.model),
                ("مدة التشغيل", fmt_duration(time.time() - self.app.started)), ("الوضع", "مفتوح PUBLIC" if self.cfg.public else "خاص"),
                ("الصيانة", "تعمل" if self.app.maintenance else "متوقفة"), ("المستخدمون", counts["all"]),
                ("مفاتيح API المتاحة", f'{sum(1 for k in keys if k["ok"])}/{len(keys)}'))
        stats = "".join(f'<div class="stat"><b>{_e(v)}</b><span>{_e(k)}</span></div>' for k, v in info)
        table = ('<div class="wrap"><table style="min-width:500px"><thead><tr><th>المفتاح</th><th>الحالة</th><th>آخر كود</th><th>إخفاقات</th><th>إعادة بعد</th></tr></thead><tbody>'
                 + (key_rows or '<tr><td colspan="5" class="mut">لا توجد مفاتيح.</td></tr>') + '</tbody></table></div>')
        return self.page(f'{self.nav("system", sess["csrf"])}<main>{self._flash(sess)}<h2>🩺 حالة النظام</h2><div class="stats">{stats}</div>'
                         f'<h3>🔑 مفاتيح API</h3>{table}</main>', "النظام")
