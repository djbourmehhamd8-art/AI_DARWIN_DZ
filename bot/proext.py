"""Extra everyday tools (calculator, JSON, regex, units, colours, dice…) + the web-chat button, as a mixin for BotApp.

The logic lives in proutils.py (pure functions, shared with the web panel); this file only talks to Telegram.
"""
from __future__ import annotations

import html

from . import proutils as P
from .utils import safe_int
from .ui import kb, tr
from .utildata import UTIL_HINTS, UTIL_KINDS, UTILS


def _e(x) -> str:
    return html.escape(str(x), quote=False)


class ProExtMixin:
    def proext_commands(self) -> dict:
        cmds = {k: getattr(self, f"cmd_{k}") for k in UTIL_KINDS}
        cmds["webchat"] = self.cmd_webchat
        return cmds

    # ------------------------------------------------------------------ screens
    def util_kb(self, lang):
        items = [(f"{ic} {ar if lang == 'ar' else en}", f"t:{k}") for k, ic, ar, en, *_ in UTILS]
        rows = [items[i:i + 2] for i in range(0, len(items), 2)]
        rows.append([("🌐 " + tr(lang, "دردشة AI (ويب)", "AI chat (web)"), "m:wc")])
        rows.append(self.home_row(lang))
        return kb(rows)

    def show_utils(self, chat_id, user, mid=None) -> None:
        lang = user["lang"]
        self._screen(chat_id, mid, tr(lang, "🧮 أدوات إضافية — اختر أداة:", "🧮 Extra tools — pick one:"), self.util_kb(lang))

    def web_chat_url(self) -> str:
        base = (self.cfg.web_panel_url or "").rstrip("/")
        return f"{base}/chat" if base else ""

    def show_webchat(self, chat_id, user, mid=None) -> None:
        lang, url = user["lang"], self.web_chat_url()
        if url and self.is_admin(user["id"]):
            text = tr(lang, "🌐 <b>دردشة الذكاء الاصطناعي في لوحة الويب</b>\nافتح الرابط وسجّل دخولك بكلمة مرور اللوحة.",
                      "🌐 <b>AI chat in the web panel</b>\nOpen the link and sign in with the panel password.")
            markup = kb([[("🌐 " + tr(lang, "افتح الدردشة", "Open chat"), url, "primary")], self.home_row(lang)])
        elif url:
            text = tr(lang, "🌐 دردشة الويب متاحة لمدير البوت فقط. استخدم الدردشة هنا مباشرة بإرسال رسالتك.",
                      "🌐 The web chat is for the bot admin only. Just send your message here to chat.")
            markup = kb([self.home_row(lang)])
        else:
            text = tr(lang, "🌐 دردشة الويب غير مفعّلة بعد. على المدير ضبط <code>WEB_PANEL_PORT</code> و<code>WEB_PANEL_TOKEN</code> و"
                            "<code>WEB_PANEL_URL</code> في .env ثم إعادة التشغيل.",
                      "🌐 The web chat is not enabled yet. The admin must set <code>WEB_PANEL_PORT</code>, <code>WEB_PANEL_TOKEN</code> and "
                      "<code>WEB_PANEL_URL</code> in .env and restart.")
            markup = kb([self.home_row(lang)])
        if mid and self.tg.edit_rich(chat_id, mid, text, text, markup):
            return
        self.tg.send_rich(chat_id, text, text, markup)

    def cmd_webchat(self, chat_id, user, args) -> None:
        self.show_webchat(chat_id, user)

    # ------------------------------------------------------------------ helpers
    def _util_fail(self, chat_id, user, kind: str, err: str = "") -> None:
        ha, he = UTIL_HINTS[kind]
        msg = tr(user["lang"], ha, he)
        if err:
            msg = "⚠️ " + _e(err) + "\n\n" + msg
        self.tg.send_message(chat_id, msg)

    def _util_run(self, chat_id, user, kind: str, args: str, fn) -> None:
        """Gate (rate limit), run `fn(args) -> list of HTML lines`, and show a friendly error otherwise."""
        if not self._sec_gate(chat_id, user):
            return
        try:
            lines = fn((args or "")[:P.MAX_INPUT])
        except ValueError as e:
            return self._util_fail(chat_id, user, kind, str(e))
        self.send_html_lines(chat_id, lines)

    # ------------------------------------------------------------------ commands
    def cmd_calc(self, chat_id, user, args) -> None:
        self._util_run(chat_id, user, "calc", args, lambda a: [f"🧮 <code>{_e(a.strip())}</code>", f"<b>= {_e(P.calc(a))}</b>"])

    def cmd_unit(self, chat_id, user, args) -> None:
        def f(a):
            r = P.convert_units(a)
            return [f"📏 <b>{_e(r['group'])}</b>", f"<code>{r['value']:g} {_e(r['from'])}</code> = <b>{r['result']:g} {_e(r['to'])}</b>"]
        self._util_run(chat_id, user, "unit", args, f)

    def cmd_pct(self, chat_id, user, args) -> None:
        self._util_run(chat_id, user, "pct", args, lambda a: [f"％ <b>{_e(P.percent(a)['text'])}</b>"])

    def cmd_json(self, chat_id, user, args) -> None:
        def f(a):
            r = P.json_pretty(a)
            return [f"🧾 <b>JSON ✅</b> · {_e(r['type'])} · {r['size']}", f"<pre>{_e(r['pretty'][:3000])}</pre>"]
        self._util_run(chat_id, user, "json", args, f)

    def cmd_regex(self, chat_id, user, args) -> None:
        def f(a):
            r = P.regex_test(a)
            lines = [f"🧩 <code>{_e(r['pattern'])}</code> — <b>{r['count']}</b> {tr(user['lang'], 'تطابق', 'match(es)')}"]
            for i, m in enumerate(r["matches"][:10], 1):
                g = f" · groups: {_e(m['groups'])}" if m["groups"] else ""
                lines.append(f"{i}. <code>{_e(m['text'])}</code> @ {m['span'][0]}-{m['span'][1]}{g}")
            return lines
        self._util_run(chat_id, user, "regex", args, f)

    def cmd_textstat(self, chat_id, user, args) -> None:
        def f(a):
            r = P.text_stats(a)
            top = " · ".join(f"{_e(w)}×{n}" for w, n in r["top"]) or "-"
            lg = user["lang"]
            return [f"🔤 <b>{tr(lg, 'إحصاءات النص', 'Text statistics')}</b>",
                    f"{tr(lg, 'كلمات', 'Words')}: <b>{r['words']}</b> ({r['unique_words']} {tr(lg, 'فريدة', 'unique')})",
                    f"{tr(lg, 'أحرف', 'Characters')}: {r['chars']} ({r['chars_no_space']} {tr(lg, 'بدون مسافات', 'no spaces')}) · {r['bytes']} bytes",
                    f"{tr(lg, 'أسطر', 'Lines')}: {r['lines']} · ⏱ ~{r['read_minutes']} min",
                    f"{tr(lg, 'الأكثر تكراراً', 'Top words')}: {top}"]
        self._util_run(chat_id, user, "textstat", args, f)

    def cmd_uniq(self, chat_id, user, args) -> None:
        def f(a):
            r = P.dedupe_sort(a)
            return [f"🧹 {r['total']} → <b>{r['unique']}</b> ({tr(user['lang'], 'حُذف', 'removed')} {r['removed']})", f"<pre>{_e(r['result'][:3000])}</pre>"]
        self._util_run(chat_id, user, "uniq", args, f)

    def cmd_urlenc(self, chat_id, user, args) -> None:
        def f(a):
            r = P.url_codec(a)
            return [f"🔗 <b>{r['mode']}</b>", f"<code>{_e(r['result'][:3500])}</code>"]
        self._util_run(chat_id, user, "urlenc", args, f)

    def cmd_color(self, chat_id, user, args) -> None:
        def f(a):
            r = P.color_convert(a)
            return ["🎨 <b>HEX / RGB / HSL</b>", f"<code>{r['hex']}</code>", f"<code>{r['rgb']}</code>", f"<code>{r['hsl']}</code>"]
        self._util_run(chat_id, user, "color", args, f)

    def cmd_caseconv(self, chat_id, user, args) -> None:
        self._util_run(chat_id, user, "caseconv", args,
                       lambda a: ["🔡 <b>Case</b>"] + [f"{_e(k)}: <code>{_e(v)}</code>" for k, v in P.case_convert(a)])

    def cmd_slug(self, chat_id, user, args) -> None:
        self._util_run(chat_id, user, "slug", args, lambda a: ["🏷 <b>Slug</b>", f"<code>{_e(P.slugify(a))}</code>"])

    def cmd_roll(self, chat_id, user, args) -> None:
        def f(a):
            r = P.rand_roll(a)
            if r["kind"] == "coin":
                return [f"🪙 <b>{_e(r['result'])}</b>"]
            if r["kind"] == "dice":
                return [f"🎲 {' + '.join(map(str, r['rolls']))} = <b>{r['result']}</b>"]
            return [f"🎲 [{r['lo']}–{r['hi']}] → <b>{r['result']}</b>"]
        self._util_run(chat_id, user, "roll", args, f)

    def cmd_uuid(self, chat_id, user, args) -> None:
        n = safe_int(args, 3)
        self._util_run(chat_id, user, "uuid", "", lambda a: ["🆔 <b>UUID v4</b>"] + [f"<code>{u}</code>" for u in P.make_uuids(n)])
