"""Commands for the v4.8 tools: SPF/DMARC audit, secret scanner, SRI, chmod, CIDR match, IP convert, user agent, diff, date.

Logic lives in security/mailauth.py and devtools.py (pure functions, shared with the web panel); this file only formats
replies. Uses ProExtMixin._util_run / _findings, so it must be mixed into BotApp next to ProExtMixin.
"""
from __future__ import annotations

import html

from . import devtools as D
from .security import mailauth as MA
from .security import webconfig as W
from .ui import tr

EXTRA_KINDS = ("spf", "dmarc", "secrets", "sri", "chmod", "cidrmatch", "ipconv", "useragent", "diff", "date")


def _e(x) -> str:
    return html.escape(str(x), quote=False)


class ExtraCmdsMixin:
    def cmd_spf(self, chat_id, user, args) -> None:
        def f(a):
            r = MA.analyze_spf(a)
            lg = user["lang"]
            return [f"📨 <b>SPF</b> · {tr(lg, 'التقييم', 'Grade')} <b>{r['grade']}</b> ({r['score']}/100) · "
                    f"{r['lookups']}/10 {tr(lg, 'عمليات بحث DNS', 'DNS lookups')}", ""] + self._findings(lg, r)
        self._util_run(chat_id, user, "spf", args, f)

    def cmd_dmarc(self, chat_id, user, args) -> None:
        def f(a):
            r = MA.analyze_dmarc(a)
            lg = user["lang"]
            tags = " · ".join(f"{_e(k)}={_e(v[:30])}" for k, v in list(r["tags"].items())[:8])
            return [f"📬 <b>DMARC</b> · {tr(lg, 'التقييم', 'Grade')} <b>{r['grade']}</b> ({r['score']}/100)", f"<code>{tags}</code>", ""] + self._findings(lg, r)
        self._util_run(chat_id, user, "dmarc", args, f)

    def cmd_secrets(self, chat_id, user, args) -> None:
        mid = getattr(self.ctx, "msg_id", None)
        if mid and args.strip():
            self.tg.delete_message(chat_id, mid)    # the pasted text may hold live credentials: do not leave it in the chat

        def f(a):
            r = MA.scan_secrets(a)
            lg = user["lang"]
            if not r["count"]:
                return ["🕵️ <b>" + tr(lg, "لم أجد أسراراً معروفة", "No known secret patterns found") + "</b>",
                        tr(lg, "الفحص يعتمد على أنماط محددة؛ غيابها لا يضمن خلو النص تماماً.", "The scan uses specific patterns; a clean result is not a guarantee.")]
            lines = [f"🕵️ <b>{r['count']}</b> {tr(lg, 'سرّ محتمل', 'possible secret(s)')} · 🔴 {r['high']}", ""]
            for h in r["hits"][:25]:
                ic = "🔴" if h["severity"] == "high" else "🟠"
                lines.append(f"{ic} {_e(h['type'])} · {tr(lg, 'سطر', 'line')} {h['line']}: <code>{_e(h['masked'])}</code>")
            lines.append("")
            lines.append("⚠️ " + tr(lg, "إن كانت حقيقية فاعتبرها مُسرَّبة: بدّلها (rotate) فوراً وأزلها من الكود والسجلّ.",
                                    "If real, treat them as leaked: rotate them now and remove them from code and history."))
            return lines
        self._util_run(chat_id, user, "secrets", args, f)

    def cmd_sri(self, chat_id, user, args) -> None:
        def f(a):
            r = D.sri_hash(a)
            lg = user["lang"]
            return [f"🔒 <b>SRI</b> · {r['bytes']:,} bytes"] + [f"<b>{k}</b>\n<code>{_e(v)}</code>" for k, v in r["hashes"].items()] + \
                   ["", f"<code>{_e(r['tag'])}</code>", tr(lg, "ضع النص بالضبط كما سيُقدَّم من الخادم (أي مسافة تغيّر الهاش).", "Hash the exact bytes the server will send (any whitespace change alters it).")]
        self._util_run(chat_id, user, "sri", args, f)

    def cmd_chmod(self, chat_id, user, args) -> None:
        def f(a):
            r = D.chmod_calc(a)
            i = 1 if user["lang"] == "ar" else 2
            lines = [f"🔑 <b>{r['octal']}</b> · <code>{r['symbolic']}</code>", f"umask: <code>{r['umask']}</code>"]
            lines += [f"{W.SEV_ICON[n[0]]} {_e(n[i])}" for n in r["notes"]]
            return lines
        self._util_run(chat_id, user, "chmod", args, f)

    def cmd_cidrmatch(self, chat_id, user, args) -> None:
        def f(a):
            r = D.cidr_match(a)
            lg = user["lang"]
            lines = [f"🎯 <b>{r['matched']}/{r['total']}</b> {tr(lg, 'عناوين ضمن النطاقات', 'addresses inside the networks')}", ""]
            for row in r["rows"][:40]:
                lines.append(("✅" if row["match"] else "❌") + f" <code>{_e(row['ip'])}</code>" + (f" ⊂ {_e(', '.join(row['match']))}" if row["match"] else ""))
            return lines
        self._util_run(chat_id, user, "cidrmatch", args, f)

    def cmd_ipconv(self, chat_id, user, args) -> None:
        self._util_run(chat_id, user, "ipconv", args, lambda a: ["🔁 <b>IP</b>"] + [f"<b>{_e(k)}</b>: <code>{_e(v)}</code>" for k, v in D.ip_convert(a)])

    def cmd_useragent(self, chat_id, user, args) -> None:
        def f(a):
            r = D.parse_user_agent(a)
            lg, i = user["lang"], 1 if user["lang"] == "ar" else 2
            lines = ["🕵️ <b>User-Agent</b>", f"{tr(lg, 'المتصفح', 'Browser')}: <b>{_e(r['browser'])}</b> {_e(r['browser_version'])}",
                     f"{tr(lg, 'النظام', 'OS')}: <b>{_e(r['os'])}</b> {_e(r['os_version'])}" + (" 📱" if r["mobile"] else "")]
            lines += [f"{W.SEV_ICON[x[0]]} {_e(x[i])}" for x in r["flags"]]
            return lines
        self._util_run(chat_id, user, "useragent", args, f)

    def cmd_diff(self, chat_id, user, args) -> None:
        def f(a):
            r = D.text_diff(a)
            lg = user["lang"]
            if r["identical"]:
                return ["🟰 " + tr(lg, "النصان متطابقان.", "The two texts are identical.")]
            return [f"🔀 <b>diff</b> · +{r['added']} −{r['removed']} · {tr(lg, 'تشابه', 'similarity')} ≈ {r['similarity']}%", f"<pre>{_e(r['diff'][:3200])}</pre>"]
        self._util_run(chat_id, user, "diff", args, f)

    def cmd_date(self, chat_id, user, args) -> None:
        def f(a):
            r = D.date_calc(a)
            lg = user["lang"]
            if r["kind"] == "diff":
                return [f"📅 <code>{r['from']}</code> → <code>{r['to']}</code>", f"<b>{r['days']:,}</b> {tr(lg, 'يوماً', 'days')} · {r['weeks']} {tr(lg, 'أسبوعاً', 'weeks')} · ≈ {r['approx_months']} {tr(lg, 'شهراً', 'months')}"]
            if r["kind"] == "shift":
                return [f"📅 <code>{r['base']}</code> → <b>{r['result']}</b> ({r['weekday']})", f"{tr(lg, 'من اليوم', 'From today')}: {r['days_from_today']:+d} {tr(lg, 'يوماً', 'days')}"]
            return [f"📅 <b>{r['date']}</b> ({r['weekday']})", f"{tr(lg, 'اليوم رقم', 'Day of year')} {r['day_of_year']} · ISO week {r['iso_week']}",
                    f"{tr(lg, 'من اليوم', 'From today')}: {r['days_from_today']:+d} · Unix {r['unix']}"]
        self._util_run(chat_id, user, "date", args, f)
