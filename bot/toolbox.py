"""/hex, /caesar, /entropy — quick offline utilities for analysts."""
from __future__ import annotations

import html

from . import toolfuncs as T
from .ui import tr

VERDICT = {
    "repetitive": ("🟡 متكرر جداً (نمط بسيط أو حشو)", "🟡 Very repetitive (simple pattern or padding)"),
    "natural": ("🟢 يشبه لغة طبيعية / نص عادي", "🟢 Looks like natural language / plain text"),
    "encoded": ("🟠 نص مرمّز أو مختلط (Base64، روابط، معرّفات)", "🟠 Encoded or mixed text (Base64, URLs, identifiers)"),
    "random": ("🔴 عالية: عشوائي أو مشفّر أو مضغوط أو مفتاح", "🔴 High: random, encrypted, compressed or key material"),
}


def _e(x) -> str:
    return html.escape(str(x), quote=False)


class ToolboxMixin:
    def toolbox_commands(self) -> dict:
        return {"hex": self.cmd_hex, "caesar": self.cmd_caesar, "entropy": self.cmd_entropy}

    def _usage(self, chat_id, user, ar: str, en: str) -> None:
        self.tg.send_message(chat_id, tr(user["lang"], ar, en))

    def cmd_hex(self, chat_id, user, args) -> None:
        rows = T.hex_convert(args)
        if not rows:
            return self._usage(chat_id, user, "🔢 /hex نص أو رقم أو بايتات hex — يحوّل بين الصيغ.",
                               "🔢 /hex text, a number or hex bytes — converts between formats.")
        lines = ["🔢 <b>Hex / Dec / Bin</b>", ""] + [f"<b>{_e(k)}</b>\n<code>{_e(v)}</code>" for k, v in rows]
        self.send_html_lines(chat_id, lines)

    def cmd_caesar(self, chat_id, user, args) -> None:
        text, shift = args.strip(), None
        parts = text.rsplit(None, 1)
        if len(parts) == 2 and parts[1].lstrip("+-").isdigit() and len(parts[1]) <= 3:
            text, shift = parts[0], int(parts[1])
        if not text:
            return self._usage(chat_id, user, "🔠 /caesar نص [إزاحة] — بدون إزاحة أعرض كل الاحتمالات (ROT13 أولاً).",
                               "🔠 /caesar text [shift] — without a shift I list every candidate (ROT13 first).")
        rows = T.caesar(text, shift)
        lines = ["🔠 <b>Caesar / ROT</b>", ""] + [f"<b>{_e(k)}</b> <code>{_e(v)}</code>" for k, v in rows]
        self.send_html_lines(chat_id, lines)

    def cmd_entropy(self, chat_id, user, args) -> None:
        lang = user["lang"]
        r = T.entropy(args)
        if not r:
            return self._usage(chat_id, user, "📊 /entropy نص — يقيس العشوائية (مفاتيح، حمولات مشفّرة، سلاسل DGA).",
                               "📊 /entropy text — measures randomness (keys, encrypted payloads, DGA strings).")
        c = r["classes"]
        lines = [f"📊 <b>{tr(lang, 'إنتروبي شانون', 'Shannon entropy')}</b>", "",
                 f"<b>{r['bits']}</b> bits/char  ·  {tr(lang, 'الحد الأقصى لهذه الأحرف', 'max for this alphabet')}: {r['max_bits']}",
                 f"{tr(lang, 'الطول', 'Length')}: {r['length']}  ·  {tr(lang, 'أحرف فريدة', 'Unique chars')}: {r['unique']}  ·  ≈ {r['total_bits']} bits",
                 f"a-z {c['lower']} · A-Z {c['upper']} · 0-9 {c['digits']} · {tr(lang, 'رموز', 'symbols')} {c['symbols']}"
                 + (f" · {tr(lang, 'غير ASCII', 'non-ASCII')} {c['non_ascii']}" if c["non_ascii"] else ""),
                 "", tr(lang, *VERDICT[r["verdict"]])]
        if r["shape"]:
            lines.append("🧬 " + tr(lang, "الشكل: ", "Shape: ") + ", ".join(r["shape"]))
        if r["short"]:
            lines.append("⚠️ " + tr(lang, "النص قصير (<16)، القياس غير موثوق.", "Very short input (<16): the estimate is unreliable."))
        self.send_html_lines(chat_id, lines)
