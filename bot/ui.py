"""Button-driven interface: inline menus + "waiting for input" state, so slash commands are optional shortcuts."""
from __future__ import annotations

import logging
import os
import time

from .brand import DETAIL_PROMPTS
from .i18n import t
from .personas import PERSONAS, TRANSLATOR_PROMPT
from .utils import fmt_duration

log = logging.getLogger("bot.ui")


_DANGER = ("❌", "🚫", "🗑", "⏹", "🚨", "🧹", "⛔")
_SUCCESS = ("✅", "➕", "📌", "💾", "🟢")
_PRIMARY = ("🏠", "🔁", "🔄", "◀️", "▶️", "🔙")


def button_style(text: str, data: str):
    """Telegram paints a button via its `style` field (primary = blue, success = green, danger = red)."""
    if data in ("act:stop", "x:cancel"):
        return "danger"
    for group, name in ((_DANGER, "danger"), (_SUCCESS, "success"), (_PRIMARY, "primary")):
        if text.startswith(group):
            return name
    return None


def kb(rows):
    colours = os.environ.get("BUTTON_COLORS", "1").lower() not in ("0", "false", "off", "no")
    out = []
    for row in rows:
        line = []
        for item in row:
            txt, data = item[0], item[1]
            btn = {"text": txt, "url": data} if data.startswith(("https://", "http://", "tg://")) \
                else {"text": txt, "callback_data": data}
            style = (item[2] if len(item) > 2 else None) or (button_style(txt, data) if colours else None)
            if style:
                btn["style"] = style
            line.append(btn)
        out.append(line)
    return {"inline_keyboard": out}


def tr(lang: str, ar: str, en: str) -> str:
    return ar if lang == "ar" else en


def chunk(items, n):
    return [items[i:i + n] for i in range(0, len(items), n)]


# key, icon, Arabic, English
TOOLS = (
    ("url", "🔗", "فحص رابط", "URL check"), ("ioc", "🎯", "استخراج IOC", "IOC extract"),
    ("pass", "🔐", "قوة كلمة مرور", "Password"), ("hash", "#️⃣", "هاش", "Hash"),
    ("jwt", "🪪", "تدقيق JWT", "JWT audit"), ("headers", "📧", "ترويسة بريد", "Mail headers"),
    ("decode", "🔓", "فك ترميز", "Decode"), ("cvss", "📐", "حاسبة CVSS", "CVSS calc"),
    ("ip", "🌐", "IP / CIDR", "IP / CIDR"), ("defang", "🧼", "Defang", "Defang"),
    ("port", "🔌", "منافذ الشبكة", "Ports"), ("ts", "🕓", "طوابع زمنية", "Timestamps"),
    ("hex", "🔢", "تحويل Hex", "Hex convert"), ("caesar", "🔠", "قيصر / ROT", "Caesar / ROT"),
    ("entropy", "📊", "إنتروبي", "Entropy"),
)
AI_TASKS = (
    ("cve", "🐞", "شرح ثغرة CVE", "Explain CVE"), ("harden", "🧱", "قائمة تحصين", "Hardening"),
    ("ir", "🚨", "استجابة لحادثة", "Incident plan"), ("explain", "📚", "شرح مفهوم", "Explain"),
    ("analyze", "🔬", "تحليل سجل/كود", "Analyse log/code"), ("sigma", "🛰", "قاعدة كشف Sigma", "Detection rule"),
    ("mitre", "🗺", "تقنية MITRE ATT&CK", "ATT&CK technique"),
)
LOCAL_KINDS = frozenset(k for k, *_ in TOOLS)
TASK_KINDS = frozenset(k for k, *_ in AI_TASKS)
ADMIN_KINDS = {"adm_dm": "dmq", "adm_find": "find", "bc_text": None, "adm_ban": "ban", "adm_unban": "unban", "adm_allow": "allow", "adm_disallow": "disallow"}
OTHER_KINDS = frozenset({"web_q", "mem_add", "rem_add", "sys", "case_new", "note_q"})
ASKABLE = LOCAL_KINDS | TASK_KINDS | OTHER_KINDS | frozenset(ADMIN_KINDS)

HINTS = {
    "adm_dm": ("✉️ اكتب الرسالة التي ستُرسل لهذا المستخدم.", "✉️ Type the message to send to this user."),
    "hex": ("🔢 أرسل نصاً أو رقماً أو بايتات hex وسأحوّلها بين الصيغ.", "🔢 Send text, a number or hex bytes and I will convert between formats."),
    "caesar": ("🔠 أرسل النص (واختيارياً الإزاحة في آخره، مثال: Uryyb 13). بدون إزاحة أعرض كل الاحتمالات.", "🔠 Send the text (optionally a shift at the end, e.g. Uryyb 13). Without a shift I list every candidate."),
    "entropy": ("📊 أرسل نصاً أو مفتاحاً أو سلسلة مشبوهة لقياس عشوائيتها.", "📊 Send a string, key or suspicious token to measure its randomness."),
    "web_q": ("🔎 اكتب سؤالك وسأبحث في الويب ثم أجيبك بمصادر.", "🔎 Type your question — I will search the web and answer with sources."),
    "url": ("🔗 أرسل الرابط (أو عدة روابط) لفحصه دون زيارته.", "🔗 Send the link(s) to check — they are never visited."),
    "ioc": ("🎯 الصق أي نص (تقرير، سجل، رسالة) وسأستخرج منه IP والنطاقات والهاشات وCVE.",
            "🎯 Paste any text (report, log, message) and I'll extract IPs, domains, hashes and CVEs."),
    "pass": ("🔐 أرسل كلمة المرور لتحليلها. سأحذف رسالتك فوراً ولن أخزّنها.\n⚠️ الأفضل تجربة كلمة مشابهة لا الحقيقية.",
             "🔐 Send the password to analyse. I delete your message at once and never store it.\n⚠️ Prefer a similar one, not the real one."),
    "hash": ("#️⃣ أرسل نصاً لحساب هاشه، أو هاشاً لمعرفة نوعه.", "#️⃣ Send text to hash, or a hash to identify."),
    "jwt": ("🪪 أرسل التوكن (JWT) لفكّه وتدقيقه.", "🪪 Send the JWT to decode and audit."),
    "headers": ("📧 الصق ترويسة البريد الخام (Show original) أو أرسلها كملف.",
                "📧 Paste the raw email headers (\"Show original\") or upload them as a file."),
    "decode": ("🔓 أرسل نصاً مموّهاً (Base64 / Hex / URL) لفك طبقاته. أو أي نص عادي لترميزه Base64.",
               "🔓 Send an obfuscated string (Base64 / Hex / URL) to peel its layers, or plain text to Base64-encode it."),
    "cvss": ("📐 أرسل متجه CVSS، مثال:\nCVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
             "📐 Send a CVSS vector, e.g.\nCVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "ip": ("🌐 أرسل عنوان IP أو شبكة CIDR (مثال 10.0.0.0/24).", "🌐 Send an IP address or CIDR (e.g. 10.0.0.0/24)."),
    "defang": ("🧼 الصق نصاً وسأعطّل الروابط والنطاقات وعناوين IP فيه ليصبح آمناً للمشاركة.",
               "🧼 Paste text and I'll defang its URLs, domains and IPs so it is safe to share."),
    "cve": ("🐞 أرسل رقم الثغرة، مثال: CVE-2024-3094", "🐞 Send the CVE ID, e.g. CVE-2024-3094"),
    "harden": ("🧱 أرسل النظام المراد تحصينه، مثال: Ubuntu 24 SSH server", "🧱 Send the system to harden, e.g. Ubuntu 24 SSH server"),
    "ir": ("🚨 صِف الحادثة، مثال: حساب موظف أرسل رسائل تصيّد", "🚨 Describe the incident, e.g. an employee account sent phishing mail"),
    "explain": ("📚 أرسل المصطلح، مثال: Kerberoasting", "📚 Send the term, e.g. Kerberoasting"),
    "analyze": ("🔬 الصق السجل أو الكود أو التنبيه، أو أرسله كملف.", "🔬 Paste the log, code or alert — or upload it as a file."),
    "sigma": ("🛰 صِف السلوك المراد كشفه، مثال: PowerShell يشغّل أمراً مشفّراً Base64",
              "🛰 Describe the behaviour to detect, e.g. PowerShell running a Base64-encoded command"),
    "port": ("🔌 أرسل رقم منفذ أو عدة أرقام أو نطاقاً أو اسم خدمة. مثال: 3389 أو 22,445 أو 20-25 أو ssh",
             "🔌 Send a port, several ports, a range or a service name. e.g. 3389, 22,445, 20-25 or ssh"),
    "ts": ("🕓 أرسل طابعاً زمنياً (Unix / FILETIME / WebKit) لتحويله إلى UTC، أو تاريخاً بصيغة ISO لتحويله، أو now.",
           "🕓 Send a timestamp (Unix / FILETIME / WebKit) to convert to UTC, an ISO date to convert back, or now."),
    "mitre": ("🗺 أرسل رقم التقنية أو اسمها، مثال: T1059.001 أو Kerberoasting", "🗺 Send the technique ID or name, e.g. T1059.001 or Kerberoasting"),
    "case_new": ("🗂 أرسل اسم القضية الجديدة، مثال: حادثة تصيّد - فبراير", "🗂 Send the new case name, e.g. Phishing incident - Feb"),
    "note_q": ("🔎 أرسل كلمة للبحث بها في ملاحظاتك.", "🔎 Send a word to search your notes."),
    "mem_add": ("🧠 أرسل المعلومة التي أحفظها عنك.", "🧠 Send the fact you want me to remember."),
    "rem_add": ("⏰ أرسل المدة ثم النص، مثال:\n30m مراجعة سجلات الخادم\n(s/m/h/d)",
                "⏰ Send the delay then the text, e.g.\n30m review server logs\n(s/m/h/d)"),
    "sys": ("📝 أرسل التعليمات الخاصة التي تريدها في كل ردّ.", "📝 Send the custom instructions to apply to every reply."),
    "bc_text": ("📣 أرسل نص الإعلان الذي يصل لكل المستخدمين.", "📣 Send the announcement text for all users."),
    "adm_find": ("🔎 أرسل معرّف المستخدم أو @اسم_المستخدم للبحث عنه.", "🔎 Send a user ID or @username to look up."),
    "adm_ban": ("🚫 أرسل معرّف المستخدم لحظره.", "🚫 Send the user ID to ban."),
    "adm_unban": ("✅ أرسل معرّف المستخدم لفك الحظر.", "✅ Send the user ID to unban."),
    "adm_allow": ("➕ أرسل معرّف المستخدم للسماح له.", "➕ Send the user ID to allow."),
    "adm_disallow": ("➖ أرسل معرّف المستخدم لسحب السماح.", "➖ Send the user ID to disallow."),
}


class UIMixin:
    """Expects BotApp attributes: tg, db, cfg, pending, ctx, commands, admin_commands and the cmd_* methods."""

    # ------------------------------------------------------------------ keyboards
    @staticmethod
    def home_row(lang):
        return [("🏠 " + tr(lang, "القائمة", "Menu"), "m:main")]

    def main_menu(self, lang, admin=False):
        rows = [
            [("🧰 " + tr(lang, "أدوات الأمن", "Security tools"), "m:tools"),
             ("🤖 " + tr(lang, "مساعد الأمن", "AI assistant"), "m:ai")],
            [("🗂 " + tr(lang, "القضايا", "Cases"), "m:cases"), ("📌 " + tr(lang, "مكتبتي", "Library"), "m:notes"),
             ("✅ " + tr(lang, "قوائم التحقق", "Checklists"), "m:ck")],
            [("🆕 " + tr(lang, "جديدة", "New"), "act:new"), ("🔁 " + tr(lang, "إعادة", "Retry"), "act:retry"),
             ("⏹ " + tr(lang, "إيقاف", "Stop"), "act:stop")],
            [("🔎 " + tr(lang, "بحث ويب", "Web search"), "t:web_q"), ("📁 " + tr(lang, "ملفات", "Files"), "m:files")],
            [("🧠 " + tr(lang, "الذاكرة", "Memory"), "m:mem"), ("⏰ " + tr(lang, "التذكيرات", "Reminders"), "m:rem"),
             ("⚙️ " + tr(lang, "الإعدادات", "Settings"), "m:set")],
            [("👤 " + tr(lang, "لوحتي", "My dashboard"), "act:me"), ("❓ " + tr(lang, "مساعدة", "Help"), "act:help")],
        ]
        if admin:
            rows.append([("👑 " + tr(lang, "لوحة المدير", "Admin panel"), "m:adm")])
        return kb(rows)

    def tools_kb(self, lang):
        items = [(f"{ic} {ar if lang == 'ar' else en}", f"t:{k}") for k, ic, ar, en in TOOLS]
        rows = chunk(items, 2) + [[("🎲 " + tr(lang, "توليد كلمة مرور", "Generate password"), "t:genpass")], self.home_row(lang)]
        return kb(rows)

    def ai_kb(self, lang):
        items = [(f"{ic} {ar if lang == 'ar' else en}", f"t:{k}") for k, ic, ar, en in AI_TASKS]
        return kb(chunk(items, 2) + [self.home_row(lang)])

    def settings_kb(self, lang):
        return kb([
            [("📏 " + tr(lang, "أسلوب الرد", "Reply style"), "m:detail"), ("🌡 " + tr(lang, "الإبداع", "Creativity"), "m:temp")],
            [("🌐 " + tr(lang, "اللغة", "Language"), "m:lang"), ("🎭 " + tr(lang, "الشخصية", "Persona"), "m:persona")],
            [("🔎 " + tr(lang, "بحث الويب", "Web search"), "m:web"), ("📁 " + tr(lang, "ملفات", "Files"), "m:files")],
            [("📝 " + tr(lang, "تعليمات خاصة", "Custom instructions"), "t:sys"),
             ("🧽 " + tr(lang, "مسح التعليمات", "Clear them"), "set:sysclear")],
            [("📤 " + tr(lang, "تصدير المحادثة", "Export chat"), "act:export"),
             ("📅 " + tr(lang, "حصتي اليومية", "Daily quota"), "act:quota")],
            [("🗑 " + tr(lang, "احذف بياناتي", "Delete my data"), "set:wipe"), ("ℹ️ " + tr(lang, "عن البوت", "About"), "act:about")],
            self.home_row(lang),
        ])

    def admin_kb(self, lang, full=True, pending=0):
        req = ("🔔 " + tr(lang, "الطلبات", "Requests") + (f" ({pending})" if pending else ""), "adm:rq", "success" if pending else None)
        if not full:                                              # moderator: users + access requests only
            return kb([
                [("👥 " + tr(lang, "المستخدمون", "Users"), "adm:ul:0"), req],
                [("🔎 " + tr(lang, "بحث عن مستخدم", "Find user"), "t:adm_find"), ("🏆 " + tr(lang, "الأعلى", "Top"), "adm:top")],
                [("🚫 " + tr(lang, "المحظورون", "Banned"), "adm:ul:0:b"), ("➕ " + tr(lang, "المسموحون", "Allowed"), "adm:ul:0:a")],
                [("🔄 " + tr(lang, "تحديث", "Refresh"), "m:adm")] + self.home_row(lang),
            ])
        return kb([
            [("👥 " + tr(lang, "المستخدمون", "Users"), "adm:ul:0"), req],
            [("🔎 " + tr(lang, "بحث عن مستخدم", "Find user"), "t:adm_find"), ("🏆 " + tr(lang, "الأعلى", "Top"), "adm:top")],
            [("🚫 " + tr(lang, "المحظورون", "Banned"), "adm:ul:0:b"), ("➕ " + tr(lang, "المسموحون", "Allowed"), "adm:ul:0:a")],
            [("👥 " + tr(lang, "المجموعات", "Groups"), "adm:gl:0"), ("🛡 " + tr(lang, "المشرفون", "Staff"), "adm:ul:0:s")],
            [("📣 " + tr(lang, "بث رسالة", "Broadcast"), "t:bc_text"), ("📈 " + tr(lang, "إحصائيات", "Stats"), "adm:stats")],
            [("🩺 " + tr(lang, "النظام", "System"), "adm:sys"), ("🧾 " + tr(lang, "سجل التدقيق", "Audit log"), "adm:audit")],
            [("🔑 " + tr(lang, "مفاتيح API", "API keys"), "adm:keys"), ("💾 " + tr(lang, "نسخة احتياطية", "Backup"), "adm:backup")],
            [("📊 " + tr(lang, "الحدود اليومية", "Daily limits"), "adm:lm"), ("📈 " + tr(lang, "تقرير اليوم", "Today's report"), "adm:rep")],
            [("🔎 " + tr(lang, "اختبار البحث", "Test web search"), "adm:wt"), ("📤 " + tr(lang, "تصدير CSV", "Export CSV"), "adm:csv")],
            [(("🛠 " + tr(lang, "الصيانة: تعمل", "Maintenance: ON")) if self.maintenance else ("🛠 " + tr(lang, "وضع الصيانة", "Maintenance")),
              "adm:mnt", "danger" if self.maintenance else None)],
            [("🔄 " + tr(lang, "تحديث", "Refresh"), "m:adm")] + self.home_row(lang),
        ])

    def stop_kb(self, lang):
        """Shown under a reply while it is being written."""
        return kb([[("⏹ " + tr(lang, "إيقاف", "Stop"), "act:stop")]])

    def retry_kb(self, lang):
        return kb([[("🔁 " + tr(lang, "إعادة المحاولة", "Try again"), "act:retry")] + self.home_row(lang)])

    def answer_kb(self, lang):
        """Quick follow-ups under every finished answer."""
        return kb([
            [("🔁 " + tr(lang, "إعادة", "Retry"), "act:retry"), ("➕ " + tr(lang, "أكمل", "Continue"), "ans:more"),
             ("✂️ " + tr(lang, "اختصر", "Shorter"), "ans:short")],
            [("🌐 " + tr(lang, "ترجم", "Translate"), "ans:tr"), ("📌 " + tr(lang, "احفظ", "Save"), "ans:save"),
             ("📁 " + tr(lang, "ملفات", "Files"), "ans:files")],
            [("🔎 " + tr(lang, "ابحث", "Web"), "ans:web"), ("🆕 " + tr(lang, "جديدة", "New"), "act:new"),
             ("🏠 " + tr(lang, "القائمة", "Menu"), "m:main")],
        ])

    def detail_kb(self, lang, cur):
        names = {"concise": tr(lang, "⚡ مختصر", "⚡ Concise"), "balanced": tr(lang, "⚖️ متوازن", "⚖️ Balanced"),
                 "detailed": tr(lang, "📚 مفصّل", "📚 Detailed"), "expert": tr(lang, "🧠 خبير", "🧠 Expert")}
        order = [k for k in ("concise", "balanced", "detailed", "expert") if k in DETAIL_PROMPTS]
        row = [(("✅ " if k == cur else "") + names[k], f"detail:{k}") for k in order]
        return kb([row[:2], row[2:], self.home_row(lang)])

    def after_kb(self, lang, kind):
        """Shown under a local tool's result: run it again, or go back to the menu."""
        again = [("🔁 " + tr(lang, "مرة أخرى", "Again"), f"t:{kind}")] if kind in ASKABLE or kind == "genpass" else []
        return kb([again + self.home_row(lang)])

    # ------------------------------------------------------------------ screens
    def _screen(self, chat_id, mid, text, markup=None):
        if mid:
            self.tg.edit_message_text(chat_id, mid, text, markup)
        else:
            self.tg.send_message(chat_id, text, markup)

    def show_main(self, chat_id, user, mid=None):
        lang = user["lang"]
        self._screen(chat_id, mid, t(lang, "menu_title"), self.main_menu(lang, self.is_staff(user["id"])))

    def show_tools(self, chat_id, user, mid=None):
        lang = user["lang"]
        self._screen(chat_id, mid, t(lang, "sec_menu"), self.tools_kb(lang))

    def show_ai(self, chat_id, user, mid=None):
        lang = user["lang"]
        self._screen(chat_id, mid, tr(lang, "🤖 مساعد الأمن (يستخدم الذكاء الاصطناعي وتُحفظ الإجابة لتتابعها بأسئلة):",
                                      "🤖 AI assistant (uses the model; the answer is kept so you can follow up):"),
                     self.ai_kb(lang))

    def show_settings(self, chat_id, user, mid=None):
        lang = user["lang"]
        self._screen(chat_id, mid, tr(lang, "⚙️ الإعدادات:", "⚙️ Settings:"), self.settings_kb(lang))

    def show_memory(self, chat_id, user, mid=None):
        lang, facts = user["lang"], self.db.list_facts(user["id"])
        if facts:
            text = t(lang, "memory_head") + "\n" + "\n".join(f"{f['id']}. {f['text'][:90]}" for f in facts)
        else:
            text = tr(lang, "🧠 لا توجد ذكريات بعد.", "🧠 No memories yet.")
        rows = chunk([(f"❌ {f['id']}", f"mem:del:{f['id']}") for f in facts], 5)
        rows.append([("➕ " + tr(lang, "إضافة", "Add"), "t:mem_add")] +
                    ([("🗑 " + tr(lang, "مسح الكل", "Clear all"), "mem:clear")] if facts else []))
        rows.append(self.home_row(lang))
        self._screen(chat_id, mid, text, kb(rows))

    def show_reminders(self, chat_id, user, mid=None):
        lang, rows_db, now = user["lang"], self.db.list_reminders(user["id"]), int(time.time())
        if rows_db:
            text = t(lang, "reminders_head") + "\n" + "\n".join(
                f"#{r['id']} · {fmt_duration(r['due'] - now)} · {r['text'][:80]}" for r in rows_db)
        else:
            text = t(lang, "reminders_empty")
        rows = chunk([(f"❌ #{r['id']}", f"rem:del:{r['id']}") for r in rows_db], 4)
        rows.append([("➕ " + tr(lang, "تذكير جديد", "New reminder"), "t:rem_add")])
        rows.append(self.home_row(lang))
        self._screen(chat_id, mid, text, kb(rows))

    def show_detail(self, chat_id, user, mid=None):
        lang = user["lang"]
        cur = (self.db.get_user(user["id"]) or user).get("detail") or "balanced"
        self._screen(chat_id, mid, tr(lang, "📏 اختر أسلوب الرد:\n⚡ مختصر — الخلاصة فقط\n⚖️ متوازن — الافتراضي\n📚 مفصّل — شرح كامل بأمثلة وخطوات\n🧠 خبير — تحليل معمّق وبدائل وقائمة تحقق",
                                      "📏 Choose the reply style:\n⚡ Concise — essentials only\n⚖️ Balanced — default\n📚 Detailed — full explanation with examples and steps\n🧠 Expert — deep analysis, alternatives and a checklist"),
                     self.detail_kb(lang, cur))

    def show_admin(self, chat_id, user, mid=None):
        self.admin_home(chat_id, user, mid)

    # ------------------------------------------------------------------ waiting for input
    def ask(self, chat_id, user, kind, mid=None):
        lang = user["lang"]
        if kind in ADMIN_KINDS and (chat_id < 0 or not (self.is_staff(user["id"]) if kind == "adm_find" else self.is_admin(user["id"]))):
            self.tg.send_message(chat_id, t(lang, "admin_only"))
            return
        if kind not in ASKABLE:
            return
        self.pending.set(chat_id, user["id"], kind)
        hint = HINTS[kind][0 if lang == "ar" else 1]
        cancel = kb([[("❌ " + tr(lang, "إلغاء", "Cancel"), "x:cancel")]])
        if mid and self.tg.edit_message_text(chat_id, mid, hint, cancel):
            self.hints[(chat_id, user["id"])] = mid
        else:
            sent = self.tg.send_message(chat_id, hint, cancel)
            if sent and sent.get("message_id"):
                self.hints[(chat_id, user["id"])] = sent["message_id"]

    def run_pending(self, chat_id, user, kind, text) -> None:
        """The user pressed a button earlier and has now sent the input."""
        lang = user["lang"]
        self.ctx.after_kb = self.after_kb(lang, kind) if kind in LOCAL_KINDS else None
        if kind == "bc_text":
            if not self.is_admin(user["id"]):
                return
            self.drafts[user["id"]] = text
            preview = text[:600] + ("…" if len(text) > 600 else "")
            self.tg.send_message(
                chat_id, tr(lang, "📣 هذه المعاينة، هل ترسلها لكل المستخدمين؟\n\n", "📣 Preview — send to all users?\n\n") + preview,
                kb([[("✅ " + tr(lang, "أرسل", "Send"), "adm:bcyes"), ("❌ " + tr(lang, "إلغاء", "Cancel"), "x:cancel")]]))
        elif kind in ADMIN_KINDS:
            if not (self.is_staff(user["id"]) if kind == "adm_find" else self.is_admin(user["id"])):
                self.tg.send_message(chat_id, t(lang, "admin_only"))
                return
            self.admin_commands[ADMIN_KINDS[kind]](chat_id, user, text)
        elif kind == "web_q":
            self.cmd_search(chat_id, user, text)
        elif kind == "mem_add":
            self.cmd_remember(chat_id, user, text)
        elif kind == "rem_add":
            self.cmd_remind(chat_id, user, text)
        elif kind == "sys":
            self.cmd_system(chat_id, user, text)
        elif kind == "case_new":
            self.case_create(chat_id, user, text)
        elif kind == "note_q":
            self.show_notes(chat_id, user, None, 0, text.strip()[:60])
        else:
            self.commands[kind](chat_id, user, text)

    # ------------------------------------------------------------------ callbacks
    def on_callback(self, cb: dict) -> None:
        self.ctx.after_kb = None
        self.ctx.msg_id = None
        self._reset_ctx()
        frm = cb.get("from") or {}
        msg = cb.get("message") or {}
        chat_id = (msg.get("chat") or {}).get("id")
        if not frm or chat_id is None:
            return
        user = self._user(frm)
        data = cb.get("data") or ""
        if data.startswith("req:"):                              # usable by people who do not have access yet
            self.tg.answer_callback(cb["id"])
            self.access_callback(data, chat_id, user, msg.get("message_id"))
            return
        if chat_id < 0 and not self.group_authorised(chat_id):
            self.tg.answer_callback(cb["id"], "🔒")
            return
        if not self.allowed(user):
            self.tg.answer_callback(cb["id"], "⛔")
            return
        if self.maintenance and not self.is_admin(user["id"]):
            self.tg.answer_callback(cb["id"], "🛠")
            return
        if cb.get("data") == "act:stop":                       # instant feedback as a toast, no extra message
            ev = self.cancels.get(chat_id)
            if ev:
                ev.set()
            self.tg.answer_callback(cb["id"], t(user["lang"], "stop_ok" if ev else "stop_none"))
            return
        self.tg.answer_callback(cb["id"])
        lang, mid, uid = user["lang"], msg.get("message_id"), user["id"]
        parts = (cb.get("data") or "").split(":")
        action, v, w = parts[0], (parts[1] if len(parts) > 1 else ""), (parts[2] if len(parts) > 2 else "")
        admin = self.is_staff(uid)                               # admins and moderators; admin_callback enforces the split

        if self.workspace_callback(action, v, w, parts, chat_id, user, mid):
            return
        if action == "m":
            if v == "main":
                self.pending.pop(chat_id, uid)
                self.hints.pop((chat_id, uid), None)
                self.show_main(chat_id, user, mid)
            elif v == "tools":
                self.show_tools(chat_id, user, mid)
            elif v == "ai":
                self.show_ai(chat_id, user, mid)
            elif v == "set":
                self.show_settings(chat_id, user, mid)
            elif v == "mem":
                self.show_memory(chat_id, user, mid)
            elif v == "rem":
                self.show_reminders(chat_id, user, mid)
            elif v == "files":
                self.show_files(chat_id, user, mid)
            elif v == "web":
                self.show_web(chat_id, user, mid)
            elif v == "adm" and admin and chat_id > 0:
                self.show_admin(chat_id, user, mid)
            elif v == "detail":
                self.show_detail(chat_id, user, mid)
            elif v == "persona":
                self._screen(chat_id, mid, t(lang, "persona_pick"), self._persona_kb(lang))
            elif v == "temp":
                self._screen(chat_id, mid, t(lang, "temp_pick"), self._temp_kb())
            elif v == "lang":
                self._screen(chat_id, mid, t(lang, "lang_pick"), self._lang_kb())
        elif action == "t":
            if v == "genpass":
                self._screen(chat_id, mid, tr(lang, "🎲 اختر طول كلمة المرور:", "🎲 Choose the password length:"),
                             kb([[(str(n), f"g:{n}") for n in (12, 16, 20, 32, 64)], self.home_row(lang)]))
            else:
                self.ask(chat_id, user, v, mid)
        elif action == "g" and v.isdigit():
            self.ctx.after_kb = self.after_kb(lang, "genpass")
            self.cmd_genpass(chat_id, user, v)
        elif action == "x":
            self.pending.pop(chat_id, uid)
            self.hints.pop((chat_id, uid), None)
            self.drafts.pop(uid, None)
            self._screen(chat_id, mid, tr(lang, "تم الإلغاء.", "Cancelled."), kb([self.home_row(lang)]))
        elif action == "act":
            fn = {"new": self.cmd_new, "retry": self.cmd_retry, "usage": self.cmd_usage, "me": self.cmd_me, "export": self.cmd_export,
                  "stop": self.cmd_stop, "quota": self.cmd_quota, "about": self.cmd_about, "help": self.cmd_help}.get(v)
            if fn:
                fn(chat_id, user, "")
        elif action == "ans":
            self._answer_action(chat_id, user, v)
        elif action == "fx":
            self.export_last(chat_id, user, v)
        elif action == "web" and v in ("off", "auto", "on"):
            self.db.set_user(uid, web=v)
            self.show_web(chat_id, self.db.get_user(uid), mid)
        elif action == "detail" and v in DETAIL_PROMPTS:
            self.db.set_user(uid, detail=v)
            self.show_detail(chat_id, self.db.get_user(uid), mid)
        elif action == "mem":
            if v == "del" and w.isdigit():
                self.db.delete_fact(uid, int(w))
                self.show_memory(chat_id, user, mid)
            elif v == "clear":
                self._screen(chat_id, mid, tr(lang, "🗑 حذف كل الذكريات؟", "🗑 Delete all memories?"),
                             kb([[("✅ " + tr(lang, "نعم", "Yes"), "mem:clearyes"), ("❌ " + tr(lang, "لا", "No"), "m:mem")]]))
            elif v == "clearyes":
                self.db.clear_facts(uid)
                self.show_memory(chat_id, user, mid)
        elif action == "rem":
            if v == "del" and w.isdigit():
                self.db.delete_reminder(uid, int(w))
                self.show_reminders(chat_id, user, mid)
            elif v in ("snz", "ok"):
                body = (msg.get("text") or "").removeprefix("⏰").strip()
                if v == "ok" or not body or not w.isdigit():
                    self.tg.edit_message_text(chat_id, mid, f"✅ {body}")
                elif self.db.count_pending(uid) >= 20:
                    self.tg.send_message(chat_id, t(lang, "remind_limit", n=20))
                else:
                    mins = max(1, min(int(w), 1440))
                    self.db.add_reminder(uid, chat_id, int(time.time()) + mins * 60, body[:500])
                    self.tg.edit_message_text(chat_id, mid, f"⏳ {body}\n↻ {fmt_duration(mins * 60)}")
        elif action == "set":
            if v == "sysclear":
                self.cmd_system(chat_id, user, "off")
            elif v == "wipe":
                self._screen(chat_id, mid, tr(lang, "🗑 سأحذف محادثتك وذكرياتك وتذكيراتك وتعليماتك الخاصة نهائياً. متأكد؟",
                                              "🗑 This permanently deletes your chat history, memories, reminders and custom instructions. Sure?"),
                             kb([[("✅ " + tr(lang, "نعم، احذف", "Yes, delete"), "set:wipeyes"), ("❌ " + tr(lang, "لا", "No"), "m:set")]]))
            elif v == "wipeyes":
                r = self.db.wipe_user(uid, chat_id)
                self.db.add_audit(uid, "wipe_self", f"msgs={r['messages']} facts={r['facts']} rem={r['reminders']}")
                self._screen(chat_id, mid, tr(lang, "✅ حُذفت بياناتك.", "✅ Your data was deleted."), kb([self.home_row(lang)]))
        elif action == "persona" and v in PERSONAS:
            self.db.set_user(uid, persona=v)
            self._screen(chat_id, mid, t(lang, "persona_set", name=PERSONAS[v][lang]), kb([self.home_row(lang)]))
        elif action == "temp":
            try:
                val = max(0.0, min(2.0, float(v)))
            except ValueError:
                return
            self.db.set_user(uid, temperature=val)
            self._screen(chat_id, mid, t(lang, "temp_set", v=val), kb([self.home_row(lang)]))
        elif action == "lang" and v in ("ar", "en"):
            self.db.set_user(uid, lang=v)
            self._screen(chat_id, mid, t(v, "lang_set"), kb([self.home_row(v)]))
        elif action == "adm":
            if not admin or chat_id < 0:
                self.tg.send_message(chat_id, t(lang, "admin_only"))
                return
            self.admin_callback(v, w, parts, chat_id, user, mid)

    # ------------------------------------------------------------------ buttons under an answer
    def _answer_action(self, chat_id, user, what: str) -> None:
        lang = user["lang"]
        if what == "more":
            self.chat(chat_id, user, tr(lang, "تابع من حيث توقفت وتوسّع في النقطة الأهم.",
                                        "Continue from where you stopped and expand on the most important point."))
        elif what == "short":
            self.chat(chat_id, user, tr(lang, "اختصر إجابتك السابقة في 5 نقاط قصيرة كحد أقصى.",
                                        "Condense your previous answer into at most 5 short bullets."))
        elif what == "tr":
            last = self.db.last_assistant(self._hk(chat_id, user))
            if not last:
                self.tg.send_message(chat_id, t(lang, "nothing_retry"))
                return
            self._oneshot(chat_id, user, TRANSLATOR_PROMPT, last[:6000], temperature=0.2)
        elif what == "files":
            self.show_files(chat_id, user)
        elif what == "web":
            self.ctx.web_force = True                      # redo the last question, this time grounded in web results
            self.cmd_retry(chat_id, user, "")
