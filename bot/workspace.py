"""Organisation features: cases (separate workspaces), notes library, interactive checklists, report, profile card."""
from __future__ import annotations

import html
import logging
import re
import time

from . import checklists
from .brand import CORE_PROMPT
from .formatting import render_chunks
from .security.secrets_guard import redact
from .storage import case_key
from .ui import chunk, kb, tr

log = logging.getLogger("bot.workspace")

NOTES_PER_PAGE = 5
MAX_CASES = 10
MAX_NOTES = 100

REPORT_PROMPT = """Write a professional {kind} report in {language}, based on the conversation above and the saved notes \
below. Do not invent facts: anything that is not established in the conversation must be written as "Not established". \
This is a long-form deliverable, so the usual length limit does not apply. Use exactly these sections as Markdown \
"##" headings, with bullet lists and no tables:
## Executive summary (3-4 plain-language lines)
## Scope and timeline (one bullet per event: time - what happened)
## Findings (for each: title, severity Critical/High/Medium/Low/Info, evidence, impact, ATT&CK/CWE ids when known)
## Actions taken
## Recommendations (grouped: Immediate / Short term / Long term)
## Open questions and next steps
Case name: {case}
Saved notes for this case:
{notes}"""


def _plain(h: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", h))


def _title_of(text: str) -> str:
    for line in text.splitlines():
        line = re.sub(r"[#*_`>\-\u2022]+", " ", line).strip()
        if line:
            return line[:60]
    return "Note"


def _date(ts: int) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(ts))


class WorkspaceMixin:
    """Expects BotApp: tg, db, cfg, ctx, home_row(), _oneshot(), _user(), is_admin() and a history key helper."""

    def workspace_commands(self) -> dict:
        return {"case": self.cmd_case, "notes": self.cmd_notes, "save": self.cmd_save,
                "checklist": self.cmd_checklist, "report": self.cmd_report, "me": self.cmd_me}

    # ------------------------------------------------------------------ helpers
    def _hk(self, chat_id, user) -> int:
        """History key: the open case's own conversation in private chats, otherwise the chat itself."""
        cid = user.get("case_id") or 0
        return case_key(cid) if cid and chat_id == user["id"] else chat_id

    def _case_name(self, user, lang) -> str:
        cid = user.get("case_id") or 0
        c = self.db.get_case(user["id"], cid) if cid else None
        return c["name"] if c else tr(lang, "الرئيسية", "Main")

    def _screen_h(self, chat_id, mid, h, markup=None) -> None:
        if mid:
            self.tg.edit_rich(chat_id, mid, h, _plain(h), markup)
        else:
            self.tg.send_rich(chat_id, h, _plain(h), markup)

    def send_md(self, chat_id, md: str, markup=None) -> None:
        parts = render_chunks(md)
        for i, (src, h) in enumerate(parts):
            self.tg.send_rich(chat_id, h, src, markup if i == len(parts) - 1 else None)

    def _fresh(self, user) -> dict:
        return self.db.get_user(user["id"]) or user

    # ------------------------------------------------------------------ cases
    def cmd_case(self, chat_id, user, args):
        lang = user["lang"]
        sub, _, rest = args.strip().partition(" ")
        sub, rest = sub.lower(), rest.strip()
        if sub in ("new", "جديدة") and rest:
            self.case_create(chat_id, user, rest)
        elif sub in ("go", "switch", "main") and (rest.isdigit() or sub == "main" or rest == "0"):
            self.case_switch(chat_id, user, 0 if sub == "main" else int(rest), None)
        elif sub:
            self.tg.send_message(chat_id, tr(lang, "الاستخدام: /case  أو  /case new <اسم>  أو  /case go <رقم>  أو  /case main",
                                             "Usage: /case  or  /case new <name>  or  /case go <id>  or  /case main"))
        else:
            self.show_cases(chat_id, user)

    def case_create(self, chat_id, user, name: str) -> None:
        lang = user["lang"]
        if chat_id != user["id"]:
            self.tg.send_message(chat_id, tr(lang, "القضايا متاحة في المحادثة الخاصة فقط.", "Cases work in private chat only."))
            return
        name = " ".join(name.split())[:60]
        if self.cfg.secret_guard:
            name = redact(name)[0]
        cid = self.db.add_case(user["id"], name, MAX_CASES)
        if cid is None:
            self.tg.send_message(chat_id, tr(lang, f"وصلت للحد الأقصى ({MAX_CASES} قضايا). احذف قضية قديمة.",
                                             f"Case limit reached ({MAX_CASES}). Delete an old one."))
            return
        self.db.set_user(user["id"], case_id=cid)
        self.tg.send_message(chat_id, tr(lang, f"✅ أُنشئت القضية «{name}» وفُعّلت. محادثتك وملاحظاتك صارت مستقلة فيها.",
                                         f"✅ Case “{name}” created and opened. Your chat and notes are now separate in it."))
        self.show_cases(chat_id, self._fresh(user))

    def case_switch(self, chat_id, user, cid: int, mid) -> None:
        if cid and not self.db.get_case(user["id"], cid):
            self.tg.send_message(chat_id, tr(user["lang"], "القضية غير موجودة.", "Case not found."))
            return
        self.db.set_user(user["id"], case_id=cid)
        self.show_cases(chat_id, self._fresh(user), mid)

    def show_cases(self, chat_id, user, mid=None) -> None:
        lang, cur = user["lang"], user.get("case_id") or 0
        cases = self.db.list_cases(user["id"])
        lines = [tr(lang, "🗂 <b>القضايا</b> — مساحات عمل مستقلة", "🗂 <b>Cases</b> — separate workspaces"),
                 tr(lang, "لكل قضية محادثة وملاحظات خاصة بها (حادثة، عميل، مشروع).",
                    "Each case has its own conversation and notes (an incident, a client, a project).")]
        lines.append("")
        lines.append(("▶️ " if cur == 0 else "▫️ ") + tr(lang, "📥 الرئيسية", "📥 Main"))
        for c in cases:
            n = self.db.count_notes(user["id"], c["id"])
            lines.append(f"{'▶️' if c['id'] == cur else '▫️'} <b>#{c['id']}</b> {html.escape(c['name'])} · 📌{n} · {_date(c['ts'])}")
        rows = [[(("▶️ " if cur == 0 else "") + tr(lang, "📥 الرئيسية", "📥 Main"), "cs:go:0")]]
        rows += chunk([(("▶️ " if c["id"] == cur else "") + f"#{c['id']} {c['name'][:18]}", f"cs:go:{c['id']}") for c in cases], 2)
        rows.append([("➕ " + tr(lang, "قضية جديدة", "New case"), "t:case_new")])
        if cur:
            rows.append([("📄 " + tr(lang, "تقرير", "Report"), "cs:report"), ("📤 " + tr(lang, "تصدير", "Export"), "cs:export"),
                         ("🗑 " + tr(lang, "حذف", "Delete"), "cs:del")])
        rows.append(self.home_row(lang))
        self._screen_h(chat_id, mid, "\n".join(lines), kb(rows))

    def export_case(self, chat_id, user) -> None:
        lang = user["lang"]
        cid = user.get("case_id") or 0
        name = self._case_name(user, lang)
        out = [f"# {tr(lang, 'ملف القضية', 'Case file')}: {name}", f"_{tr(lang, 'تاريخ التصدير', 'Exported')}: "
               f"{time.strftime('%Y-%m-%d %H:%M')}_", ""]
        notes = self.db.list_notes(user["id"], cid, limit=MAX_NOTES)
        out.append(f"## {tr(lang, 'الملاحظات', 'Notes')} ({len(notes)})")
        for n in reversed(notes):
            out += [f"### {n['title']} — {_date(n['ts'])}", n["text"], ""]
        hist = self.db.get_history(self._hk(chat_id, user), 500)
        out.append(f"## {tr(lang, 'المحادثة', 'Conversation')} ({len(hist)})")
        for m in hist:
            who = tr(lang, "أنت", "You") if m["role"] == "user" else "DARWIN"
            out += [f"**{who}** · {time.strftime('%Y-%m-%d %H:%M', time.localtime(m['ts']))}", m["content"], ""]
        slug = re.sub(r"[^\w-]+", "-", name).strip("-")[:30] or "case"
        self.tg.send_document(chat_id, f"case-{slug}.md", "\n".join(out).encode("utf-8"))

    # ------------------------------------------------------------------ notes library
    def cmd_save(self, chat_id, user, args):
        self.save_last_answer(chat_id, user)

    def save_last_answer(self, chat_id, user) -> None:
        lang = user["lang"]
        last = self.db.last_assistant(self._hk(chat_id, user))
        if not last:
            self.tg.send_message(chat_id, tr(lang, "لا توجد إجابة لحفظها.", "There is no answer to save."))
            return
        if self.cfg.secret_guard:
            last = redact(last)[0]
        nid = self.db.add_note(user["id"], user.get("case_id") or 0, _title_of(last), last, MAX_NOTES)
        if nid is None:
            self.tg.send_message(chat_id, tr(lang, f"مكتبتك ممتلئة ({MAX_NOTES}). احذف ملاحظات قديمة.",
                                             f"Your library is full ({MAX_NOTES}). Delete some notes."))
            return
        self.tg.send_message(chat_id, tr(lang, f"📌 حُفظت في «{self._case_name(user, lang)}» (#{nid})",
                                         f"📌 Saved to “{self._case_name(user, lang)}” (#{nid})"),
                             kb([[("📌 " + tr(lang, "مكتبتي", "Library"), "m:notes")] + self.home_row(lang)]))

    def cmd_notes(self, chat_id, user, args):
        self.show_notes(chat_id, user, None, 0, args.strip() or None)

    def show_notes(self, chat_id, user, mid=None, page=0, query=None) -> None:
        lang, uid, cid = user["lang"], user["id"], user.get("case_id") or 0
        total = self.db.count_notes(uid, cid, query)
        pages = max(1, -(-total // NOTES_PER_PAGE))
        page = max(0, min(page, pages - 1))
        items = (self.db.list_notes(uid, cid, limit=NOTES_PER_PAGE, offset=page * NOTES_PER_PAGE, query=query))
        head = tr(lang, "📌 <b>مكتبتي</b>", "📌 <b>Library</b>") + f" — {html.escape(self._case_name(user, lang))}"
        if query:
            head += f"\n🔎 {html.escape(query)}"
        lines = [head, tr(lang, f"{total} ملاحظة" + (f" · صفحة {page + 1}/{pages}" if pages > 1 else ""),
                          f"{total} note(s)" + (f" · page {page + 1}/{pages}" if pages > 1 else "")), ""]
        if not items:
            lines.append(tr(lang, "لا شيء هنا بعد. اضغط 📌 تحت أي إجابة لحفظها.", "Nothing here yet. Tap 📌 under any answer to save it."))
        for n in items:
            lines.append(f"▪️ <b>#{n['id']}</b> {html.escape(n['title'])} · {_date(n['ts'])}")
        rows = [[(f"👁 #{n['id']} {n['title'][:24]}", f"nt:v:{n['id']}")] for n in items]
        if pages > 1 and not query:
            nav = []
            if page > 0:
                nav.append(("◀️", f"nt:p:{page - 1}"))
            nav.append((f"{page + 1}/{pages}", "nt:p:%d" % page))
            if page < pages - 1:
                nav.append(("▶️", f"nt:p:{page + 1}"))
            rows.append(nav)
        rows.append([("🔎 " + tr(lang, "بحث", "Search"), "t:note_q"), ("📤 " + tr(lang, "تصدير", "Export"), "nt:export")])
        rows.append(self.home_row(lang))
        self._screen_h(chat_id, mid, "\n".join(lines), kb(rows))

    def view_note(self, chat_id, user, nid: int) -> None:
        lang = user["lang"]
        n = self.db.get_note(user["id"], nid)
        if not n:
            self.tg.send_message(chat_id, tr(lang, "الملاحظة غير موجودة.", "Note not found."))
            return
        self.send_md(chat_id, f"**📌 {n['title']}**\n_{_date(n['ts'])}_\n\n{n['text']}",
                     kb([[("🗑 " + tr(lang, "حذف", "Delete"), f"nt:d:{nid}"), ("📌 " + tr(lang, "مكتبتي", "Library"), "m:notes")]]))

    def export_notes(self, chat_id, user) -> None:
        lang, cid = user["lang"], user.get("case_id") or 0
        notes = self.db.list_notes(user["id"], cid, limit=MAX_NOTES)
        if not notes:
            self.tg.send_message(chat_id, tr(lang, "لا ملاحظات للتصدير.", "No notes to export."))
            return
        out = [f"# {tr(lang, 'مكتبتي', 'Library')} — {self._case_name(user, lang)}", ""]
        for n in reversed(notes):
            out += [f"## {n['title']} ({_date(n['ts'])})", n["text"], ""]
        self.tg.send_document(chat_id, "notes.md", "\n".join(out).encode("utf-8"))

    def send_last_answer_file(self, chat_id, user) -> None:
        last = self.db.last_assistant(self._hk(chat_id, user))
        if not last:
            self.tg.send_message(chat_id, tr(user["lang"], "لا توجد إجابة لتصديرها.", "There is no answer to export."))
            return
        self.tg.send_document(chat_id, f"darwin-{time.strftime('%Y%m%d-%H%M')}.md", last.encode("utf-8"))

    # ------------------------------------------------------------------ checklists
    def cmd_checklist(self, chat_id, user, args):
        key = args.strip().lower()
        if key in checklists.CHECKLISTS:
            self.show_checklist(chat_id, user, None, key, 0)
        else:
            self.show_checklists(chat_id, user)

    def show_checklists(self, chat_id, user, mid=None) -> None:
        lang = user["lang"]
        items = [(f"{ic} {ar if lang == 'ar' else en}", f"ck:{cid}:0:v") for cid, (ic, ar, en, _) in checklists.CHECKLISTS.items()]
        rows = [[b] for b in items] + [self.home_row(lang)]
        self._screen_h(chat_id, mid, tr(lang, "✅ <b>قوائم التحقق</b> — تفاعلية وتعمل بلا اتصال.\nاختر قائمة وعلّم ما أنجزته:",
                                        "✅ <b>Checklists</b> — interactive, work offline.\nPick one and tick what you have done:"),
                       kb(rows))

    def show_checklist(self, chat_id, user, mid, cid: str, mask: int) -> None:
        lang = user["lang"]
        n = len(checklists.CHECKLISTS[cid][3])
        mask &= checklists.full_mask(cid)
        toggles = [(("✅" if mask >> i & 1 else "⬜") + str(i + 1), f"ck:{cid}:{mask}:{i}") for i in range(n)]
        rows = chunk(toggles, 4)
        rows.append([("🔄 " + tr(lang, "إعادة", "Reset"), f"ck:{cid}:0:r"), ("📌 " + tr(lang, "حفظ", "Save"), f"ck:{cid}:{mask}:s")])
        rows.append([("⬅️ " + tr(lang, "القوائم", "Lists"), "ck:menu")] + self.home_row(lang))
        self._screen_h(chat_id, mid, checklists.render(cid, mask, lang), kb(rows))

    def checklist_callback(self, chat_id, user, mid, parts: list) -> None:
        lang = user["lang"]
        if len(parts) < 2 or parts[1] == "menu":
            self.show_checklists(chat_id, user, mid)
            return
        cid = parts[1]
        if cid not in checklists.CHECKLISTS or len(parts) < 4 or not parts[2].isdigit():
            return
        mask, act = int(parts[2]), parts[3]
        n = len(checklists.CHECKLISTS[cid][3])
        if act.isdigit() and int(act) < n:
            mask ^= 1 << int(act)
        elif act == "r":
            mask = 0
        elif act == "s":
            body = checklists.to_markdown(cid, mask, lang)
            nid = self.db.add_note(user["id"], user.get("case_id") or 0, _title_of(body), body, MAX_NOTES)
            self.tg.send_message(chat_id, tr(lang, f"📌 حُفظ التقدّم (#{nid}) في مكتبتك.", f"📌 Progress saved (#{nid}) to your library.")
                                 if nid else tr(lang, "مكتبتك ممتلئة.", "Your library is full."))
        self.show_checklist(chat_id, user, mid, cid, mask)

    # ------------------------------------------------------------------ report + profile
    def cmd_report(self, chat_id, user, args):
        lang = user["lang"]
        hk = self._hk(chat_id, user)
        if not self.db.get_history(hk, 1):
            self.tg.send_message(chat_id, tr(lang, "لا توجد محادثة لإعداد تقرير عنها. ابدأ بسؤال أولاً.",
                                             "There is no conversation to report on. Ask something first."))
            return
        notes = self.db.list_notes(user["id"], user.get("case_id") or 0, limit=10)
        notes_txt = "\n".join(f"- {n['title']}: {n['text'][:300]}" for n in notes) or "(none)"
        kind = args.strip()[:40] or "security incident / engagement"
        prompt = REPORT_PROMPT.format(kind=kind, language="Arabic" if lang == "ar" else "English",
                                      case=self._case_name(user, lang), notes=notes_txt)
        self._oneshot(chat_id, user, CORE_PROMPT, prompt, with_history=True, temperature=0.2)

    def cmd_me(self, chat_id, user, args):
        from .personas import PERSONAS
        lang, uid = user["lang"], user["id"]
        u = self._fresh(user)
        lim = self.cfg.daily_limit
        used = self.db.daily_count(uid)
        quota = ("∞" if not lim or self.is_admin(uid) else f"{used}/{lim}")
        persona = PERSONAS.get(u["persona"], PERSONAS["default"])[lang]
        notes_total = self.db.count_all_notes(uid)
        lines = [
            f"👤 <b>{html.escape(u.get('first_name') or '—')}</b> · <code>{uid}</code>",
            f"🎭 {html.escape(persona)}",
            f"🗂 {tr(lang, 'القضية', 'Case')}: {html.escape(self._case_name(u, lang))}",
            f"📏 {u.get('detail') or 'balanced'} · 🌡 {u['temperature']} · 🌐 {u['lang']}",
            "",
            f"💬 {tr(lang, 'الرسائل', 'Messages')}: {u['msgs']}  ·  📅 {tr(lang, 'اليوم', 'Today')}: {used} / {quota}",
            f"🔢 {tr(lang, 'الرموز', 'Tokens')}: {u['tokens_in']} ⬆ / {u['tokens_out']} ⬇",
            f"📌 {tr(lang, 'ملاحظات', 'Notes')}: {notes_total}  ·  🧠 {tr(lang, 'ذكريات', 'Memories')}: {len(self.db.list_facts(uid))}"
            f"  ·  ⏰ {tr(lang, 'تذكيرات', 'Reminders')}: {self.db.count_pending(uid)}",
        ]
        h = "\n".join(lines)
        self.tg.send_rich(chat_id, h, _plain(h), kb([[("📌 " + tr(lang, "مكتبتي", "Library"), "m:notes"),
                                                     ("🗂 " + tr(lang, "القضايا", "Cases"), "m:cases")], self.home_row(lang)]))

    # ------------------------------------------------------------------ callback router (cs / nt / ck)
    def workspace_callback(self, action, v, w, parts, chat_id, user, mid) -> bool:
        lang = user["lang"]
        if action == "m" and v in ("cases", "notes", "ck"):
            {"cases": self.show_cases, "notes": self.show_notes, "ck": self.show_checklists}[v](chat_id, user, mid)
        elif action == "cs":
            if v == "go" and w.isdigit():
                self.case_switch(chat_id, user, int(w), mid)
            elif v == "export":
                self.export_case(chat_id, user)
            elif v == "report":
                self.cmd_report(chat_id, user, "")
            elif v == "del" and user.get("case_id"):
                self._screen_h(chat_id, mid, tr(lang, f"🗑 حذف القضية «{html.escape(self._case_name(user, lang))}» مع محادثتها وملاحظاتها نهائياً؟",
                                                f"🗑 Permanently delete case “{html.escape(self._case_name(user, lang))}” with its chat and notes?"),
                               kb([[("✅ " + tr(lang, "نعم، احذف", "Yes, delete"), "cs:delyes"), ("❌ " + tr(lang, "لا", "No"), "m:cases")]]))
            elif v == "delyes" and user.get("case_id"):
                self.db.delete_case(user["id"], user["case_id"])
                self.show_cases(chat_id, self._fresh(user), mid)
        elif action == "nt":
            if v == "p" and w.isdigit():
                self.show_notes(chat_id, user, mid, int(w))
            elif v == "v" and w.isdigit():
                self.view_note(chat_id, user, int(w))
            elif v == "d" and w.isdigit():
                self.db.delete_note(user["id"], int(w))
                self.tg.send_message(chat_id, tr(lang, "🗑 حُذفت الملاحظة.", "🗑 Note deleted."))
                self.show_notes(chat_id, user)
            elif v == "export":
                self.export_notes(chat_id, user)
        elif action == "ck":
            self.checklist_callback(chat_id, user, mid, parts)
        elif action == "ans" and v == "save":
            self.save_last_answer(chat_id, user)
        elif action == "ans" and v == "file":
            self.send_last_answer_file(chat_id, user)
        else:
            return False
        return True
