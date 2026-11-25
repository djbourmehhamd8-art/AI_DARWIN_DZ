"""Problem reports: users send /problem (bug, wrong tool result, idea, abuse); admins triage them in Telegram or in the web panel.

One resolution path, `report_resolve`, is shared by the bot buttons, `/replyreport` and the web panel, so a reply always reaches
the user the same way and is always audited. Reports are private-chat only and rate-limited (anti-spam).
"""
from __future__ import annotations

import html
import time

from . import __version__
from .ui import kb, tr

KINDS = (  # key, icon, Arabic, English
    ("bug", "🐞", "خطأ في البوت", "Bot bug"),
    ("tool", "🧰", "أداة تعطي نتيجة خاطئة", "Tool gives a wrong result"),
    ("idea", "💡", "اقتراح أو ميزة", "Idea / feature request"),
    ("abuse", "🚫", "إساءة أو محتوى مخالف", "Abuse / bad content"),
    ("other", "❓", "أخرى", "Other"),
)
KIND_LABEL = {k: (ic, ar, en) for k, ic, ar, en in KINDS}
MIN_LEN, MAX_LEN = 5, 1500
MAX_PER_DAY, MAX_OPEN = 5, 10
LIST_SIZE = 8


def _e(x) -> str:
    return html.escape(str(x if x is not None else ""), quote=False)


def kind_label(kind: str, lang: str) -> str:
    ic, ar, en = KIND_LABEL.get(kind, KIND_LABEL["other"])
    return f"{ic} {ar if lang == 'ar' else en}"


def who(r: dict) -> str:
    name = r.get("first_name") or r.get("username") or str(r["user_id"])
    return f"{_e(str(name)[:40])}" + (f" @{_e(r['username'])}" if r.get("username") else "") + f" <code>{r['user_id']}</code>"


class ReportsMixin:
    def report_commands(self) -> dict:
        # NOTE: /report is the existing AI incident-report command (workspace.py); problem reports use /problem and friends.
        return {"problem": self.cmd_problem, "bug": self.cmd_problem, "issue": self.cmd_problem, "feedback": self.cmd_problem,
                "myreports": self.cmd_myreports}

    def report_admin_commands(self) -> dict:
        return {"reports": self.cmd_reports_admin, "replyreport": self.cmd_replyreport}

    # ------------------------------------------------------------------ user side
    def report_menu_kb(self, lang):
        rows = [[(f"{ic} {ar if lang == 'ar' else en}", f"rp:new:{k}")] for k, ic, ar, en in KINDS]
        rows.append([("📋 " + tr(lang, "بلاغاتي", "My reports"), "rp:my")] + self.home_row(lang))
        return kb(rows)

    def cmd_problem(self, chat_id, user, args) -> None:
        lang = user["lang"]
        if chat_id < 0:
            self.tg.send_message(chat_id, tr(lang, "🐞 أرسل /problem لي في المحادثة الخاصة.", "🐞 Send /problem to me in a private chat."))
            return
        if args.strip():
            self.report_submit(chat_id, user, "other", args)
            return
        self.tg.send_message(chat_id, tr(lang, "🐞 <b>الإبلاغ عن مشكلة</b>\nما نوع المشكلة؟ (أو اكتب: <code>/problem وصف المشكلة</code>)",
                                         "🐞 <b>Report a problem</b>\nWhat kind of problem? (or type: <code>/problem describe it</code>)"),
                             self.report_menu_kb(lang))

    def report_submit(self, chat_id, user, kind: str, text: str) -> None:
        lang, uid = user["lang"], user["id"]
        text = (text or "").strip()
        if len(text) < MIN_LEN:
            self.tg.send_message(chat_id, tr(lang, "✍️ اكتب وصفاً أوضح للمشكلة (5 أحرف على الأقل).", "✍️ Please describe the problem a bit more (5 characters minimum)."),
                                 kb([[("🐞 " + tr(lang, "حاول مجدداً", "Try again"), "rp:new:" + (kind if kind in KIND_LABEL else "other"))]]))
            return
        if self.db.reports_since(uid, 86400) >= MAX_PER_DAY or self.db.open_reports_of(uid) >= MAX_OPEN:
            self.tg.send_message(chat_id, tr(lang, "⏳ وصلتَ للحد المسموح من البلاغات حالياً. سننظر فيما أرسلته، وجرّب لاحقاً.",
                                             "⏳ You have reached the current report limit. We are reviewing what you sent; please try later."))
            return
        prior = self.db.reports_of_user(uid, 3)
        if any(p["text"] == text[:MAX_LEN] and time.time() - p["created_at"] < 600 for p in prior):
            self.tg.send_message(chat_id, tr(lang, "✅ استلمنا هذا البلاغ قبل قليل.", "✅ We already received this report a moment ago."))
            return
        recent = self.recent_tools(uid)
        ctx = f"v{__version__}" + (f" · last tool: {recent[0]}" if recent else "") + f" · {lang}"
        rid = self.db.add_report(uid, kind, text[:MAX_LEN], ctx)
        self.db.add_audit(uid, "report_new", f"#{rid} {kind}")
        note = tr(lang, "\n(اختُصر النص إلى 1500 حرف)", "\n(text trimmed to 1500 characters)") if len(text) > MAX_LEN else ""
        self.tg.send_message(chat_id, tr(lang, f"✅ شكراً! سُجّل بلاغك <b>#{rid}</b> ({kind_label(kind, 'ar')}).\nسيصلك ردّ هنا عند مراجعته.{note}",
                                         f"✅ Thank you! Your report <b>#{rid}</b> ({kind_label(kind, 'en')}) was recorded.\nYou will get a reply here once it is reviewed.{note}"),
                             kb([[("📋 " + tr(lang, "بلاغاتي", "My reports"), "rp:my")] + self.home_row(lang)]))
        self._report_alert_admins(rid)

    def _report_alert_admins(self, rid: int) -> None:
        r = self.db.get_report(rid)
        if not r:
            return
        for aid in self.cfg.admin_ids:
            try:
                lang = self._lang_of(aid)
                self.tg.send_message(aid, self._report_card(r, lang, short=True),
                                     kb([[("👁 " + tr(lang, "عرض", "View"), f"rp:view:{rid}"), ("✅ " + tr(lang, "إغلاق", "Close"), f"rp:close:{rid}"),
                                          ("💬 " + tr(lang, "رد", "Reply"), f"rp:reply:{rid}")]]))
            except Exception:                                       # one unreachable admin must not lose the report
                pass

    def cmd_myreports(self, chat_id, user, args) -> None:
        lang = user["lang"]
        rows = self.db.reports_of_user(user["id"], 6)
        if not rows:
            self.tg.send_message(chat_id, tr(lang, "📋 لا توجد بلاغات لديك بعد. استخدم /problem", "📋 You have no reports yet. Use /problem"), kb([[("🐞 " + tr(lang, "بلاغ جديد", "New report"), "rp:menu")]]))
            return
        lines = []
        for r in rows:
            st = tr(lang, "✅ مُغلق", "✅ closed") if r["status"] == "closed" else tr(lang, "🟡 مفتوح", "🟡 open")
            lines.append(f"<b>#{r['id']}</b> {kind_label(r['kind'], lang)} · {st}\n<i>{_e(r['text'][:120])}</i>" + (f"\n💬 {_e(r['reply'][:300])}" if r["reply"] else ""))
        self.tg.send_message(chat_id, "📋 <b>" + tr(lang, "بلاغاتي", "My reports") + "</b>\n\n" + "\n\n".join(lines),
                             kb([[("🐞 " + tr(lang, "بلاغ جديد", "New report"), "rp:menu")] + self.home_row(lang)]))

    # ------------------------------------------------------------------ admin side
    def _report_card(self, r: dict, lang: str, short: bool = False) -> str:
        st = "✅ " + tr(lang, "مُغلق", "closed") if r["status"] == "closed" else "🟡 " + tr(lang, "مفتوح", "open")
        body = r["text"][:300] + ("…" if short and len(r["text"]) > 300 else "") if short else r["text"]
        out = (f"🐞 <b>{tr(lang, 'بلاغ', 'Report')} #{r['id']}</b> · {kind_label(r['kind'], lang)} · {st}\n{who(r)}\n"
               f"🕐 {time.strftime('%Y-%m-%d %H:%M', time.localtime(r['created_at']))}" + (f" · <code>{_e(r['ctx'])}</code>" if r.get("ctx") else "") + f"\n\n{_e(body)}")
        if r.get("reply"):
            out += f"\n\n💬 <b>{tr(lang, 'الرد', 'Reply')}:</b> {_e(r['reply'])}"
        return out

    def _report_kb(self, r: dict, lang: str):
        rid = r["id"]
        toggle = ("♻️ " + tr(lang, "إعادة فتح", "Reopen"), f"rp:open:{rid}") if r["status"] == "closed" else ("✅ " + tr(lang, "إغلاق", "Close"), f"rp:close:{rid}")
        return kb([[("💬 " + tr(lang, "رد", "Reply"), f"rp:reply:{rid}"), toggle],
                   [("🗑 " + tr(lang, "حذف", "Delete"), f"rp:del:{rid}"), ("📋 " + tr(lang, "القائمة", "List"), "rp:list:open")] + [self.home_row(lang)[0]]])

    def show_reports_list(self, chat_id, user, status="open", mid=None) -> None:
        lang = user["lang"]
        status = status if status in ("open", "closed", "") else "open"
        rows, total = self.db.list_reports(status, limit=LIST_SIZE)
        counts = self.db.report_counts()
        head = "📨 <b>" + tr(lang, "البلاغات", "Reports") + f"</b> · 🟡 {counts['open']} · ✅ {counts['closed']}"
        lines = [f"<b>#{r['id']}</b> {KIND_LABEL.get(r['kind'], KIND_LABEL['other'])[0]} {_e(str(r.get('first_name') or r.get('username') or r['user_id'])[:20])}: {_e(r['text'][:60])}" for r in rows]
        text = head + "\n\n" + ("\n".join(lines) if lines else tr(lang, "لا توجد بلاغات.", "No reports.")) + (f"\n… +{total - len(rows)}" if total > len(rows) else "")
        tabs = [(("• " if status == s else "") + t, f"rp:list:{s or 'all'}") for s, t in (("open", tr(lang, "مفتوحة", "Open")), ("closed", tr(lang, "مغلقة", "Closed")), ("", tr(lang, "الكل", "All")))]
        buttons = [[(f"👁 #{r['id']}", f"rp:view:{r['id']}") for r in rows[i:i + 4]] for i in range(0, len(rows), 4)]
        markup = kb([tabs] + buttons + [self.home_row(lang)])
        if mid and self.tg.edit_message_text(chat_id, mid, text, markup):
            return
        self.tg.send_message(chat_id, text, markup)

    def cmd_reports_admin(self, chat_id, user, args) -> None:
        a = args.strip().lstrip("#")
        if a.isdigit():
            return self.show_report(chat_id, user, int(a))
        self.show_reports_list(chat_id, user, a if a in ("open", "closed") else ("" if a == "all" else "open"))

    def show_report(self, chat_id, user, rid: int, mid=None) -> None:
        lang = user["lang"]
        r = self.db.get_report(rid)
        if not r:
            self.tg.send_message(chat_id, tr(lang, "🔍 البلاغ غير موجود.", "🔍 Report not found."))
            return
        text, markup = self._report_card(r, lang), self._report_kb(r, lang)
        if mid and self.tg.edit_message_text(chat_id, mid, text, markup):
            return
        self.tg.send_message(chat_id, text, markup)

    def cmd_replyreport(self, chat_id, user, args) -> None:
        lang = user["lang"]
        head, _, text = args.strip().partition(" ")
        if not head.lstrip("#").isdigit() or not text.strip():
            self.tg.send_message(chat_id, tr(lang, "💬 الاستخدام: /replyreport رقم نص الرد", "💬 Usage: /replyreport number reply text"))
            return
        _ok, msg = self.report_resolve(int(head.lstrip("#")), text.strip(), True, user["id"])
        self.tg.send_message(chat_id, msg)

    def report_resolve(self, rid: int, reply: str, close: bool, actor: int) -> tuple:
        """Store the reply, optionally close, tell the user. Shared by Telegram and the web panel. -> (ok, message)."""
        r = self.db.get_report(rid)
        if not r:
            return False, "🔍 البلاغ غير موجود."
        reply = reply.strip()[:1500]
        self.db.set_report(rid, status="closed" if close else "", reply=reply)
        self.db.add_audit(actor, "report_reply" if reply else "report_close", f"#{rid} → {r['user_id']}")
        delivered = False
        if reply or close:
            lang = r.get("lang") or "ar"
            body = tr(lang, f"📨 <b>ردّ على بلاغك #{rid}</b>", f"📨 <b>Reply to your report #{rid}</b>")
            if reply:
                body += f"\n\n{_e(reply)}"
            if close:
                body += "\n\n" + tr(lang, "✅ أُغلق البلاغ. شكراً لمساعدتك!", "✅ The report is closed. Thanks for helping!")
            try:
                delivered = bool(self.tg.send_message(r["user_id"], body))
            except Exception:
                delivered = False
        return True, f"✅ #{rid}" + (" ⚠️ تعذّر إرسال الرد للمستخدم (ربما حظر البوت)." if (reply or close) and not delivered else "")

    def report_callback(self, action, v, w, chat_id, user, mid) -> bool:
        if action != "rp":
            return False
        lang, uid = user["lang"], user["id"]
        if v == "menu":
            self._screen(chat_id, mid, tr(lang, "🐞 <b>الإبلاغ عن مشكلة</b>\nما نوع المشكلة؟", "🐞 <b>Report a problem</b>\nWhat kind of problem?"), self.report_menu_kb(lang))
        elif v == "new":
            self.ask(chat_id, user, "rep_" + (w if w in KIND_LABEL else "other"), mid)
        elif v == "my":
            self.cmd_myreports(chat_id, user, "")
        else:
            if not self.is_admin(uid) or chat_id < 0:                         # triage is for admins, in private chat only
                return True
            rid = int(w) if w.isdigit() else 0
            if v == "list":
                self.show_reports_list(chat_id, user, {"all": ""}.get(w, w), mid)
            elif v == "view":
                self.show_report(chat_id, user, rid, mid)
            elif v in ("close", "open"):
                if self.db.get_report(rid):
                    self.db.set_report(rid, status="closed" if v == "close" else "open")
                    self.db.add_audit(uid, "report_" + v, f"#{rid}")
                self.show_report(chat_id, user, rid, mid)
            elif v == "reply":
                self.report_reply_target[uid] = rid
                self.ask(chat_id, user, "rep_reply", mid)
            elif v == "del":
                self._screen(chat_id, mid, tr(lang, f"🗑 حذف البلاغ #{rid} نهائياً؟", f"🗑 Delete report #{rid} permanently?"),
                             kb([[("✅ " + tr(lang, "نعم", "Yes"), f"rp:delyes:{rid}"), ("❌ " + tr(lang, "لا", "No"), f"rp:view:{rid}")]]))
            elif v == "delyes":
                self.db.delete_report(rid)
                self.db.add_audit(uid, "report_delete", f"#{rid}")
                self.show_reports_list(chat_id, user, "open", mid)
        return True

    def report_pending(self, chat_id, user, kind: str, text: str) -> None:
        """Called from run_pending for the rep_* kinds."""
        if kind == "rep_reply":
            if not self.is_admin(user["id"]):
                return
            rid = self.report_reply_target.pop(user["id"], 0)
            _ok, msg = self.report_resolve(rid, text, True, user["id"]) if rid else (False, "…")
            self.tg.send_message(chat_id, msg, kb([[("📋 " + tr(user["lang"], "القائمة", "List"), "rp:list:open")] + self.home_row(user["lang"])]))
        else:
            self.report_submit(chat_id, user, kind[4:], text)
