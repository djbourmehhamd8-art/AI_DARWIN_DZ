"""Admin control panel with two levels.

Admin (ADMIN_IDS)   : everything — users, requests, groups, broadcast, backup, CSV, limits, roles, maintenance.
Moderator (role=mod): users list/cards, access requests, allow/disallow/temporary access, ban/unban.

Every action is private-chat-only (never in a group), audited, and never touches admins (or, for moderators,
other moderators)."""
from __future__ import annotations

import csv
import html
import io
import re
import time
from pathlib import Path

from . import __version__
from .ui import kb, tr
from .utils import fmt_duration

PAGE = 8
FILTERS = {"": "", "b": "banned", "a": "allowed", "p": "pending", "s": "staff"}
# callbacks a moderator may use; everything else is admin-only
STAFF_CALLS = frozenset({"ul", "u", "ap", "ap7", "rj", "tmp", "al", "da", "ub", "bq", "ban", "top", "rq", "home"})
TEMP_DAYS = (1, 7, 30)
LIMITS = (("d", "default"), ("10", "10"), ("50", "50"), ("200", "200"), ("0", "∞"))


def _plain(h: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", h))


def _esc(x) -> str:
    return html.escape(str(x if x is not None else ""), quote=False)


def _cell(v) -> str:
    """CSV cell safe against spreadsheet formula injection."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def user_label(u: dict) -> str:
    name = (u.get("first_name") or "").strip() or (("@" + u["username"]) if u.get("username") else str(u["id"]))
    return name[:22]


def _day(ts) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(ts)) if ts else "-"


class AdminPanelMixin:
    # ------------------------------------------------------------------ helpers
    def _html_screen(self, chat_id, mid, text, markup=None) -> None:
        if mid and self.tg.edit_rich(chat_id, mid, text, _plain(text), markup):
            return
        self.tg.send_rich(chat_id, text, _plain(text), markup)

    def _back_row(self, lang, to="m:adm", label=None):
        return [("🔙 " + (label or tr(lang, "اللوحة", "Panel")), to)]

    def _role_of(self, u: dict) -> str:
        if u["id"] in self.cfg.admin_ids:
            return "admin"
        return "mod" if u.get("role") == "mod" else "user"

    def _status_of(self, u: dict) -> str:
        role = self._role_of(u)
        if role == "admin":
            return "👑 admin"
        if u.get("banned"):
            return "🚫 banned"
        badge = "🛡 mod · " if role == "mod" else ""
        exp = u.get("expires_at") or 0
        if u.get("allowed") or u["id"] in self.cfg.allowed_ids:
            return badge + "✅ allowed" + (f" ⏳ {_day(exp)}" if exp else "")
        if (u.get("requested_at") or 0) > 0:
            return badge + "🔔 requested"
        return badge + "👤 " + ("public" if self.cfg.public else "no access")

    def _can_manage(self, actor: dict, tid: int) -> bool:
        """Never admins or yourself; moderators additionally cannot manage other moderators."""
        if tid <= 0 or tid in self.cfg.admin_ids or tid == actor["id"]:
            return False
        if not self.is_admin(actor["id"]):
            t = self.db.get_user(tid)
            if t and t.get("role") == "mod":
                return False
        return True

    def cmd_panel(self, chat_id, user, args) -> None:
        if chat_id < 0 or not self.is_staff(user["id"]):
            self.tg.send_message(chat_id, tr(user["lang"], "⛔ للمشرفين فقط (في المحادثة الخاصة).", "⛔ Staff only (in private chat)."))
            return
        self.admin_home(chat_id, user)

    # ------------------------------------------------------------------ dashboard
    def admin_home(self, chat_id, user, mid=None) -> None:
        lang = user["lang"]
        full = self.is_admin(user["id"])
        s = self.db.stats()
        pend = self.db.count_users("pending")
        lines = [f"👥 {s['users']} {tr(lang, 'مستخدم', 'users')} · 🟢 {s['active24']} {tr(lang, 'نشط 24س', 'active 24h')} · 🚫 {s['banned']}",
                 f"🔔 {pend} {tr(lang, 'طلب معلّق', 'pending requests')} · 👥 {self.db.count_chats()} {tr(lang, 'مجموعة', 'groups')}"]
        if full:
            keys = f"{self.ai.pool.available()}/{len(self.ai.pool)}"
            lines.append(f"📨 {s['msgs']} {tr(lang, 'رسالة', 'messages')} · 🔑 {keys} {tr(lang, 'مفاتيح', 'keys')}")
            lines.append(f"⏱ {fmt_duration(time.time() - self.started)} · {'🌍 PUBLIC' if self.cfg.public else '🔒 private'}"
                         f"{' · 🛠 ' + tr(lang, 'صيانة', 'MAINTENANCE') if self.maintenance else ''}")
        title = tr(lang, "لوحة المدير", "Admin panel") if full else tr(lang, "لوحة الإشراف", "Moderation panel")
        text = f"{'👑' if full else '🛡'} <b>{title}</b> · v{__version__}\n<blockquote>" + "\n".join(lines) + "</blockquote>"
        self._html_screen(chat_id, mid, text, self.admin_kb(lang, full, pend))

    def admin_sys(self, chat_id, user, mid=None) -> None:
        lang = user["lang"]
        try:
            db_state = self.db.integrity_check()
        except Exception as exc:                                    # never break the panel on a diagnostic
            db_state = f"error ({type(exc).__name__})"
        try:
            size_kb = Path(self.cfg.db_path).stat().st_size // 1024
        except OSError:
            size_kb = 0
        ok = db_state.lower() == "ok"
        priv = tr(lang, "🟢 يقرأ كل رسائل المجموعات", "🟢 reads all group messages") if self.can_read_all else \
            tr(lang, "🟠 Privacy Mode مفعّل (يرى الأوامر والإشارات فقط)", "🟠 Privacy Mode ON (sees commands/mentions only)")
        text = (f"🩺 <b>{tr(lang, 'حالة النظام', 'System status')}</b>\n"
                f"<blockquote>{'🟢' if ok else '🔴'} SQLite: {_esc(db_state)} · {size_kb} KB\n"
                f"🔑 {tr(lang, 'مفاتيح API', 'API keys')}: {self.ai.pool.available()}/{len(self.ai.pool)}\n"
                f"⚙️ {tr(lang, 'ردود جارية', 'Replies running')}: {len(self.cancels)}/{self.cfg.workers}\n"
                f"⏰ {tr(lang, 'تذكيرات معلّقة', 'Pending reminders')}: {self.db.pending_total()}\n"
                f"👥 {tr(lang, 'مجموعات', 'Groups')}: {self.db.count_chats()} · {priv}\n"
                f"🤖 {_esc(self.cfg.model)}\n"
                f"⏱ {fmt_duration(time.time() - self.started)}</blockquote>")
        self._html_screen(chat_id, mid, text, kb([
            [("🔄 " + tr(lang, "تحديث", "Refresh"), "adm:sys"), ("🔑 " + tr(lang, "المفاتيح", "Keys"), "adm:keys")],
            [("🔎 " + tr(lang, "تشخيص", "Diagnostics"), "adm:diag")],
            self._back_row(lang)]))

    # ------------------------------------------------------------------ users
    def admin_users_page(self, chat_id, user, mid, page: int, flt: str) -> None:
        lang = user["lang"]
        flt = flt if flt in FILTERS else ""
        where = FILTERS[flt]
        total = self.db.count_users(where)
        pages = max(1, -(-total // PAGE))
        page = max(0, min(page, pages - 1))
        rows = self.db.list_users(PAGE, page * PAGE, where)
        title = {"": tr(lang, "المستخدمون", "Users"), "b": tr(lang, "المحظورون", "Banned"), "a": tr(lang, "المسموحون", "Allowed"),
                 "p": tr(lang, "طلبات الصلاحية", "Access requests"), "s": tr(lang, "الإشراف", "Staff")}[flt]
        text = f"👥 <b>{title}</b> — {total}\n<i>{tr(lang, 'صفحة', 'Page')} {page + 1}/{pages}</i>"
        if not rows:
            text += "\n\n—"
        sfx = f":{flt}" if flt else ""
        buttons = []
        for u in rows:
            mark = ("👑" if u["id"] in self.cfg.admin_ids else "🛡" if u.get("role") == "mod" else "🚫" if u["banned"]
                    else "✅" if u["allowed"] else "🔔" if (u.get("requested_at") or 0) > 0 else "👤")
            buttons.append([(f"{mark} {user_label(u)} · {u['msgs']}", f"adm:u:{u['id']}", "primary" if mark in ("👤", "🔔") else None)])
        nav = []
        if page > 0:
            nav.append(("◀️", f"adm:ul:{page - 1}{sfx}"))
        if page < pages - 1:
            nav.append(("▶️", f"adm:ul:{page + 1}{sfx}"))
        if nav:
            buttons.append(nav)
        buttons.append([("🔎 " + tr(lang, "بحث", "Find"), "t:adm_find")] + self._back_row(lang))
        self._html_screen(chat_id, mid, text, kb(buttons))

    def admin_top(self, chat_id, user, mid) -> None:
        lang = user["lang"]
        rows = self.db.top_users(8)
        lines = [f"{i}. {_esc(user_label(u))} — 📨 {u['msgs']} · 🧮 {u['tokens_in'] + u['tokens_out']}" for i, u in enumerate(rows, 1)]
        text = f"🏆 <b>{tr(lang, 'الأكثر استخداماً', 'Top users')}</b>\n<blockquote>" + ("\n".join(lines) or "—") + "</blockquote>"
        buttons = [[(f"{i}. {user_label(u)}", f"adm:u:{u['id']}")] for i, u in enumerate(rows[:5], 1)]
        self._html_screen(chat_id, mid, text, kb(buttons + [self._back_row(lang)]))

    def admin_user_card(self, chat_id, user, target: dict, mid=None) -> None:
        lang = user["lang"]
        tid = target["id"]
        full = self.is_admin(user["id"])
        last = time.strftime("%Y-%m-%d %H:%M", time.localtime(target["last_seen"]))
        lim = target.get("limit_override", -1)
        lim_txt = tr(lang, "افتراضي", "default") if lim is None or lim < 0 else ("∞" if lim == 0 else str(lim))
        text = (f"👤 <b>{_esc(user_label(target))}</b> · <code>{tid}</code>\n"
                f"<blockquote>@{_esc(target.get('username') or '-')} · {self._status_of(target)}\n"
                f"📨 {target['msgs']} · 🧮 {target['tokens_in']}/{target['tokens_out']} tok · 📊 {tr(lang, 'حد يومي', 'daily limit')}: {lim_txt}\n"
                f"🕓 {last} · 🌐 {target['lang']}</blockquote>")
        rows = []
        if self._can_manage(user, tid):
            if (target.get("requested_at") or 0) != 0 and not target["allowed"] and not target["banned"]:
                rows.append([("✅ " + tr(lang, "موافقة", "Approve"), f"adm:ap:{tid}"), ("⏳ " + tr(lang, "7 أيام", "7 days"), f"adm:ap7:{tid}"),
                             ("❌ " + tr(lang, "رفض", "Reject"), f"adm:rj:{tid}")])
            ban_btn = ("✅ " + tr(lang, "فك الحظر", "Unban"), f"adm:ub:{tid}") if target["banned"] else \
                      ("🚫 " + tr(lang, "حظر", "Ban"), f"adm:bq:{tid}")
            allow_btn = ("➖ " + tr(lang, "سحب السماح", "Disallow"), f"adm:da:{tid}", "danger") if target["allowed"] else \
                        ("➕ " + tr(lang, "سماح", "Allow"), f"adm:al:{tid}")
            rows.append([ban_btn, allow_btn])
            rows.append([(f"⏳ {d} " + tr(lang, "يوم", "d"), f"adm:tmp:{tid}:{d}") for d in TEMP_DAYS])
            if full:
                rows.append([("✉️ " + tr(lang, "راسله", "Message"), f"adm:dm:{tid}"), ("📊 " + tr(lang, "الحد اليومي", "Limit"), f"adm:lim:{tid}")])
                mod_btn = ("🛡 " + tr(lang, "إلغاء الإشراف", "Remove mod"), f"adm:mod:{tid}", "danger") if target.get("role") == "mod" else \
                          ("🛡 " + tr(lang, "ترقية لمشرف", "Make mod"), f"adm:mod:{tid}")
                rows.append([mod_btn, ("🧹 " + tr(lang, "مسح محادثته", "Clear chat"), f"adm:cq:{tid}")])
        rows.append(self._back_row(lang, "adm:ul:0", tr(lang, "المستخدمون", "Users")) + [("🏠", "m:adm")])
        self._html_screen(chat_id, mid, text, kb(rows))

    def _confirm(self, chat_id, mid, lang, question: str, yes: tuple, back: str) -> None:
        self._html_screen(chat_id, mid, f"⚠️ <b>{question}</b>", kb([[yes, ("❌ " + tr(lang, "إلغاء", "Cancel"), back)]]))

    def _flag(self, actor: dict, tid: int, action: str, **fields) -> bool:
        """Change access flags. Refuses invalid ids, admins, yourself (and mods for moderators)."""
        if not self._can_manage(actor, tid):
            return False
        self.db.ensure_user_row(tid, self.cfg.default_lang, self.cfg.default_temp)
        self.db.set_user(tid, **fields)
        self.db.add_audit(actor["id"], action, str(tid))
        return True

    def adm_find(self, chat_id, user, args) -> None:
        target = self.db.find_user(args)
        if not target:
            self.tg.send_message(chat_id, tr(user["lang"], "🔍 لم أجد هذا المستخدم.", "🔍 User not found."),
                                 kb([self._back_row(user["lang"])]))
            return
        self.admin_user_card(chat_id, user, target)

    # ------------------------------------------------------------------ direct message to a user
    def adm_dm_pending(self, chat_id, user, args) -> None:
        """Button flow only: the admin pressed ✉️ on a card, now sends the text. A stale target is never reused."""
        tid = self.dm_target.pop(user["id"], None)
        if tid is None or not args.strip():
            return
        self._send_dm(chat_id, user, tid, args.strip())

    def adm_dm_send(self, chat_id, user, args) -> None:
        """Command flow: /dm <id> <text> (the id is always explicit)."""
        self.dm_target.pop(user["id"], None)
        first, _, rest = args.strip().partition(" ")
        if not first.isdigit() or not rest.strip():
            self.tg.send_message(chat_id, tr(user["lang"], "✉️ الاستخدام: /dm المعرّف النص", "✉️ Usage: /dm <id> <text>"))
            return
        self._send_dm(chat_id, user, int(first), rest.strip())

    def _send_dm(self, chat_id, user, tid: int, text: str) -> None:
        lang = user["lang"]
        if tid <= 0 or not self.db.get_user(tid):
            self.tg.send_message(chat_id, tr(lang, "🔍 المستخدم غير موجود.", "🔍 User not found."))
            return
        ok = self.tg.send_message(tid, tr(self._lang_of(tid), "📩 رسالة من إدارة DARWIN DZ:\n\n", "📩 Message from DARWIN DZ admin:\n\n") + text[:3500])
        self.db.add_audit(user["id"], "dm", f"{tid}: {text[:100]}")
        self.tg.send_message(chat_id, tr(lang, "✅ أُرسلت.", "✅ Sent.") if ok else
                             tr(lang, "⚠️ تعذّر الإرسال (ربما أوقف المستخدم البوت).", "⚠️ Could not deliver (the user may have blocked the bot)."),
                             kb([[("👤 " + tr(lang, "البطاقة", "Card"), f"adm:u:{tid}")] + self._back_row(lang)]))

    # ------------------------------------------------------------------ groups
    def admin_groups_page(self, chat_id, user, mid, page: int) -> None:
        lang = user["lang"]
        total = self.db.count_chats()
        pages = max(1, -(-total // PAGE))
        page = max(0, min(page, pages - 1))
        rows = self.db.list_chats(PAGE, page * PAGE)
        text = (f"👥 <b>{tr(lang, 'المجموعات', 'Groups')}</b> — {total}\n<i>{tr(lang, 'صفحة', 'Page')} {page + 1}/{pages}</i>\n"
                f"<blockquote>{'🌍 GROUP_OPEN' if self.cfg.group_open else tr(lang, 'كل مجموعة تحتاج تفعيلاً', 'every group needs activation')}</blockquote>")
        buttons = [[(("✅ " if c["allowed"] else "⏳ ") + (c["title"] or str(c["id"]))[:28], f"adm:gc:{c['id']}")] for c in rows]
        nav = ([("◀️", f"adm:gl:{page - 1}")] if page > 0 else []) + ([("▶️", f"adm:gl:{page + 1}")] if page < pages - 1 else [])
        if nav:
            buttons.append(nav)
        self._html_screen(chat_id, mid, text, kb(buttons + [self._back_row(lang)]))

    def admin_group_card(self, chat_id, user, row: dict, mid=None) -> None:
        lang, cid = user["lang"], row["id"]
        text = (f"👥 <b>{_esc(row['title'] or '-')}</b>\n<blockquote>🆔 <code>{cid}</code>\n"
                f"{'✅ ' + tr(lang, 'مفعّلة', 'activated') if row['allowed'] else '⏳ ' + tr(lang, 'بانتظار التفعيل', 'waiting for activation')}\n"
                f"🕓 {time.strftime('%Y-%m-%d %H:%M', time.localtime(row['last_seen']))}</blockquote>")
        toggle = ("⛔ " + tr(lang, "إيقاف", "Deactivate"), f"adm:grv:{cid}", "danger") if row["allowed"] else \
                 ("✅ " + tr(lang, "تفعيل", "Activate"), f"adm:gok:{cid}")
        self._html_screen(chat_id, mid, text, kb([[toggle, ("🚪 " + tr(lang, "مغادرة", "Leave"), f"adm:glq:{cid}")],
                                                  self._back_row(lang, "adm:gl:0", tr(lang, "المجموعات", "Groups"))]))

    # ------------------------------------------------------------------ CSV export
    def admin_csv(self, chat_id, user) -> None:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["id", "username", "name", "lang", "role", "allowed", "banned", "expires", "msgs", "tokens_in", "tokens_out", "last_seen"])
        for u in self.db.list_users(10 ** 6):
            w.writerow([u["id"], _cell(u.get("username")), _cell(u.get("first_name")), u["lang"], self._role_of(u),
                        u["allowed"], u["banned"], _day(u.get("expires_at")), u["msgs"], u["tokens_in"], u["tokens_out"],
                        time.strftime("%Y-%m-%d %H:%M", time.localtime(u["last_seen"]))])
        self.db.add_audit(user["id"], "export_csv", "")
        self.tg.send_document(chat_id, f"users-{time.strftime('%Y%m%d-%H%M')}.csv", buf.getvalue().encode("utf-8-sig"))

    # ------------------------------------------------------------------ callback router
    def admin_callback(self, v, w, parts, chat_id, user, mid) -> None:
        lang = user["lang"]
        uid = user["id"]
        full = self.is_admin(uid)
        if v not in STAFF_CALLS and not full:
            self.tg.send_message(chat_id, tr(lang, "⛔ للمدير فقط.", "⛔ Admin only."))
            return
        if v in ("home", "rq"):
            if v == "rq":
                self.admin_users_page(chat_id, user, mid, 0, "p")
            else:
                self.admin_home(chat_id, user, mid)
        elif v == "bcyes":
            text = self.drafts.pop(uid, "")
            if text:
                self._screen(chat_id, mid, tr(lang, "📣 جارٍ الإرسال…", "📣 Sending…"))
                self.adm_broadcast(chat_id, user, text)
        elif v == "sys":
            self.admin_sys(chat_id, user, mid)
        elif v == "mnt":
            self.maintenance = not self.maintenance
            self.db.add_audit(uid, "maintenance", "on" if self.maintenance else "off")
            self.admin_home(chat_id, user, mid)
        elif v == "top":
            self.admin_top(chat_id, user, mid)
        elif v == "csv":
            self.admin_csv(chat_id, user)
        elif v == "ul":
            try:
                page = int(w or 0)
            except ValueError:
                page = 0
            self.admin_users_page(chat_id, user, mid, page, parts[3] if len(parts) > 3 else "")
        elif v in ("gl", "gc", "gok", "grv", "glq", "glv"):
            self._group_callback(v, w, chat_id, user, mid)
        elif v in ("u", "bq", "ban", "ub", "al", "da", "cq", "cy", "ap", "ap7", "rj", "tmp", "lim", "mod", "dm"):
            self._user_callback(v, w, parts, chat_id, user, mid)
        else:
            fn = {"stats": self.adm_stats, "users": self.adm_users, "audit": self.adm_audit,
                  "backup": self.adm_backup, "status": self.adm_status, "keys": self.adm_keys,
                  "diag": self.adm_diag}.get(v)
            if fn:
                fn(chat_id, user, "")

    def _group_callback(self, v, w, chat_id, user, mid) -> None:
        lang = user["lang"]
        if v == "gl":
            self.admin_groups_page(chat_id, user, mid, int(w) if (w or "0").lstrip("-").isdigit() else 0)
            return
        try:
            cid = int(w)
        except ValueError:
            return
        row = self.db.get_chat(cid)
        if not row:
            self._html_screen(chat_id, mid, tr(lang, "🔍 المجموعة غير موجودة.", "🔍 Group not found."), kb([self._back_row(lang, "adm:gl:0")]))
            return
        if v == "gc":
            pass
        elif v == "gok":
            self.db.set_chat_allowed(cid, True)
            self.db.add_audit(user["id"], "group_allow", str(cid))
            self.tg.send_message(cid, "✅ تم تفعيل المجموعة. اكتب DZ ثم سؤالك.\n✅ Group activated. Write DZ then your question.")
        elif v == "grv":
            self.db.set_chat_allowed(cid, False)
            self.db.add_audit(user["id"], "group_revoke", str(cid))
        elif v == "glq":
            self._confirm(chat_id, mid, lang, tr(lang, f"مغادرة «{_esc(row['title'])}»؟", f"Leave “{_esc(row['title'])}”?"),
                          ("🚪 " + tr(lang, "نعم، غادر", "Yes, leave"), f"adm:glv:{cid}"), f"adm:gc:{cid}")
            return
        elif v == "glv":
            self.tg.leave_chat(cid)
            self.db.delete_chat(cid)
            self.db.add_audit(user["id"], "group_leave", str(cid))
            self.admin_groups_page(chat_id, user, mid, 0)
            return
        self.admin_group_card(chat_id, user, self.db.get_chat(cid), mid)

    def _user_callback(self, v, w, parts, chat_id, user, mid) -> None:
        lang = user["lang"]
        uid = user["id"]
        try:
            tid = int(w)
        except ValueError:
            return
        target = self.db.get_user(tid)
        if not target:
            self._screen(chat_id, mid, tr(lang, "🔍 المستخدم غير موجود.", "🔍 User not found."), kb([self._back_row(lang)]))
            return
        back = f"adm:u:{tid}"
        name = _esc(user_label(target))
        if v == "u":
            self.admin_user_card(chat_id, user, target, mid)
            return
        if not self._can_manage(user, tid):
            self.tg.send_message(chat_id, tr(lang, "🛡 لا يمكن تعديل مدير أو مشرف أو نفسك.", "🛡 Cannot modify an admin, a moderator or yourself."))
            return
        if v == "bq":
            self._confirm(chat_id, mid, lang, tr(lang, f"حظر {name}؟", f"Ban {name}?"),
                          ("🚫 " + tr(lang, "نعم، احظر", "Yes, ban"), f"adm:ban:{tid}"), back)
            return
        if v == "cq":
            if not self.is_admin(uid):
                return
            self._confirm(chat_id, mid, lang, tr(lang, "مسح كل رسائل هذا المستخدم؟", "Delete this user's chat history?"),
                          ("🧹 " + tr(lang, "نعم، امسح", "Yes, clear"), f"adm:cy:{tid}"), back)
            return
        if v == "ban":
            self._flag(user, tid, "ban", banned=1)
        elif v == "ub":
            self._flag(user, tid, "unban", banned=0)
        elif v == "al":
            self._flag(user, tid, "allow", allowed=1, expires_at=0)
        elif v == "da":
            self._flag(user, tid, "disallow", allowed=0, expires_at=0)
        elif v in ("ap", "ap7", "tmp") and target["banned"]:
            self.tg.send_message(chat_id, tr(lang, "🚫 هذا المستخدم محظور. فك الحظر أولاً.", "🚫 This user is banned. Unban first."))
            self.admin_user_card(chat_id, user, target, mid)
            return
        elif v in ("ap", "ap7"):
            days = 7 if v == "ap7" else 0
            if self._flag(user, tid, "approve" if not days else f"approve_{days}d", allowed=1, requested_at=0,
                          expires_at=int(time.time()) + days * 86400 if days else 0):
                self.notify_user_decision(tid, "approved", days)
                self._html_screen(chat_id, mid, f"✅ <b>{tr(lang, 'تمت الموافقة', 'Approved')}</b> — {name} (<code>{tid}</code>)"
                                  + (f" · {days}d" if days else ""), kb([[("👤 " + tr(lang, "البطاقة", "Card"), back)] + self._back_row(lang)]))
            return
        elif v == "rj":
            if self._flag(user, tid, "reject", requested_at=-int(time.time())):
                self.notify_user_decision(tid, "rejected")
                self._html_screen(chat_id, mid, f"❌ <b>{tr(lang, 'تم الرفض', 'Rejected')}</b> — {name} (<code>{tid}</code>)",
                                  kb([[("👤 " + tr(lang, "البطاقة", "Card"), back)] + self._back_row(lang)]))
            return
        elif v == "tmp":
            days = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0
            if days in TEMP_DAYS and self._flag(user, tid, f"temp_{days}d", allowed=1, requested_at=0,
                                                expires_at=int(time.time()) + days * 86400):
                self.notify_user_decision(tid, "approved", days)
        elif v == "lim" and self.is_admin(uid):
            choice = parts[3] if len(parts) > 3 else ""
            if choice not in dict(LIMITS):
                self._html_screen(chat_id, mid, f"📊 <b>{tr(lang, 'الحد اليومي لـ', 'Daily limit for')} {name}</b>",
                                  kb([[(lbl, f"adm:lim:{tid}:{k}") for k, lbl in LIMITS], [("🔙", back)]]))
                return
            self._flag(user, tid, f"limit_{choice}", limit_override=-1 if choice == "d" else int(choice))
        elif v == "mod" and self.is_admin(uid):
            self._flag(user, tid, "demote" if target.get("role") == "mod" else "promote",
                       role="" if target.get("role") == "mod" else "mod")
        elif v == "dm" and self.is_admin(uid):
            self.dm_target[uid] = tid
            self.ask(chat_id, user, "adm_dm")
            return
        elif v == "cy" and self.is_admin(uid):
            self.db.clear_history(tid)
            self.db.add_audit(uid, "clear_chat", str(tid))
        self.admin_user_card(chat_id, user, self.db.get_user(tid), mid)
