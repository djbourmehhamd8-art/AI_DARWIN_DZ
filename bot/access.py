"""Access control UX: a clear 'private bot' screen, access requests with one-tap staff approval, temporary access,
moderator role, and group support (authorised groups, "DZ <question>" trigger, welcome message)."""
from __future__ import annotations

import html
import re
import time

from .ui import kb, tr

REQ_COOLDOWN = 24 * 3600            # one access request per user per day
GROUP_NOTICE_EVERY = 3600           # "group not authorised" reply at most once an hour per group
STAFF_NOTIFY_EVERY = 6 * 3600       # and the staff ping at most once per 6 hours per group
GROUP_MEMBER_CMDS = frozenset({"help", "id", "start", "ask", "search", "groupusage"})
_SEP = r"[\s,:،؛;!؟?.\-–—]"


def _e(x) -> str:
    return html.escape(str(x if x is not None else ""), quote=False)


def _plain(h: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", h))


class AccessMixin:
    def _init_access(self) -> None:
        self._welcomed, self._group_notice, self._staff_pinged = {}, {}, {}
        self._trigger_cache = None
        self.bot_id = 0
        self.can_read_all = True

    # ================================================================== roles
    def is_mod(self, uid: int) -> bool:
        u = self.db.get_user(uid)
        return bool(u and u.get("role") == "mod" and not u.get("banned"))

    def is_staff(self, uid: int) -> bool:
        return self.is_admin(uid) or self.is_mod(uid)

    def staff_ids(self, admins_only: bool = False) -> list:
        ids = set(self.cfg.admin_ids)
        if not admins_only:
            ids.update(u["id"] for u in self.db.list_users(200, 0, "staff") if not u["banned"])
        return sorted(ids)

    def _lang_of(self, uid: int) -> str:
        u = self.db.get_user(uid)
        return (u or {}).get("lang") or self.cfg.default_lang

    def notify_staff(self, build, admins_only: bool = False) -> int:
        """`build(lang) -> (html, markup)`; sent to every staff member in their own language. Returns deliveries."""
        sent = 0
        for uid in self.staff_ids(admins_only):
            h, markup = build(self._lang_of(uid))
            if self.tg.send_rich(uid, h, _plain(h), markup):
                sent += 1
        return sent

    # ================================================================== access screen (users without permission)
    def access_text(self, user: dict) -> str:
        lang, uid, contact = user["lang"], user["id"], _e(self.cfg.contact)
        fresh = self.db.get_user(uid) or user
        if fresh.get("banned"):
            return tr(lang,
                      f"⛔ <b>حسابك مقيّد</b>\nتم تقييد وصولك إلى هذا البوت. للاستفسار راسل @{contact}.\n🆔 <code>{uid}</code>",
                      f"⛔ <b>Your account is restricted</b>\nYour access to this bot has been restricted. Contact @{contact} for details.\n🆔 <code>{uid}</code>")
        req = fresh.get("requested_at") or 0
        status = ""
        if req > 0 and time.time() - req < REQ_COOLDOWN:
            status = tr(lang, "\n⏳ <b>طلبك قيد المراجعة</b> — سيصلك إشعار هنا عند الموافقة.\n",
                        "\n⏳ <b>Your request is under review</b> — you will be notified here once it is approved.\n")
        elif req < 0:
            status = tr(lang, "\n❌ تم رفض طلبك السابق. يمكنك مراسلة المطوّر مباشرة.\n",
                        "\n❌ Your previous request was declined. You can message the developer directly.\n")
        return tr(
            lang,
            "🔒 <b>DARWIN DZ — بوت خاص</b>\n"
            "<blockquote>مساعد متخصص في <b>الأمن السيبراني</b>: تحليل التهديدات، الاستجابة للحوادث، أدوات دفاعية ومحتوى تقني متقدّم. "
            "الوصول إليه <b>بدعوة فقط</b>، وحسابك غير مفعّل بعد.</blockquote>\n"
            f"🆔 معرّفك: <code>{uid}</code>\n{status}\n"
            "<b>كيف تحصل على صلاحية؟</b>\n"
            "1️⃣ اضغط «🔑 طلب صلاحية» ليصل طلبك إلى المطوّر مباشرة.\n"
            f"2️⃣ أو راسل @{contact} وأرسل له معرّفك أعلاه.",
            "🔒 <b>DARWIN DZ — Private bot</b>\n"
            "<blockquote>A specialised <b>cybersecurity</b> assistant: threat analysis, incident response, defensive tools and advanced "
            "technical content. Access is <b>by invitation only</b> and your account is not activated yet.</blockquote>\n"
            f"🆔 Your ID: <code>{uid}</code>\n{status}\n"
            "<b>How to get access?</b>\n"
            "1️⃣ Tap “🔑 Request access” and your request goes straight to the developer.\n"
            f"2️⃣ Or message @{contact} and send them your ID above.")

    def access_kb(self, user: dict):
        lang, contact = user["lang"], self.cfg.contact
        fresh = self.db.get_user(user["id"]) or user
        rows = []
        if not fresh.get("banned"):
            pending = (fresh.get("requested_at") or 0) > 0 and time.time() - fresh["requested_at"] < REQ_COOLDOWN
            rows.append([("⏳ " + tr(lang, "تم إرسال الطلب", "Request sent") if pending
                          else "🔑 " + tr(lang, "طلب صلاحية", "Request access"), "req:go", None if pending else "success")])
        rows.append([("📩 " + tr(lang, f"راسل @{contact}", f"Message @{contact}"), f"https://t.me/{contact}")])
        rows.append([("🌐 " + tr(lang, "English", "العربية"), "req:lang")])
        return kb(rows)

    def show_access(self, chat_id, user: dict, mid=None) -> None:
        text = self.access_text(user)
        markup = self.access_kb(user)
        if mid and self.tg.edit_rich(chat_id, mid, text, _plain(text), markup):
            return
        self.tg.send_rich(chat_id, text, _plain(text), markup)

    def access_callback(self, data: str, chat_id, user: dict, mid) -> None:
        """req:* buttons — usable by people who do NOT have access yet."""
        if data == "req:lang":
            new = "en" if user["lang"] == "ar" else "ar"
            self.db.set_user(user["id"], lang=new)
            self.show_access(chat_id, self.db.get_user(user["id"]), mid)
        elif data == "req:go":
            self.request_access(chat_id, user, mid)

    # ================================================================== access requests
    def request_access(self, chat_id, user: dict, mid=None) -> None:
        lang, uid = user["lang"], user["id"]
        fresh = self.db.get_user(uid) or user
        if fresh.get("banned"):
            self.show_access(chat_id, fresh, mid)
            return
        if self.allowed(fresh):
            self.tg.send_message(chat_id, tr(lang, "✅ لديك صلاحية بالفعل. اضغط /start.", "✅ You already have access. Press /start."))
            return
        last = abs(fresh.get("requested_at") or 0)
        if last and time.time() - last < REQ_COOLDOWN:
            hours = max(1, int((REQ_COOLDOWN - (time.time() - last)) // 3600) + 1)
            self.tg.send_message(chat_id, tr(lang, f"⏳ أرسلت طلباً قبل قليل. يمكنك إعادة المحاولة بعد نحو {hours} ساعة، أو راسل @{self.cfg.contact}.",
                                             f"⏳ You already sent a request. You can retry in about {hours} h, or message @{self.cfg.contact}."))
            return
        if not self.staff_ids():
            self.tg.send_message(chat_id, tr(lang, f"تعذّر إرسال الطلب الآن. راسل @{self.cfg.contact} مباشرة.",
                                             f"The request could not be sent right now. Please message @{self.cfg.contact} directly."))
            return
        self.db.set_user(uid, requested_at=int(time.time()))
        self.db.add_audit(uid, "access_request", f"@{fresh.get('username') or '-'}")
        now = time.time()
        self._req_times = [t for t in getattr(self, "_req_times", []) if now - t < 3600]
        if len(self._req_times) >= 15:                          # request flood: recorded, but staff are not pinged again
            self.show_access(chat_id, self.db.get_user(uid), mid)
            self.tg.send_message(chat_id, tr(lang, "✅ سُجّل طلبك وسيُراجع قريباً.", "✅ Your request was recorded and will be reviewed soon."))
            return
        self._req_times.append(now)

        def build(slang):
            name = _e((fresh.get("first_name") or "").strip() or "-")
            h = (f"🔔 <b>{tr(slang, 'طلب صلاحية جديد', 'New access request')}</b>\n"
                 f"<blockquote>👤 {name} · @{_e(fresh.get('username') or '-')}\n🆔 <code>{uid}</code> · 🌐 {fresh['lang']}</blockquote>")
            markup = kb([[("✅ " + tr(slang, "موافقة", "Approve"), f"adm:ap:{uid}"), ("⏳ " + tr(slang, "7 أيام", "7 days"), f"adm:ap7:{uid}")],
                         [("❌ " + tr(slang, "رفض", "Reject"), f"adm:rj:{uid}"), ("🚫 " + tr(slang, "حظر", "Ban"), f"adm:bq:{uid}")],
                         [("👤 " + tr(slang, "البطاقة", "Card"), f"adm:u:{uid}")]])
            return h, markup
        delivered = self.notify_staff(build)
        self.show_access(chat_id, self.db.get_user(uid), mid)
        self.tg.send_message(chat_id, tr(lang, "✅ تم إرسال طلبك للمطوّر. ستصلك رسالة هنا عند الموافقة." if delivered else
                                         f"✅ سُجّل طلبك. لتسريعه راسل @{self.cfg.contact}.",
                                         "✅ Your request was sent to the developer. You will get a message here once approved." if delivered else
                                         f"✅ Your request was recorded. To speed it up, message @{self.cfg.contact}."))

    def notify_user_decision(self, uid: int, kind: str, days: int = 0) -> None:
        lang = self._lang_of(uid)
        if kind == "approved":
            until = tr(lang, f"\n⏳ مدة الصلاحية: {days} يوم.", f"\n⏳ Access lasts {days} day(s).") if days else ""
            text = tr(lang, f"✅ <b>تم تفعيل حسابك!</b>{until}\nاضغط /start أو الزر أدناه للبدء.",
                      f"✅ <b>Your account is now active!</b>{until}\nPress /start or the button below.")
            markup = kb([[("🏠 " + tr(lang, "ابدأ", "Start"), "m:main", "success")]])
        else:
            text = tr(lang, f"❌ <b>تعذّرت الموافقة على طلبك</b>\nيمكنك مراسلة @{self.cfg.contact} للاستفسار.",
                      f"❌ <b>Your request was not approved</b>\nYou can message @{self.cfg.contact} for details.")
            markup = None
        self.tg.send_rich(uid, text, _plain(text), markup)

    # ================================================================== groups
    def _trigger_rx(self):
        if self._trigger_cache is None:
            words = "|".join(re.escape(w) for w in sorted(self.cfg.group_triggers, key=len, reverse=True) if w)
            self._trigger_cache = re.compile(rf"^\s*(?:{words})(?=$|{_SEP})(?:{_SEP})*(.*)$", re.I | re.S) if words else False
        return self._trigger_cache

    def group_trigger(self, text: str):
        """'DZ كم عدد دول العالم؟' -> 'كم عدد دول العالم؟'; bare 'DZ' -> ''; no trigger -> None."""
        rx = self._trigger_rx()
        m = rx.match(text or "") if rx else None
        return None if not m else m.group(1).strip()

    def group_usage_text(self) -> str:
        me = f"@{self.bot_username}" if self.bot_username else "@bot"
        return (f"💬 <b>DARWIN DZ</b>\n<blockquote>اكتب <code>DZ</code> ثم سؤالك، مثال: <code>DZ كم عدد دول العالم؟</code>\n"
                f"أو اذكرني {_e(me)} أو ردّ على إحدى رسائلي.\n\n"
                f"Write <code>DZ</code> then your question, e.g. <code>DZ how many countries are there?</code>\n"
                f"Or mention {_e(me)} / reply to one of my messages.</blockquote>")

    def cmd_groupusage(self, chat_id, user, args) -> None:
        h = self.group_usage_text()
        self.tg.send_rich(chat_id, h, _plain(h))

    def group_authorised(self, chat_id: int) -> bool:
        if self.cfg.group_open:
            return True
        c = self.db.get_chat(chat_id)
        return bool(c and c["allowed"])

    def group_welcome(self, chat: dict, authorised: bool) -> str:
        text = self.group_usage_text()
        if not authorised:
            text += (f"\n\n🔒 <b>هذه المجموعة بانتظار موافقة المطوّر</b> @{_e(self.cfg.contact)}\n"
                     f"🔒 <b>This group is waiting for the developer's approval.</b>")
        if not self.can_read_all:
            text += ("\n\n⚠️ لقراءة رسائل «DZ …» اجعلني <b>مشرفاً</b> أو عطّل Privacy Mode من BotFather.\n"
                     "⚠️ To read “DZ …” messages, make me an <b>admin</b> or disable Privacy Mode in BotFather.")
        return text

    def group_joined(self, chat: dict, actor: dict | None) -> None:
        if not self.cfg.groups or chat.get("type") not in ("group", "supergroup"):
            return
        cid = chat["id"]
        now = time.time()
        if now - self._welcomed.get(cid, 0) < 60:                      # my_chat_member + service message both fire
            return
        self._welcomed[cid] = now
        row = self.db.upsert_chat(cid, chat.get("title") or "")
        by_staff = bool(actor and actor.get("id") and (self.is_staff(actor["id"]) or self.allowed(self._user(actor))))
        if by_staff and not row["allowed"] and actor and self.is_staff(actor["id"]):
            self.db.set_chat_allowed(cid, True)                         # a staff member added the bot: trust it
            self.db.add_audit(actor["id"], "group_auto_allow", str(cid))
        authorised = self.group_authorised(cid)
        h = self.group_welcome(chat, authorised)
        self.tg.send_rich(cid, h, _plain(h))
        if not authorised:
            self._ping_staff_group(row, actor)

    def _ping_staff_group(self, row: dict, actor: dict | None = None) -> None:
        cid = row["id"]
        if time.time() - self._staff_pinged.get(cid, 0) < STAFF_NOTIFY_EVERY:
            return
        self._staff_pinged[cid] = time.time()
        who = ""
        if actor:
            who = f"\n👤 {_e(actor.get('first_name') or '')} @{_e(actor.get('username') or '-')} · <code>{actor.get('id')}</code>"

        def build(slang):
            h = (f"👥 <b>{tr(slang, 'مجموعة جديدة تطلب التفعيل', 'A group is asking for activation')}</b>\n"
                 f"<blockquote>{_e(row['title'] or '-')}\n🆔 <code>{cid}</code>{who}</blockquote>")
            return h, kb([[("✅ " + tr(slang, "تفعيل المجموعة", "Authorize group"), f"adm:gok:{cid}"),
                           ("🚪 " + tr(slang, "مغادرة", "Leave"), f"adm:glv:{cid}")]])
        self.notify_staff(build, admins_only=True)

    def on_my_chat_member(self, ev: dict) -> None:
        chat = ev.get("chat") or {}
        if chat.get("type") not in ("group", "supergroup"):
            return
        new = (ev.get("new_chat_member") or {}).get("status")
        old = (ev.get("old_chat_member") or {}).get("status")
        if new in ("member", "administrator") and old in (None, "left", "kicked"):
            self.group_joined(chat, ev.get("from"))
        elif new in ("left", "kicked"):
            self.db.delete_chat(chat["id"])

    def group_member_ok(self, chat_id: int, msg: dict, user: dict) -> bool:
        """True when this group message should be served: the group is authorised, or the sender has personal access."""
        row = self.db.upsert_chat(chat_id, (msg.get("chat") or {}).get("title") or "")
        if user.get("banned") and not self.is_admin(user["id"]):
            return False
        if row["allowed"] or self.cfg.group_open:
            return True
        if self.allowed(user):
            return True
        now = time.time()
        if now - self._group_notice.get(chat_id, 0) >= GROUP_NOTICE_EVERY:
            self._group_notice[chat_id] = now
            t = (f"🔒 هذه المجموعة غير مفعّلة بعد. تم إبلاغ المطوّر @{_e(self.cfg.contact)}.\n"
                 f"🔒 This group is not activated yet. The developer @{_e(self.cfg.contact)} has been notified.")
            self.tg.send_message(chat_id, t, reply_to=msg.get("message_id"))
            self._ping_staff_group(row)
        return False

    def group_admin_command(self, chat_id: int, msg: dict, uid: int, cmd: str) -> None:
        """/allowgroup and /revokegroup, typed by an admin inside the group."""
        if not self.is_admin(uid):
            return
        title = (msg.get("chat") or {}).get("title") or ""
        self.db.upsert_chat(chat_id, title)
        on = cmd == "allowgroup"
        self.db.set_chat_allowed(chat_id, on)
        self.db.add_audit(uid, cmd, str(chat_id))
        self.tg.send_message(chat_id, "✅ تم تفعيل المجموعة. اكتب DZ ثم سؤالك.\n✅ Group activated. Write DZ then your question." if on
                             else "⛔ تم إيقاف المجموعة.\n⛔ Group deactivated.", reply_to=msg.get("message_id"))
