"""Web panel control pages: groups, global settings (maintenance, default limits), broadcast, DB backup, user roles (mixin for WebPanel).

Same security model as the rest of the panel: token login, CSRF on every POST, no JavaScript, every value escaped, and every
change goes through the same fields/helpers as the Telegram admin panel and is written to the audit trail (actor 0 = web).
Destructive actions (leave group, clear history, broadcast) need an explicit confirmation checkbox.
"""
from __future__ import annotations

import html
import logging
import threading
import time

from .utils import fmt_duration

log = logging.getLogger("bot.web")

GROUP_PAGE = 20
BROADCAST_MAX = 3500
LIMIT_OPTS = (("d", "الافتراضي (من .env)"), ("10", "10"), ("25", "25"), ("50", "50"), ("100", "100"),
              ("200", "200"), ("500", "500"), ("0", "∞ بلا حد"))


def _e(x) -> str:
    return html.escape(str(x if x is not None else ""), quote=True)


def _ts(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "-"


def _lim(n) -> str:
    return "∞" if not n else str(n)


def _num(v, default=0, lo=-(10 ** 15), hi=10 ** 15) -> int:
    try:
        return max(lo, min(int(v), hi))
    except (TypeError, ValueError):
        return default


class WebCtlMixin:
    _bc_lock = threading.Lock()
    _bc_running = False

    # ================================================================== groups
    def groups_page(self, sess: dict, params: dict) -> bytes:
        csrf = sess["csrf"]
        total = self.db.count_chats()
        pages = max(1, -(-total // GROUP_PAGE))
        page = _num(params.get("p"), 1, 1, pages)
        rows = self.db.list_chats(GROUP_PAGE, (page - 1) * GROUP_PAGE)
        default = self.app.default_group_limit()
        opts = "".join(f'<option value="{k}">{_e(t)}</option>' for k, t in LIMIT_OPTS)
        trs = []
        for c in rows:
            own = c["daily_limit"] if c["daily_limit"] is not None and c["daily_limit"] >= 0 else None
            lim = own if own is not None else default
            used = self.db.daily_count(c["id"])
            over = ' class="bad"' if lim and used >= lim else ""
            st = '<span class="b ok">مفعّلة</span>' if c["allowed"] else '<span class="b warn">بانتظار التفعيل</span>'
            toggle = (f'<button name="act" value="revoke">⛔ إيقاف</button>' if c["allowed"] else '<button name="act" value="allow">✅ تفعيل</button>')
            acts = (f'<form method="post" action="/groups/act">{self._hidden(csrf, cid=c["id"], p=page)}{toggle}'
                    f'<select name="value">{opts}</select><button name="act" value="limit">📊 حد</button>'
                    f'<label class="mut"><input type="checkbox" name="confirm" value="1"> تأكيد</label>'
                    f'<button name="act" value="leave">🚪 مغادرة</button></form>')
            trs.append(f'<tr><td><code>{c["id"]}</code></td><td>{_e((c["title"] or "-")[:40])}</td><td>{st}</td>'
                       f'<td{over}>{used} / {_lim(lim)}{"" if own is not None else " <span class=mut>(افتراضي)</span>"}</td>'
                       f'<td>{_e(_ts(c["last_seen"]))}</td><td class="act">{acts}</td></tr>')
        table = ('<div class="wrap"><table style="min-width:820px"><thead><tr><th>المعرّف</th><th>الاسم</th><th>الحالة</th><th>اليوم / الحد</th>'
                 '<th>آخر نشاط</th><th>إجراءات</th></tr></thead><tbody>'
                 + ("".join(trs) or '<tr><td colspan="6" class="mut">لا توجد مجموعات بعد. أضف البوت إلى مجموعة.</td></tr>') + '</tbody></table></div>')
        note = ('<p class="mut">🌍 وضع GROUP_OPEN مفعّل: المجموعات تعمل دون تفعيل.</p>' if self.cfg.group_open
                else '<p class="mut">كل مجموعة تحتاج تفعيلاً من المدير قبل أن يجيب البوت فيها.</p>')
        return self.page(f'{self.nav("groups", csrf)}<main>{self._flash(sess)}<h2>👥 المجموعات</h2>{note}{table}'
                         f'{self._pager("/groups", {}, page, pages, total, "مجموعة")}</main>', "المجموعات")

    def groups_act(self, form: dict) -> str:
        cid = _num(form.get("cid"), 0)
        act = form.get("act", "")
        row = self.db.get_chat(cid) if cid else None
        if not row:
            return "🔍 المجموعة غير موجودة."
        name = row["title"] or cid
        if act == "allow":
            self.db.set_chat_allowed(cid, True)
            self.db.add_audit(0, "web_group_allow", str(cid))
            try:
                self.app.tg.send_message(cid, "✅ تم تفعيل المجموعة. اكتب DZ ثم سؤالك.\n✅ Group activated. Write DZ then your question.")
            except Exception:
                log.warning("could not notify group %s", cid, exc_info=True)
            return f"✅ فُعّلت المجموعة {name}"
        if act == "revoke":
            self.db.set_chat_allowed(cid, False)
            self.db.add_audit(0, "web_group_revoke", str(cid))
            return f"⛔ أُوقفت المجموعة {name}"
        if act == "limit":
            v = form.get("value", "")
            if v not in dict(LIMIT_OPTS):
                return "قيمة الحد غير صالحة."
            self.db.set_chat_limit(cid, -1 if v == "d" else int(v))
            self.db.add_audit(0, "web_group_limit", f"{cid}:{v}")
            return f"📊 حد {name}: " + ("الافتراضي" if v == "d" else _lim(int(v)))
        if act == "leave":
            if form.get("confirm") != "1":
                return "☑️ فعّل «تأكيد» أولاً قبل المغادرة."
            try:
                self.app.tg.leave_chat(cid)
            except Exception:
                log.warning("leave_chat failed for %s", cid, exc_info=True)
            self.db.delete_chat(cid)
            self.db.add_audit(0, "web_group_leave", str(cid))
            return f"🚪 غادر البوت المجموعة {name}"
        return "إجراء غير معروف."

    # ================================================================== settings / broadcast / backup
    def settings_page(self, sess: dict) -> bytes:
        csrf = sess["csrf"]
        mnt = bool(self.app.maintenance)
        ul, gl = self.db.get_setting("limit_user", ""), self.db.get_setting("limit_group", "")

        def select(name, cur):
            cur = cur if cur in dict(LIMIT_OPTS) else "d"
            return f'<select name="{name}">' + "".join(f'<option value="{k}"{" selected" if k == cur else ""}>{_e(t)}</option>' for k, t in LIMIT_OPTS) + "</select>"
        status = (f'<span class="b {"warn" if mnt else "ok"}">{"🛠 الصيانة تعمل: المدراء فقط يُخدَمون" if mnt else "🟢 الخدمة طبيعية"}</span>')
        mnt_form = (f'<form method="post" action="/settings/save" class="row">{self._hidden(csrf, what="maintenance")}'
                    f'<button class="{"p" if not mnt else ""}" name="value" value="{"0" if mnt else "1"}">{"إيقاف وضع الصيانة" if mnt else "🛠 تفعيل وضع الصيانة"}</button></form>')
        lim_form = (f'<form method="post" action="/settings/save">{self._hidden(csrf, what="limits")}'
                    f'<p class="row"><label>👤 حد كل مستخدم يومياً</label>{select("user", ul)}</p>'
                    f'<p class="row"><label>👥 حد كل مجموعة يومياً</label>{select("group", gl)}</p>'
                    f'<button class="p">حفظ الحدود</button> <span class="mut">يمكن تخصيص حد لمستخدم أو مجموعة من بطاقته.</span></form>')
        n = sum(1 for r in self.db.broadcast_users() if self.app.allowed(r))
        bc = (f'<form method="post" action="/settings/broadcast">{self._hidden(csrf)}'
              f'<textarea name="text" maxlength="{BROADCAST_MAX}" placeholder="نص الرسالة التي ستصل لكل المستخدمين المفعّلين…" required></textarea>'
              f'<div class="row"><button class="p">📣 إرسال إلى {n} مستخدم</button>'
              f'<label class="mut"><input type="checkbox" name="confirm" value="1"> أؤكد الإرسال</label></div></form>')
        info = (f'<table style="min-width:0"><tbody><tr><td>حجم قاعدة البيانات</td><td>{self.db.db_size() / 1048576:.1f} MB</td></tr>'
                f'<tr><td>مدة التشغيل</td><td>{_e(fmt_duration(time.time() - self.app.started))}</td></tr>'
                f'<tr><td>فحص السلامة</td><td>{_e(self.db.integrity_check())}</td></tr></tbody></table>')
        backup = (f'<form method="post" action="/settings/backup">{self._hidden(csrf)}<button>💾 تنزيل نسخة احتياطية من قاعدة البيانات</button></form>'
                  '<p class="mut">تحتوي النسخة على محادثات المستخدمين: احفظها في مكان آمن.</p>')
        body = (f'{self.nav("settings", csrf)}<main>{self._flash(sess)}<h2>⚙️ الإعدادات والتحكم</h2>'
                f'<div class="grid2"><section class="card"><h3>🛠 وضع الصيانة</h3><p>{status}</p>{mnt_form}</section>'
                f'<section class="card"><h3>📊 الحدود اليومية الافتراضية</h3>{lim_form}</section></div>'
                f'<section class="card"><h3>📣 بث رسالة</h3>{bc}<p class="mut">تصل للمستخدمين المفعّلين غير المحظورين فقط. يجري الإرسال في الخلفية ويُسجَّل الناتج في السجل.</p></section>'
                f'<div class="grid2"><section class="card"><h3>🗄 قاعدة البيانات</h3>{info}{backup}</section></div></main>')
        return self.page(body, "الإعدادات")

    def settings_save(self, form: dict) -> str:
        what = form.get("what", "")
        if what == "maintenance":
            on = form.get("value") == "1"
            self.app.maintenance = on
            self.db.set_setting("maintenance", "1" if on else "0")
            self.db.add_audit(0, "web_maintenance", "on" if on else "off")
            return "🛠 فُعّل وضع الصيانة." if on else "🟢 أُوقف وضع الصيانة."
        if what == "limits":
            for key, field in (("limit_user", "user"), ("limit_group", "group")):
                v = form.get(field, "d")
                if v not in dict(LIMIT_OPTS):
                    return "قيمة الحد غير صالحة."
            for key, field in (("limit_user", "user"), ("limit_group", "group")):
                v = form.get(field, "d")
                self.db.set_setting(key, "" if v == "d" else v)
                self.db.add_audit(0, "web_default_" + key, v)
            return "📊 حُفظت الحدود الافتراضية."
        return "إجراء غير معروف."

    def broadcast_start(self, form: dict) -> str:
        text = (form.get("text") or "").strip()[:BROADCAST_MAX]
        if not text:
            return "✍️ اكتب الرسالة أولاً."
        if form.get("confirm") != "1":
            return "☑️ فعّل «أؤكد الإرسال» أولاً."
        with self._bc_lock:
            if WebCtlMixin._bc_running:
                return "⏳ هناك بث جارٍ حالياً، انتظر انتهاءه."
            WebCtlMixin._bc_running = True
        rows = [r for r in self.db.broadcast_users() if self.app.allowed(r)]
        self.db.add_audit(0, "web_broadcast", f"{len(rows)} users:{text[:40]}")
        body = "📣 <b>إعلان من الإدارة</b>\n\n" + html.escape(text, quote=False)

        def run():
            ok = fail = 0
            try:
                for r in rows:
                    try:
                        good = bool(self.app.tg.send_message(r["id"], body))
                    except Exception:
                        good = False
                    ok, fail = ok + good, fail + (not good)
                    time.sleep(0.06)
            finally:
                WebCtlMixin._bc_running = False
                self.db.add_audit(0, "web_broadcast_done", f"ok={ok} fail={fail}")
        try:
            threading.Thread(target=run, name="web-broadcast", daemon=True).start()
        except RuntimeError:                               # could not start a thread: release the lock
            WebCtlMixin._bc_running = False
            return "⚠️ تعذّر بدء الإرسال."
        return f"📣 بدأ الإرسال إلى {len(rows)} مستخدم. النتيجة في السجل (web_broadcast_done)."

    def backup_file(self) -> tuple:
        self.db.add_audit(0, "web_backup")
        return time.strftime("darwin-%Y%m%d-%H%M.db"), self.db.backup_bytes()

    # ================================================================== recent warnings / errors
    def logs_page(self, sess: dict, params: dict) -> bytes:
        from .ringlog import RING, fmt_time
        lvl = params.get("l", "WARNING")
        lvl = lvl if lvl in ("WARNING", "ERROR") else "WARNING"
        q = (params.get("q") or "")[:64]
        rows = RING.records(lvl, q)
        trs = "".join(f'<tr><td class="mut">{_e(fmt_time(t))}</td><td><span class="b {"bad" if lv in ("ERROR", "CRITICAL") else "warn"}">{_e(lv)}</span></td>'
                      f'<td class="mut">{_e(name)}</td><td style="white-space:normal;word-break:break-word">{_e(msg)}</td></tr>' for t, lv, name, msg in rows)
        opts = "".join(f'<option value="{k}"{" selected" if k == lvl else ""}>{t}</option>' for k, t in (("WARNING", "تحذيرات وأخطاء"), ("ERROR", "أخطاء فقط")))
        bar = (f'<form class="bar" method="get" action="/logs"><input type="search" name="q" value="{_e(q)}" placeholder="بحث في الرسائل">'
               f'<select name="l">{opts}</select><button class="p">تصفية</button></form>')
        table = ('<div class="wrap"><table style="min-width:640px"><thead><tr><th>الوقت</th><th>المستوى</th><th>المصدر</th><th>الرسالة</th></tr></thead><tbody>'
                 + (trs or '<tr><td colspan="4" class="empty">✅ لا توجد تحذيرات أو أخطاء حديثة منذ آخر تشغيل.</td></tr>') + "</tbody></table></div>")
        return self.page(f'{self.nav("logs", sess["csrf"])}<main>{self._flash(sess)}<h2>📜 السجلات الحديثة</h2>'
                         f'<p class="mut">آخر التحذيرات والأخطاء في الذاكرة فقط (تُصفَّر عند إعادة التشغيل) مع إخفاء المفاتيح والتوكنات.</p>{bar}{table}</main>', "السجلات")

    # ================================================================== bulk user actions
    BULK_ACTS = ("ap", "rj", "ban", "ub", "da")
    BULK_CAP = 500

    def bulk_act(self, form: dict) -> str:
        act = form.get("act", "")
        if act not in self.BULK_ACTS:
            return "إجراء غير معروف."
        if form.get("confirm") != "1":
            return "☑️ فعّل «أؤكد» لتنفيذ الإجراء الجماعي."
        if form.get("scope") == "all":
            from urllib.parse import parse_qs
            back = {k: v[0] for k, v in parse_qs(form.get("back", ""), max_num_fields=10).items()}
            flt, sort, desc, q, _ = self.query(back)
            if not flt and not q:
                return "⚠️ اختر فلتراً أو ابحث أولاً: لا يُطبَّق إجراء جماعي على كل المستخدمين دفعة واحدة."
            rows, _t = self.db.search_users(flt, q, sort, desc, self.BULK_CAP, 0)
            ids = [u["id"] for u in rows]
        else:
            ids = []
            for x in (form.get("ids") or "").split(","):
                if x.strip().isdigit():
                    ids.append(int(x))
            ids = list(dict.fromkeys(ids))
        if not ids:
            return "✍️ حدّد مستخدماً واحداً على الأقل أو اختر «كل النتائج»."
        ids = ids[:self.BULK_CAP]
        ok = skipped = 0
        for tid in ids:
            done, _msg = self.apply(act, tid)
            ok, skipped = ok + done, skipped + (not done)
        self.db.add_audit(0, "web_bulk_" + act, f"ok={ok} skip={skipped}")
        return f"✅ نُفّذ على {ok} مستخدم" + (f" وتُخطّي {skipped} (محمي/محظور/غير موجود)" if skipped else "")

    # ================================================================== user roles / history
    def user_ctl_card(self, csrf: str, u: dict) -> str:
        uid = u["id"]
        if uid in self.cfg.admin_ids:
            return ""
        is_mod = u.get("role") == "mod"
        return (f'<section class="card"><h3>🛡 صلاحيات متقدمة</h3><form method="post" action="/user/ctl" class="row" style="flex-wrap:wrap">'
                f'{self._hidden(csrf, uid=uid)}<button name="act" value="{"demote" if is_mod else "promote"}">'
                f'{"⬇️ سحب صفة المشرف" if is_mod else "⬆️ ترقية إلى مشرف"}</button>'
                f'<label class="mut"><input type="checkbox" name="confirm" value="1"> تأكيد</label>'
                f'<button name="act" value="clear">🧹 مسح محادثات المستخدم</button></form></section>')

    def user_ctl(self, form: dict) -> str:
        uid = _num(form.get("uid"), 0, 1)
        act = form.get("act", "")
        u = self.db.get_user(uid) if uid else None
        if not u:
            return "🔍 المستخدم غير موجود."
        if uid in self.cfg.admin_ids:
            return "🛡 لا يمكن تعديل مدير."
        if act == "promote":
            if u["banned"]:
                return "🚫 لا تُرقّى مستخدماً محظوراً."
            self.db.set_user(uid, role="mod")
            self.db.add_audit(0, "web_promote", str(uid))
            return "⬆️ رُقّي المستخدم إلى مشرف."
        if act == "demote":
            self.db.set_user(uid, role="")
            self.db.add_audit(0, "web_demote", str(uid))
            return "⬇️ سُحبت صفة المشرف."
        if act == "clear":
            if form.get("confirm") != "1":
                return "☑️ فعّل «تأكيد» أولاً."
            self.db.clear_history(uid)
            self.db.add_audit(0, "web_clear_chat", str(uid))
            return "🧹 مُسحت محادثات المستخدم."
        return "إجراء غير معروف."
