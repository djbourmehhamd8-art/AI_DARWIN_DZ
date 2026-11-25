"""Admin web panel pages: overview dashboard, reports inbox, user detail, searchable audit log (mixin for WebPanel).

Same security model as the rest of the panel: token login, CSRF on every POST, no JavaScript, every value escaped, charts are
plain HTML/CSS (the panel's CSP forbids scripts and images). Actions go through the same code paths as Telegram:
report replies use `app.report_resolve`, user decisions use `WebPanel.apply`.
"""
from __future__ import annotations

import csv
import html
import io
import re
import time
from urllib.parse import urlencode

from . import __version__
from .admin_panel import _cell
from .reports import KIND_LABEL, KINDS

PAGE = 20
AUDIT_PAGE = 50


def _e(x) -> str:
    return html.escape(str(x if x is not None else ""), quote=True)


def _ts(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "-"


def _int(v, default=0, lo=0, hi=10 ** 9) -> int:
    try:
        return max(lo, min(int(v), hi))
    except (TypeError, ValueError):
        return default


def bar_chart(series: list, unit: str = "") -> str:
    """Pure-CSS bar chart. `series` = [(label, value, ...)] oldest first."""
    mx = max([s[1] for s in series] + [1])
    bars = "".join(
        f'<div class="bc" title="{_e(s[0])}: {s[1]}{_e(unit)}"><em>{s[1] or ""}</em><i style="height:{max(2, round(s[1] * 100 / mx)) if s[1] else 1}%"></i>'
        f'<s>{_e(str(s[0])[8:])}</s></div>' for s in series)
    return f'<div class="chart" dir="ltr">{bars}</div>'


def safe_ret(ret: str) -> str:
    """Only panel-internal return targets are honoured after an action (no open redirect)."""
    ret = (ret or "").strip()
    if ret in ("/overview", "/reports") or re.fullmatch(r"/user\?id=\d{1,15}", ret) or re.fullmatch(r"/reports\?[A-Za-z0-9_=&%.-]{0,200}", ret):
        return ret
    return ""


class WebAdminMixin:
    # ================================================================== helpers
    def _hidden(self, csrf: str, **kw) -> str:
        return f'<input type="hidden" name="csrf" value="{_e(csrf)}">' + "".join(f'<input type="hidden" name="{_e(k)}" value="{_e(v)}">' for k, v in kw.items())

    def _user_link(self, uid, name="") -> str:
        label = _e(str(name)[:30]) if name else f"<code>{_e(uid)}</code>"
        return f'<a href="/user?id={_e(uid)}">{label}</a>'

    def _pager(self, path: str, base: dict, page: int, pages: int, total: int, noun: str) -> str:
        link = lambda p: path + "?" + urlencode({**{k: v for k, v in base.items() if v not in ("", None)}, **({"p": p} if p > 1 else {})})   # noqa: E731
        return ('<div class="pager">' + (f'<a href="{_e(link(1))}">« الأولى</a><a href="{_e(link(page - 1))}">→ السابق</a>' if page > 1 else "")
                + f'<span>صفحة {page} من {pages} · {total} {_e(noun)}</span>' + (f'<a href="{_e(link(page + 1))}">التالي ←</a><a href="{_e(link(pages))}">الأخيرة »</a>' if page < pages else "") + "</div>")

    def _status_chip(self, u: dict) -> str:
        st, cls = self.status_of(u)
        return f'<span class="b {cls}">{_e(st)}</span>'

    # ================================================================== overview
    def overview_page(self, sess: dict) -> bytes:
        csrf, db = sess["csrf"], self.db
        counts, nums, rc = db.web_counts(), db.overview_numbers(), db.report_counts()
        msgs, signups = db.messages_series(14), db.signups_series(14)
        keys = self.app.ai.pool.status()
        from .utils import fmt_duration
        st_code, _ = getattr(self.app, "tg_state", ("ok", ""))
        tg = {"ok": ("🟢 متصل", "ok"), "starting": ("🟡 يبدأ", "warn")}.get(st_code, ("🔴 مشكلة", "bad"))
        ok_keys = sum(1 for k in keys if k["ok"])

        def card(n, t, href="", cls=""):
            inner = f'<b>{_e(n)}</b><span>{_e(t)}</span>' + (delta if t == "رسائل اليوم" else "")
            return f'<a class="stat {cls}" href="{href}">{inner}</a>' if href else f'<div class="stat {cls}">{inner}</div>'
        today_n, yday_n = (msgs[-1][1], msgs[-2][1]) if len(msgs) >= 2 else (0, 0)
        avg7 = sum(m[1] for m in msgs[-8:-1]) / 7 if len(msgs) >= 8 else 0
        delta = ("" if not yday_n else f'<em class="{"up" if today_n >= yday_n else "down"}">{"▲" if today_n >= yday_n else "▼"} {abs(today_n - yday_n) * 100 // yday_n}% عن أمس</em>')
        cards = "".join((
            card(counts["all"], "المستخدمون", "/"), card(counts["pending"], "طلبات معلّقة", "/?f=pending", "warn" if counts["pending"] else ""),
            card(rc["open"], "بلاغات مفتوحة", "/reports", "bad" if rc["open"] else ""), card(nums["active24"], "نشطون (24س)"),
            card(nums["active7"], "نشطون (7 أيام)"), card(counts["today_msgs"], "رسائل اليوم"), card(f"{avg7:.0f}", "متوسط الرسائل اليومي (7 أيام)"), card(nums["msgs_total"], "إجمالي الرسائل"),
            card(f'{(nums["tokens_in"] + nums["tokens_out"]) / 1000:.0f}K', "توكنات مستهلكة"), card(counts["banned"], "محظورون", "/?f=banned"),
            card(nums["new7"], "انضموا هذا الأسبوع"), card(nums["groups"], "مجموعات"),
        ))
        health = (f'<table style="min-width:0"><tbody><tr><td>تيليجرام</td><td><span class="b {tg[1]}">{tg[0]}</span></td></tr>'
                  f'<tr><td>مفاتيح API المتاحة</td><td><span class="b {"ok" if keys and ok_keys == len(keys) else "warn" if ok_keys else "bad"}">{ok_keys}/{len(keys)}</span></td></tr>'
                  f'<tr><td>مدة التشغيل</td><td>{_e(fmt_duration(time.time() - self.app.started))}</td></tr>'
                  f'<tr><td>حجم قاعدة البيانات</td><td>{db.db_size() / 1048576:.1f} MB</td></tr>'
                  f'<tr><td>الإصدار</td><td>{_e(__version__)}</td></tr><tr><td>الوضع</td><td>{"مفتوح PUBLIC" if self.cfg.public else "خاص"}'
                  f'{" · 🛠 صيانة" if self.app.maintenance else ""}</td></tr></tbody></table>')

        pend, _ = db.search_users("pending", "", "last_seen", True, 5, 0)
        pend_rows = "".join(
            f'<tr><td>{self._user_link(u["id"], u.get("first_name") or u.get("username") or u["id"])}</td><td class="act">'
            f'<form method="post" action="/act">{self._hidden(csrf, uid=u["id"], ret="/overview")}<button name="act" value="ap">✅</button><button name="act" value="rj">❌</button></form></td></tr>'
            for u in pend)
        pend_html = (f'<table style="min-width:0"><tbody>{pend_rows}</tbody></table>' if pend_rows else '<p class="mut">لا توجد طلبات معلّقة 🎉</p>')
        top, _ = db.search_users("", "", "today", True, 5, 0)
        top_rows = "".join(f'<tr><td>{self._user_link(u["id"], u.get("first_name") or u.get("username") or u["id"])}</td><td>{u["today"]}</td></tr>' for u in top if u["today"])
        top_html = f'<table style="min-width:0"><tbody>{top_rows}</tbody></table>' if top_rows else '<p class="mut">لا نشاط اليوم بعد.</p>'
        reps, _ = db.list_reports("open", limit=5)
        rep_rows = "".join(f'<tr><td><a href="/reports?f=open#r{r["id"]}">#{r["id"]}</a></td><td>{KIND_LABEL.get(r["kind"], KIND_LABEL["other"])[0]}</td>'
                           f'<td class="mut">{_e(r["text"][:70])}</td></tr>' for r in reps)
        rep_html = f'<table style="min-width:0"><tbody>{rep_rows}</tbody></table>' if rep_rows else '<p class="mut">لا توجد بلاغات مفتوحة 🎉</p>'
        aud = "".join(f'<tr><td class="mut">{_e(time.strftime("%m-%d %H:%M", time.localtime(a["ts"])))}</td><td>{_e(a["action"])}</td><td class="mut">{_e((a["detail"] or "")[:40])}</td></tr>'
                      for a in db.list_audit(8))
        body = (f'{self.nav("overview", csrf)}<main>{self._flash(sess)}<h2>📊 نظرة عامة</h2><div class="stats">{cards}</div>'
                f'<div class="grid2"><section class="card"><h3>💬 الرسائل (آخر 14 يوماً)</h3>{bar_chart(msgs)}</section>'
                f'<section class="card"><h3>🆕 الانضمام (آخر 14 يوماً)</h3>{bar_chart(signups)}</section></div>'
                f'<div class="grid2"><section class="card"><h3>🔔 طلبات معلّقة</h3>{pend_html}<p><a href="/?f=pending">كل الطلبات ←</a></p></section>'
                f'<section class="card"><h3>📨 بلاغات مفتوحة</h3>{rep_html}<p><a href="/reports">صندوق البلاغات ←</a></p></section></div>'
                f'<div class="grid2"><section class="card"><h3>🏆 الأكثر نشاطاً اليوم</h3>{top_html}</section>'
                f'<section class="card"><h3>🩺 الحالة</h3>{health}<p><a href="/system">تفاصيل النظام ←</a></p></section></div>'
                f'<section class="card"><h3>🧾 آخر الأحداث</h3><table style="min-width:0"><tbody>{aud or "<tr><td class=mut>لا شيء</td></tr>"}</tbody></table><p><a href="/audit">السجل الكامل ←</a></p></section>'
                f'</main>')
        return self.page(body, "نظرة عامة")

    # ================================================================== reports inbox
    def reports_query(self, params: dict):
        f = params.get("f", "open")
        f = f if f in ("open", "closed", "all") else "open"
        k = params.get("k", "")
        k = k if k in KIND_LABEL else ""
        q = (params.get("q") or "")[:64]
        return f, k, q, _int(params.get("p"), 1, 1, 100000)

    def reports_page(self, sess: dict, params: dict) -> bytes:
        csrf = sess["csrf"]
        f, k, q, page = self.reports_query(params)
        status = "" if f == "all" else f
        rows, total = self.db.list_reports(status, k, q, PAGE, (page - 1) * PAGE)
        pages = max(1, -(-total // PAGE))
        if page > pages:
            page = pages
            rows, total = self.db.list_reports(status, k, q, PAGE, (page - 1) * PAGE)
        rc = self.db.report_counts()
        base = {"f": f, "k": k, "q": q}
        back = urlencode({**{a: b for a, b in base.items() if b}, **({"p": page} if page > 1 else {})})
        tabs = "".join(f'<a class="{"on" if f == key else ""}" href="/reports?{_e(urlencode({"f": key, "k": k, "q": q}))}">{_e(t)} ({rc[key]})</a>'
                       for key, t in (("open", "🟡 مفتوحة"), ("closed", "✅ مغلقة"), ("all", "الكل")))
        kind_opts = '<option value="">كل الأنواع</option>' + "".join(f'<option value="{kk}"{" selected" if kk == k else ""}>{ic} {_e(ar)}</option>' for kk, ic, ar, _en in KINDS)
        bar = (f'<form class="bar" method="get" action="/reports"><input type="hidden" name="f" value="{_e(f)}"><input type="search" name="q" value="{_e(q)}" '
               f'placeholder="بحث في النص أو المستخدم"><select name="k">{kind_opts}</select><button class="p">بحث</button>'
               f'<a href="/reports.csv?{_e(urlencode({"f": f, "k": k, "q": q}))}"><button type="button">⬇️ CSV</button></a></form>')
        cards = []
        for r in rows:
            ic, ar, _en = KIND_LABEL.get(r["kind"], KIND_LABEL["other"])
            name = r.get("first_name") or r.get("username") or r["user_id"]
            st = '<span class="b ok">مغلق</span>' if r["status"] == "closed" else '<span class="b warn">مفتوح</span>'
            reply = f'<div class="reply">💬 {_e(r["reply"])}</div>' if r["reply"] else ""
            toggle = ('<button name="act" value="open">♻️ إعادة فتح</button>' if r["status"] == "closed" else '<button name="act" value="close">✅ إغلاق</button>')
            cards.append(
                f'<details class="rep" id="r{r["id"]}"{" open" if r["status"] == "open" and len(rows) <= 3 else ""}><summary><b>#{r["id"]}</b> {ic} {_e(ar)} {st} · '
                f'{_e(str(name)[:30])} · <span class="mut">{_e(_ts(r["created_at"]))}</span> — <span class="mut">{_e(r["text"][:80])}</span></summary>'
                f'<div class="repbody"><p class="txt">{_e(r["text"])}</p><p class="mut">{self._user_link(r["user_id"], "👤 " + str(name)[:30])} · <code>{_e(r["ctx"])}</code></p>{reply}'
                f'<form method="post" action="/reports/act">{self._hidden(csrf, rid=r["id"], back=back)}'
                f'<textarea name="reply" maxlength="1500" placeholder="اكتب رداً يصل للمستخدم في تيليجرام…"></textarea>'
                f'<div class="row"><button class="p" name="act" value="reply_close">💬 رد وإغلاق</button><button name="act" value="reply">💬 رد فقط</button>{toggle}'
                f'<label class="mut"><input type="checkbox" name="confirm" value="1"> تأكيد الحذف</label><button name="act" value="delete">🗑 حذف</button></div></form></div></details>')
        empty = '<p class="mut">لا توجد بلاغات مطابقة 🎉</p>' if not cards else ""
        pager = self._pager("/reports", base, page, pages, total, "بلاغ")
        return self.page(f'{self.nav("reports", csrf)}<main>{self._flash(sess)}<h2>📨 صندوق البلاغات</h2><div class="tabs">{tabs}</div>{bar}{empty}{"".join(cards)}{pager}</main>', "البلاغات")

    def reports_act(self, form: dict) -> str:
        rid = _int(form.get("rid"), 0, 0, 10 ** 12)
        act = form.get("act", "")
        r = self.db.get_report(rid)
        if not r:
            return "🔍 البلاغ غير موجود."
        if act in ("reply", "reply_close"):
            text = (form.get("reply") or "").strip()
            if not text:
                return "✍️ اكتب نص الرد أولاً."
            return self.app.report_resolve(rid, text, act == "reply_close", 0)[1]
        if act in ("close", "open"):
            self.db.set_report(rid, status="closed" if act == "close" else "open")
            self.db.add_audit(0, "web_report_" + act, f"#{rid}")
            return f"✅ البلاغ #{rid} " + ("أُغلق" if act == "close" else "أُعيد فتحه")
        if act == "delete":
            if form.get("confirm") != "1":
                return "☑️ فعّل «تأكيد الحذف» أولاً."
            self.db.delete_report(rid)
            self.db.add_audit(0, "web_report_delete", f"#{rid}")
            return f"🗑 حُذف البلاغ #{rid}"
        return "إجراء غير معروف."

    def reports_csv(self, params: dict) -> bytes:
        f, k, q, _ = self.reports_query(params)
        rows, _total = self.db.list_reports("" if f == "all" else f, k, q, 200, 0)
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["id", "status", "kind", "user_id", "username", "created", "text", "context", "reply"])
        for r in rows:
            w.writerow([r["id"], r["status"], r["kind"], r["user_id"], _cell(r.get("username")), _ts(r["created_at"]), _cell(r["text"]), _cell(r["ctx"]), _cell(r["reply"])])
        self.db.add_audit(0, "web_export_reports", f"{len(rows)} rows")
        return ("\ufeff" + out.getvalue()).encode("utf-8")

    # ================================================================== user detail
    def user_page(self, sess: dict, params: dict) -> bytes:
        csrf = sess["csrf"]
        uid = _int(params.get("id"), 0, 0, 10 ** 15)
        u = self.db.get_user(uid) if uid else None
        if not u:
            return self.page(f'{self.nav("users", csrf)}<main><div class="flash bad">🔍 المستخدم غير موجود.</div><p><a href="/">← المستخدمون</a></p></main>', "مستخدم")
        lim = self.limit_of(u)
        today = self.db.daily_count(uid)
        locked = uid in self.cfg.admin_ids or u.get("role") == "mod"
        name = u.get("first_name") or u.get("username") or uid
        info = "".join(f"<tr><td class=mut>{_e(k)}</td><td>{v}</td></tr>" for k, v in (
            ("المعرّف", f"<code>{uid}</code>"), ("الاسم", _e(name)), ("المستخدم", f'@{_e(u["username"])}' if u.get("username") else "-"),
            ("الحالة", self._status_chip(u) + (' <span class="b">مدير</span>' if uid in self.cfg.admin_ids else "")),
            ("اللغة / الشخصية", f'{_e(u.get("lang"))} / {_e(u.get("persona"))}'), ("اليوم / الحد", f'{today} / {lim if lim else "∞"}'),
            ("إجمالي الرسائل", u["msgs"]), ("التوكنات (دخل/خرج)", f'{u["tokens_in"]:,} / {u["tokens_out"]:,}'),
            ("انضم", _e(_ts(u["created_at"]))), ("آخر نشاط", _e(_ts(u["last_seen"])))))
        from .webpanel import LIMIT_CHOICES                      # imported late: webpanel imports this module
        lim_opts = "".join(f'<option value="{k}">{_e(t)}</option>' for k, t in LIMIT_CHOICES)
        ret = f"/user?id={uid}"
        btn = lambda a, t: f'<button name="act" value="{a}">{t}</button>'      # noqa: E731
        actions = ('<span class="mut">محمي: لا يمكن تعديل المديرين والمشرفين من هنا.</span>' if locked else
                   f'<form method="post" action="/act" class="row" style="flex-wrap:wrap">{self._hidden(csrf, uid=uid, ret=ret)}'
                   + btn("ap", "✅ موافقة") + btn("rj", "❌ رفض") + (btn("ub", "♻️ فك الحظر") if u["banned"] else btn("ban", "🚫 حظر"))
                   + (btn("da", "⛔ سحب") if u["allowed"] else "") + f'<select name="value">{lim_opts}</select>' + btn("lim", "📊 ضبط الحد") + "</form>")
        dm = (f'<form method="post" action="/user/dm">{self._hidden(csrf, uid=uid)}<textarea name="text" maxlength="1500" placeholder="رسالة مباشرة لهذا المستخدم عبر البوت…" required></textarea>'
              f'<div class="row"><button class="p">✉️ إرسال</button></div></form>')
        reps = self.db.reports_of_user(uid, 8)
        rep_rows = "".join(f'<tr><td><a href="/reports?f=all&q={uid}#r{r["id"]}">#{r["id"]}</a></td><td>{KIND_LABEL.get(r["kind"], KIND_LABEL["other"])[0]}</td>'
                           f'<td>{"✅" if r["status"] == "closed" else "🟡"}</td><td class="mut">{_e(r["text"][:80])}</td></tr>' for r in reps)
        aud = "".join(f'<tr><td class="mut">{_e(_ts(a["ts"]))}</td><td>{_e(a["action"])}</td><td class="mut">{_e((a["detail"] or "")[:50])}</td></tr>' for a in self.db.user_audit(uid, 12))
        body = (f'{self.nav("users", csrf)}<main>{self._flash(sess)}<p><a href="/">← المستخدمون</a></p><h2>👤 {_e(name)}</h2>'
                f'<div class="grid2"><section class="card"><h3>المعلومات</h3><table style="min-width:0"><tbody>{info}</tbody></table></section>'
                f'<section class="card"><h3>💬 النشاط (14 يوماً)</h3>{bar_chart(self.db.user_daily(uid, 14))}<h3>إجراءات</h3>{actions}</section></div>'
                f'<section class="card"><h3>✉️ مراسلة المستخدم</h3>{dm}</section>{self.user_ctl_card(csrf, u)}'
                f'<div class="grid2"><section class="card"><h3>📨 بلاغاته</h3>{("<table style=min-width:0><tbody>" + rep_rows + "</tbody></table>") if rep_rows else "<p class=mut>لا بلاغات.</p>"}</section>'
                f'<section class="card"><h3>🧾 أحداث متعلقة</h3>{("<table style=min-width:0><tbody>" + aud + "</tbody></table>") if aud else "<p class=mut>لا أحداث.</p>"}</section></div></main>')
        return self.page(body, f"مستخدم {name}")

    def user_dm(self, form: dict) -> str:
        uid = _int(form.get("uid"), 0, 0, 10 ** 15)
        text = (form.get("text") or "").strip()[:1500]
        if not uid or not self.db.get_user(uid):
            return "🔍 المستخدم غير موجود."
        if not text:
            return "✍️ اكتب الرسالة أولاً."
        try:
            ok = bool(self.app.tg.send_message(uid, "📩 <b>رسالة من الإدارة</b>\n\n" + html.escape(text, quote=False)))
        except Exception:
            ok = False
        self.db.add_audit(0, "web_dm" if ok else "web_dm_fail", f"{uid}:{len(text)}c")
        return "✅ أُرسلت الرسالة." if ok else "⚠️ تعذّر الإرسال (ربما حظر المستخدم البوت)."

    # ================================================================== audit log
    def audit_query(self, params: dict):
        q = (params.get("q") or "")[:64]
        a = re.sub(r"[^A-Za-z0-9_]", "", params.get("a", ""))[:30]
        return q, a, _int(params.get("p"), 1, 1, 100000)

    def audit_page(self, sess: dict, params: dict | None = None) -> bytes:
        params = params or {}
        q, a, page = self.audit_query(params)
        rows, total = self.db.search_audit(q, a, AUDIT_PAGE, (page - 1) * AUDIT_PAGE)
        pages = max(1, -(-total // AUDIT_PAGE))
        trs = "".join(f'<tr><td>{_e(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"])))}</td><td><code>{_e(r["user_id"])}</code></td>'
                      f'<td>{_e(r["action"])}</td><td class="mut">{_e((r["detail"] or "")[:120])}</td></tr>' for r in rows)
        opts = '<option value="">كل الأنواع</option>' + "".join(f'<option value="{_e(x)}"{" selected" if x == a else ""}>{_e(x)}</option>' for x in self.db.audit_actions())
        bar = (f'<form class="bar" method="get" action="/audit"><input type="search" name="q" value="{_e(q)}" placeholder="بحث في الإجراء أو التفاصيل أو المعرّف">'
               f'<select name="a">{opts}</select><button class="p">بحث</button><a href="/audit.csv?{_e(urlencode({"q": q, "a": a}))}"><button type="button">⬇️ CSV</button></a></form>')
        table = ('<div class="wrap"><table style="min-width:600px"><thead><tr><th>الوقت</th><th>المنفِّذ</th><th>الإجراء</th><th>تفاصيل</th></tr></thead><tbody>'
                 + (trs or '<tr><td colspan="4" class="mut">لا توجد سجلات مطابقة.</td></tr>') + "</tbody></table></div>")
        return self.page(f'{self.nav("audit", sess["csrf"])}<main>{self._flash(sess)}<h2>🧾 سجل التدقيق</h2>{bar}{table}'
                         f'{self._pager("/audit", {"q": q, "a": a}, page, pages, total, "سجل")}</main>', "السجل")

    def audit_csv(self, params: dict) -> bytes:
        q, a, _ = self.audit_query(params)
        rows, _total = self.db.search_audit(q, a, 500, 0)
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["time", "user_id", "action", "detail"])
        for r in rows:
            w.writerow([_ts(r["ts"]), r["user_id"], _cell(r["action"]), _cell(r["detail"])])
        return ("\ufeff" + out.getvalue()).encode("utf-8")
