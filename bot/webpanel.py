"""Web panel: every user in one searchable list, with one-click management (no extra dependencies).

Off by default. Set WEB_PANEL_PORT and WEB_PANEL_TOKEN in .env to turn it on. It listens on 127.0.0.1 only unless you
change WEB_PANEL_HOST, is protected by the token (login form -> HttpOnly session cookie, CSRF token on every action,
login attempts rate-limited), sends strict security headers, needs no JavaScript and escapes every value it prints.
It changes users through the same fields and the same helpers as the Telegram admin panel, and logs to the audit trail.
"""
from __future__ import annotations

import csv
import hmac
import html
import io
import logging
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit, urlencode

from .admin_panel import _cell
from .webext import WebExtMixin

log = logging.getLogger("bot.web")

PAGE_SIZE = 25
SESSION_TTL = 12 * 3600
MAX_BODY = 262144                                      # chat / tool inputs (Arabic text is ~9 bytes per char once URL-encoded)
LOGIN_FAILS, LOGIN_WINDOW = 5, 300
LOOPBACK = ("127.0.0.1", "localhost", "[::1]", "::1")
LIMIT_CHOICES = (("d", "الافتراضي"), ("10", "10"), ("25", "25"), ("50", "50"), ("100", "100"),
                 ("200", "200"), ("500", "500"), ("0", "∞ بلا حد"))
FILTERS = (("", "الكل"), ("pending", "🔔 طلبات معلّقة"), ("allowed", "✅ مفعّلون"), ("banned", "🚫 محظورون"),
           ("rejected", "❌ مرفوضون"), ("staff", "🛡 مشرفون"))
SORTS = (("last_seen", "آخر نشاط"), ("created", "تاريخ الانضمام"), ("msgs", "إجمالي الرسائل"),
         ("today", "رسائل اليوم"), ("id", "المعرّف"))
SEC_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
                               "base-uri 'none'; frame-ancestors 'none'",
    "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store", "Cross-Origin-Resource-Policy": "same-origin",
}

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#14171c;--mut:#6b7280;--line:#e3e6ea;--acc:#1f6feb;--ok:#1a7f37;--bad:#cf222e;--warn:#9a6700}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--card:#161b22;--fg:#e6edf3;--mut:#8b949e;--line:#30363d;--acc:#58a6ff;--ok:#3fb950;--bad:#f85149;--warn:#d29922}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Tahoma,sans-serif}
header{display:flex;gap:12px;align-items:center;justify-content:space-between;padding:12px 16px;background:var(--card);border-bottom:1px solid var(--line)}
h1{font-size:18px;margin:0}main{max-width:1200px;margin:0 auto;padding:16px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:14px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 12px}.stat b{display:block;font-size:22px}.stat span{color:var(--mut);font-size:13px}
.tabs{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px}.tabs a{padding:6px 12px;border:1px solid var(--line);border-radius:99px;background:var(--card);color:var(--fg);text-decoration:none;font-size:14px}
.tabs a.on{background:var(--acc);border-color:var(--acc);color:#fff}
form.bar{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}
input,select,button{font:inherit;color:var(--fg);background:var(--card);border:1px solid var(--line);border-radius:8px;padding:7px 10px}
input[type=search],input[type=password]{flex:1;min-width:160px}button{cursor:pointer}button:hover{border-color:var(--acc)}
button.p{background:var(--acc);border-color:var(--acc);color:#fff}
.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%;min-width:880px}th,td{padding:8px 10px;text-align:start;border-bottom:1px solid var(--line);vertical-align:middle;white-space:nowrap}
th{background:var(--bg);font-size:13px;color:var(--mut)}tr:last-child td{border-bottom:0}
.b{display:inline-block;padding:1px 9px;border-radius:99px;font-size:12px;border:1px solid var(--line)}
.ok{color:var(--ok);border-color:var(--ok)}.bad{color:var(--bad);border-color:var(--bad)}.warn{color:var(--warn);border-color:var(--warn)}.mut{color:var(--mut)}
td.act form{display:flex;gap:4px;flex-wrap:wrap;align-items:center}td.act button,td.act select{padding:3px 8px;font-size:13px}
.flash{padding:10px 14px;border-radius:8px;margin-bottom:12px;border:1px solid var(--line);background:var(--card)}
.pager{display:flex;gap:10px;align-items:center;justify-content:center;margin:14px 0}.pager a{color:var(--acc);text-decoration:none}
.login{max-width:360px;margin:12vh auto;padding:20px;background:var(--card);border:1px solid var(--line);border-radius:12px}
.login form{display:flex;flex-direction:column;gap:10px}code{font-family:ui-monospace,Menlo,Consolas,monospace}
header .nav{margin:0;flex:1;justify-content:center}h2{font-size:17px;margin:4px 0 12px}h3{font-size:15px;margin:18px 0 8px}
.chat{display:flex;flex-direction:column;gap:10px;margin-bottom:14px}
.msg{max-width:85%;padding:10px 14px;border-radius:12px;border:1px solid var(--line);background:var(--card)}
.msg.me{align-self:flex-start;background:var(--acc);border-color:var(--acc);color:#fff}.msg.ai{align-self:flex-end}
.msg b{font-size:12px;opacity:.75;display:block;margin-bottom:2px}.txt{white-space:pre-wrap;word-break:break-word}
.chatform{display:flex;flex-direction:column;gap:8px;margin-bottom:10px}.chatform textarea{font:inherit;color:var(--fg);background:var(--card);border:1px solid var(--line);border-radius:8px;padding:9px 12px;resize:vertical;min-height:90px}
.row{display:flex;gap:8px;margin:6px 0}pre.out{white-space:pre-wrap;word-break:break-word;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px;font-family:ui-monospace,Menlo,Consolas,monospace;direction:ltr;text-align:left}
"""


def _e(x) -> str:
    return html.escape(str(x if x is not None else ""), quote=True)


def _ts(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "-"


class WebPanel(WebExtMixin):
    """Owns the logic (apply / rows / csv / pages) and the HTTP server; the logic is testable without a socket."""

    def __init__(self, app):
        self.app, self.cfg, self.db = app, app.cfg, app.db
        self.sessions: dict = {}
        self.fails: dict = {}
        self.pub_hits: dict = {}
        self._lock = threading.Lock()
        self.server = None
        self.thread = None

    # ================================================================== lifecycle
    def start(self) -> None:
        panel = self
        handler = type("Handler", (_Handler,), {"panel": panel})
        self.server = ThreadingHTTPServer((self.cfg.web_panel_host, self.cfg.web_panel_port), handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.1}, name="web-panel", daemon=True)
        self.thread.start()
        host, port = self.server.server_address[:2]
        log.info("Web panel listening on http://%s:%s", host, port)
        if host not in ("127.0.0.1", "::1", "localhost"):
            log.warning("Web panel is reachable beyond this machine over plain HTTP: put HTTPS (reverse proxy) in front of it")

    @property
    def port(self) -> int:
        return self.server.server_address[1] if self.server else 0

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None

    # ================================================================== auth / sessions
    @staticmethod
    def same(a: str, b: str) -> bool:
        """Constant-time compare that accepts any Unicode (compare_digest on str rejects non-ASCII)."""
        return hmac.compare_digest((a or "").encode("utf-8"), (b or "").encode("utf-8"))

    def check_token(self, token: str) -> bool:
        a, b = (token or "").encode("utf-8"), self.cfg.web_panel_token.encode("utf-8")
        return bool(b) and hmac.compare_digest(a, b)

    def login_blocked(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            xs = [t for t in self.fails.get(ip, []) if now - t < LOGIN_WINDOW]
            self.fails[ip] = xs
            return len(xs) >= LOGIN_FAILS

    def login_failed(self, ip: str) -> None:
        with self._lock:
            now = time.time()
            self.fails.setdefault(ip, []).append(now)
            if len(self.fails) > 1000:                     # never wipe everyone's lockout: drop expired, then the oldest
                self.fails = {k: v for k, v in self.fails.items() if v and now - v[-1] < LOGIN_WINDOW}
                while len(self.fails) > 1000:
                    self.fails.pop(min(self.fails, key=lambda k: self.fails[k][-1]))

    def new_session(self) -> str:
        sid = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            self.sessions = {k: v for k, v in self.sessions.items() if v["exp"] > now}
            self.sessions[sid] = {"exp": now + SESSION_TTL, "csrf": secrets.token_urlsafe(24), "flash": ""}
        return sid

    def session(self, sid: str):
        with self._lock:
            s = self.sessions.get(sid or "")
            if s and s["exp"] > time.time():
                return s
            self.sessions.pop(sid or "", None)
            return None

    def end_session(self, sid: str) -> None:
        with self._lock:
            self.sessions.pop(sid or "", None)

    def host_ok(self, host_header: str) -> bool:
        """Blocks DNS-rebinding: while the panel is bound to loopback only local host names are accepted."""
        if self.cfg.web_panel_host not in ("127.0.0.1", "::1", "localhost"):
            return True
        h = (host_header or "").strip().lower()
        h = h.rsplit(":", 1)[0] if (h.count(":") == 1 or h.startswith("[") and "]:" in h) else h
        return h in LOOPBACK or h in self.cfg.web_panel_hostnames() or (host_header or "").strip().lower() in self.cfg.web_panel_hostnames()

    # ================================================================== actions (same rules as the Telegram panel)
    def apply(self, act: str, tid: int, value: str = "") -> tuple:
        """-> (ok, message). Never touches admins, moderators or invalid ids."""
        if tid <= 0 or tid in self.cfg.admin_ids:
            return False, "🛡 لا يمكن تعديل مدير أو معرّف غير صالح."
        u = self.db.get_user(tid)
        if not u:
            return False, "🔍 المستخدم غير موجود."
        if u.get("role") == "mod":
            return False, "🛡 لا يمكن تعديل مشرف من هنا."
        name = u.get("first_name") or u.get("username") or tid
        now = int(time.time())
        if act == "ap":
            if u["banned"]:
                return False, "🚫 هذا المستخدم محظور. فك الحظر أولاً."
            self.db.set_user(tid, allowed=1, requested_at=0)
            self.app.grant_welcome_limit(tid)
            self._notify(tid, "approved")
            msg = f"✅ تمت الموافقة على {name}"
        elif act == "rj":
            self.db.set_user(tid, requested_at=-now)
            self._notify(tid, "rejected")
            msg = f"❌ تم رفض {name}"
        elif act == "ban":
            self.db.set_user(tid, banned=1)
            msg = f"🚫 تم حظر {name}"
        elif act == "ub":
            self.db.set_user(tid, banned=0)
            msg = f"♻️ تم فك حظر {name}"
        elif act == "da":
            self.db.set_user(tid, allowed=0)
            msg = f"⛔ تم سحب صلاحية {name}"
        elif act == "lim":
            if value not in dict(LIMIT_CHOICES):
                return False, "قيمة الحد غير صالحة."
            self.db.set_user(tid, limit_override=-1 if value == "d" else int(value))
            msg = f"📊 تم ضبط الحد اليومي لـ {name}: " + ("الافتراضي" if value == "d" else ("∞" if value == "0" else value))
        else:
            return False, "إجراء غير معروف."
        self.db.add_audit(0, "web_" + act, f"{tid}:{value}"[:60])
        return True, msg

    def _notify(self, tid: int, kind: str) -> None:
        try:
            self.app.notify_user_decision(tid, kind)
        except Exception:                                  # the change is saved even if Telegram is unreachable
            log.warning("could not notify user %s", tid, exc_info=True)

    # ================================================================== data helpers
    def status_of(self, u: dict) -> tuple:
        now = time.time()
        if u["banned"]:
            return "محظور", "bad"
        if u.get("role") == "mod":
            return "مشرف", "ok"
        if u["allowed"]:
            return "مفعّل", "ok"
        if (u.get("requested_at") or 0) > 0:
            return "بانتظار الموافقة", "warn"
        if (u.get("requested_at") or 0) < 0:
            return "مرفوض", "bad"
        return "غير مفعّل", "mut"

    def limit_of(self, u: dict) -> int:
        if u["id"] in self.cfg.admin_ids:
            return 0
        ov = u.get("limit_override", -1)
        return ov if (ov is not None and ov >= 0) else self.app.default_user_limit()

    def query(self, params: dict):
        flt = params.get("f", "")
        flt = flt if flt in dict(FILTERS) else ""
        sort = params.get("s", "last_seen")
        sort = sort if sort in dict(SORTS) else "last_seen"
        desc = params.get("o", "d") != "a"
        q = (params.get("q") or "")[:64]
        try:
            page = max(1, min(int(params.get("p", "1")), 100000))
        except ValueError:
            page = 1
        return flt, sort, desc, q, page

    def export_csv(self, params: dict) -> bytes:
        flt, sort, desc, q, _ = self.query(params)
        rows, _total = self.db.search_users(flt, q, sort, desc, 5000, 0)
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["id", "username", "first_name", "status", "daily_limit", "today", "messages", "tokens_in",
                    "tokens_out", "joined", "last_seen"])
        for u in rows:
            lim = self.limit_of(u)
            w.writerow([u["id"], _cell(u.get("username")), _cell(u.get("first_name")), self.status_of(u)[0],
                        lim or "unlimited", u["today"], u["msgs"], u["tokens_in"], u["tokens_out"],
                        _ts(u["created_at"]), _ts(u["last_seen"])])
        self.db.add_audit(0, "web_export", f"{len(rows)} users")
        return ("\ufeff" + out.getvalue()).encode("utf-8")           # BOM so Excel opens Arabic correctly

    # ================================================================== pages
    def page(self, body: str, title: str = "DARWIN DZ") -> bytes:
        return (f'<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">'
                f'<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">'
                f'<title>{_e(title)}</title><style>{CSS}</style></head><body>{body}</body></html>').encode("utf-8")

    def login_page(self, error: str = "") -> bytes:
        """Public home page: what the bot is, a link to the bot, the free tools, and the admin login box."""
        err = f'<div class="flash bad">{_e(error)}</div>' if error else ""
        uname = getattr(self.app, "bot_username", "") or ""
        bot_link = (f'<p><a href="https://t.me/{_e(uname)}"><button type="button" class="p">💬 افتح البوت @{_e(uname)} في تيليجرام</button></a></p>'
                    if uname else "")
        return self.page(f'<div class="login"><h1>🛡 DARWIN DZ</h1><p class="mut">مساعد ذكاء اصطناعي وأدوات أمن سيبراني</p>{bot_link}'
                         '<p><a href="/t"><button type="button">🧰 الأدوات المجانية (بدون تسجيل)</button></a></p>'
                         f'<h3>دخول المدير</h3>{err}'
                         '<form method="post" action="/login"><input type="password" name="token" placeholder="كلمة المرور (أرسل /web للبوت)" '
                         'autocomplete="current-password" required><button class="p">دخول</button></form></div>', "DARWIN DZ")

    def dashboard(self, sess: dict, params: dict) -> bytes:
        flt, sort, desc, q, page = self.query(params)
        rows, total = self.db.search_users(flt, q, sort, desc, PAGE_SIZE, (page - 1) * PAGE_SIZE)
        counts = self.db.web_counts()
        pages = max(1, -(-total // PAGE_SIZE))
        if page > pages:                                   # e.g. after banning the last user of a filtered page
            page = pages
            rows, total = self.db.search_users(flt, q, sort, desc, PAGE_SIZE, (page - 1) * PAGE_SIZE)
        csrf = sess["csrf"]
        flash, sess["flash"] = sess.get("flash") or "", ""

        def link(**kw):
            base = {"f": flt, "q": q, "s": sort, "o": "d" if desc else "a", "p": page}
            base.update(kw)
            return "/?" + urlencode({k: v for k, v in base.items() if v not in ("", None) and not (k == "p" and v == 1)
                                     and not (k == "s" and v == "last_seen") and not (k == "o" and v == "d")})

        stats = "".join(f'<div class="stat"><b>{n}</b><span>{_e(t)}</span></div>' for n, t in (
            (counts["all"], "كل المستخدمين"), (counts["pending"], "طلبات معلّقة"), (counts["allowed"], "مفعّلون"),
            (counts["banned"], "محظورون"), (counts["today_msgs"], "رسائل اليوم")))
        tabs = "".join(f'<a class="{"on" if k == flt else ""}" href="{_e(link(f=k, p=1))}">{_e(t)} ({counts[k or "all"]})</a>'
                       for k, t in FILTERS)
        sort_opts = "".join(f'<option value="{k}"{" selected" if k == sort else ""}>{_e(t)}</option>' for k, t in SORTS)
        bar = (f'<form class="bar" method="get" action="/"><input type="hidden" name="f" value="{_e(flt)}">'
               f'<input type="search" name="q" value="{_e(q)}" placeholder="بحث بالمعرّف أو @المستخدم أو الاسم">'
               f'<select name="s">{sort_opts}</select>'
               f'<select name="o"><option value="d"{" selected" if desc else ""}>تنازلي</option>'
               f'<option value="a"{"" if desc else " selected"}>تصاعدي</option></select>'
               f'<button class="p">بحث</button><a href="{_e("/export.csv?" + urlencode({"f": flt, "q": q, "s": sort, "o": "d" if desc else "a"}))}">'
               f'<button type="button">⬇️ CSV</button></a></form>')
        lim_opts = "".join(f'<option value="{k}">{_e(t)}</option>' for k, t in LIMIT_CHOICES)
        back = urlencode({"f": flt, "q": q, "s": sort, "o": "d" if desc else "a", "p": page})
        trs = []
        for u in rows:
            st, cls = self.status_of(u)
            lim = self.limit_of(u)
            used = f'{u["today"]} / {lim if lim else "∞"}'
            over = ' class="bad"' if lim and u["today"] >= lim else ""
            locked = u["id"] in self.cfg.admin_ids or u.get("role") == "mod"
            if locked:
                acts = '<span class="mut">محمي</span>'
            else:
                btn = lambda a, t: f'<button name="act" value="{a}">{t}</button>'
                acts = (f'<form method="post" action="/act"><input type="hidden" name="csrf" value="{_e(csrf)}">'
                        f'<input type="hidden" name="uid" value="{u["id"]}"><input type="hidden" name="back" value="{_e(back)}">'
                        + btn("ap", "✅ موافقة") + btn("rj", "❌ رفض")
                        + (btn("ub", "♻️ فك الحظر") if u["banned"] else btn("ban", "🚫 حظر"))
                        + (btn("da", "⛔ سحب") if u["allowed"] else "")
                        + f'<select name="value">{lim_opts}</select>' + btn("lim", "📊 حد") + '</form>')
            uname = f'@{_e(u["username"])}' if u.get("username") else '<span class="mut">-</span>'
            trs.append(f'<tr><td><code>{u["id"]}</code></td><td>{_e((u.get("first_name") or "-")[:40])}</td><td>{uname}</td>'
                       f'<td><span class="b {cls}">{_e(st)}</span></td><td{over}>{_e(used)}</td><td>{u["msgs"]}</td>'
                       f'<td>{_e(_ts(u["last_seen"]))}</td><td>{_e(_ts(u["created_at"]))}</td><td class="act">{acts}</td></tr>')
        table = ('<div class="wrap"><table><thead><tr><th>المعرّف</th><th>الاسم</th><th>المستخدم</th><th>الحالة</th>'
                 '<th>اليوم / الحد</th><th>الرسائل</th><th>آخر نشاط</th><th>انضم</th><th>إجراءات</th></tr></thead><tbody>'
                 + ("".join(trs) or '<tr><td colspan="9" class="mut">لا يوجد مستخدمون مطابقون.</td></tr>') + '</tbody></table></div>')
        pager = (f'<div class="pager">' + (f'<a href="{_e(link(p=page - 1))}">→ السابق</a>' if page > 1 else "")
                 + f'<span>صفحة {page} من {pages} · {total} مستخدم</span>'
                 + (f'<a href="{_e(link(p=page + 1))}">التالي ←</a>' if page < pages else "") + '</div>')
        flash_html = f'<div class="flash">{_e(flash)}</div>' if flash else ""
        head = self.nav("users", csrf)
        return self.page(f'{head}<main>{flash_html}<div class="stats">{stats}</div><div class="tabs">{tabs}</div>{bar}{table}{pager}</main>')


class _Handler(BaseHTTPRequestHandler):
    panel: WebPanel = None
    protocol_version = "HTTP/1.1"
    timeout = 15                                             # idle/slow clients (slowloris) are dropped, not parked forever
    server_version = "DZ"
    sys_version = ""

    def log_message(self, fmt, *args):                       # never log URLs/cookies; one short line at DEBUG
        log.debug("web %s", fmt % args)

    # ---- helpers
    def _send(self, code: int, body: bytes = b"", ctype: str = "text/html; charset=utf-8", headers: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in {**SEC_HEADERS, **(headers or {})}.items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _redirect(self, where: str, extra: dict | None = None) -> None:
        self._send(303, b"", headers={"Location": where, **(extra or {})})

    def _cookie(self) -> str:
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "dz_sid":
                return v
        return ""

    def _set_cookie(self, sid: str, max_age: int) -> str:
        https = (self.headers.get("X-Forwarded-Proto") or "").lower() == "https" or self.panel.cfg.web_panel_url.startswith("https://")
        secure = "; Secure" if https else ""
        return f"dz_sid={sid}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}"

    def _form(self) -> dict | None:
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if n < 0 or n > MAX_BODY:
            return None
        raw = self.rfile.read(n).decode("utf-8", "replace")
        return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True, max_num_fields=20).items()}

    def _guard(self) -> bool:
        if not self.panel.host_ok(self.headers.get("Host", "")):
            self._send(403, b"forbidden", "text/plain; charset=utf-8")
            return False
        return True

    def _ip(self) -> str:
        """Client address for the login rate limit. Behind a reverse proxy (WEB_PANEL_URL set, proxy on this machine) every request comes from the
        proxy, so use the LAST X-Forwarded-For entry (the one the proxy itself appended; earlier ones can be forged)."""
        if self.panel.cfg.web_panel_url and self.client_address[0] in ("127.0.0.1", "::1"):   # only a LOCAL proxy may speak for a client
            xff = [x.strip() for x in (self.headers.get("X-Forwarded-For") or "").split(",") if x.strip()]
            if xff:
                return xff[-1][:45]
        return self.client_address[0]

    # ---- routes
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        try:
            if not self._guard():
                return
            url = urlsplit(self.path)
            params = {k: v[0] for k, v in parse_qs(url.query, max_num_fields=20).items()}
            sess = self.panel.session(self._cookie())
            if url.path == "/healthz":
                return self._send(200, b"ok", "text/plain; charset=utf-8")
            if url.path == "/t":
                return self._send(200, self.panel.public_tools_page())
            if not sess:
                if url.path not in ("/", "/login"):
                    return self._redirect("/")
                return self._send(200, self.panel.login_page())
            if url.path == "/":
                return self._send(200, self.panel.dashboard(sess, params))
            if url.path == "/chat":
                return self._send(200, self.panel.chat_page(sess))
            if url.path == "/tools":
                return self._send(200, self.panel.tools_page(sess))
            if url.path == "/audit":
                return self._send(200, self.panel.audit_page(sess))
            if url.path == "/system":
                return self._send(200, self.panel.system_page(sess))
            if url.path == "/export.csv":
                return self._send(200, self.panel.export_csv(params), "text/csv; charset=utf-8",
                                  {"Content-Disposition": 'attachment; filename="darwin_users.csv"'})
            self._send(404, b"not found", "text/plain; charset=utf-8")
        except Exception:
            log.exception("web GET failed")
            self._send(500, b"server error", "text/plain; charset=utf-8")

    def do_POST(self):
        try:
            if not self._guard():
                return
            url = urlsplit(self.path)
            form = self._form()
            if form is None:
                self.close_connection = True               # the unread body must not be parsed as the next request
                return self._send(413, b"too large", "text/plain; charset=utf-8", {"Connection": "close"})
            if url.path == "/login":
                ip = self._ip()
                if self.panel.login_blocked(ip):
                    return self._send(429, self.panel.login_page("محاولات كثيرة. انتظر بضع دقائق."), headers={"Retry-After": "300"})
                if not self.panel.check_token(form.get("token", "")):
                    self.panel.login_failed(ip)
                    self.panel.db.add_audit(0, "web_login_fail", ip[:45])
                    return self._send(401, self.panel.login_page("كلمة المرور غير صحيحة."))
                sid = self.panel.new_session()
                self.panel.db.add_audit(0, "web_login", ip[:45])
                return self._redirect("/", {"Set-Cookie": self._set_cookie(sid, SESSION_TTL)})
            if url.path == "/t":                           # public tools: stateless, rate-limited per IP, no cookies needed
                code, page = self.panel.public_tools_run(self._ip(), form.get("tool", ""), form.get("text", ""))
                return self._send(code, page)
            sid = self._cookie()
            sess = self.panel.session(sid)
            if not sess or not self.panel.same(form.get("csrf", ""), sess["csrf"]):
                return self._send(403, b"forbidden", "text/plain; charset=utf-8")
            if url.path == "/logout":
                self.panel.end_session(sid)
                return self._redirect("/", {"Set-Cookie": self._set_cookie("", 0)})
            if url.path == "/chat/send":
                err = self.panel.chat_send(sess, form.get("persona", ""), form.get("msg", ""))
                sess["flash"] = err
                return self._redirect("/chat")
            if url.path == "/chat/clear":
                sess["chat"] = []
                return self._redirect("/chat")
            if url.path == "/tools/run":
                self.panel.tools_run(sess, form.get("tool", ""), form.get("text", ""))
                return self._redirect("/tools")
            if url.path == "/act":
                try:
                    tid = int(form.get("uid", ""))
                except ValueError:
                    tid = 0
                ok, msg = self.panel.apply(form.get("act", ""), tid, form.get("value", ""))
                sess["flash"] = msg
                back = {k: v[0] for k, v in parse_qs(form.get("back", ""), max_num_fields=10).items()}
                flt, sort, desc, q, page = self.panel.query(back)
                qs = urlencode({k: v for k, v in (("f", flt), ("q", q), ("s", sort), ("o", "d" if desc else "a"), ("p", page)) if v})
                return self._redirect("/?" + qs)
            self._send(404, b"not found", "text/plain; charset=utf-8")
        except Exception:
            log.exception("web POST failed")
            self._send(500, b"server error", "text/plain; charset=utf-8")
