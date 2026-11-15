"""v4.4.0: web user-management panel (real HTTP on a local ephemeral port)."""
import dataclasses
import http.client
import re
import time
import unittest
from urllib.parse import urlencode

from bot.config import Config
from bot.webpanel import WebPanel
from tests import test_integration as ti
from tests.test_v34 import Harness

TOKEN = "correct-horse-battery"


class PanelBase(Harness):
    __test__ = True

    def setUp(self):
        super().setUp()
        self.app.cfg = dataclasses.replace(self.app.cfg, web_panel_port=0, web_panel_token=TOKEN)
        self.panel = WebPanel(self.app)
        self.panel.start()
        self.port = self.panel.port
        for uid, un, name in ((2, "alice", "Alice"), (3, "bob", "<script>alert(1)</script>"), (4, "=cmd", "=HYPERLINK(1)")):
            self.db.upsert_user(uid, un, name)
        self.db.set_user(3, requested_at=int(time.time()))

    def tearDown(self):
        self.panel.stop()
        super().tearDown()

    def req(self, method, path, body=None, cookie="", host=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Host": host or f"127.0.0.1:{self.port}"}
        if cookie:
            h["Cookie"] = cookie
        data = None
        if body is not None:
            data = urlencode(body)
            h["Content-Type"] = "application/x-www-form-urlencoded"
        c.request(method, path, data, h)
        r = c.getresponse()
        out = (r.status, dict(r.getheaders()), r.read().decode("utf-8", "replace"))
        c.close()
        return out

    def login(self):
        st, hd, _ = self.req("POST", "/login", {"token": TOKEN})
        self.assertEqual(st, 303)
        cookie = hd["Set-Cookie"].split(";")[0]
        return cookie

    def csrf(self, cookie):
        _, _, page = self.req("GET", "/", cookie=cookie)
        return re.search(r'name="csrf" value="([^"]+)"', page).group(1)


class Auth(PanelBase):
    def test_login_required_and_headers(self):
        st, hd, body = self.req("GET", "/")
        self.assertEqual(st, 200)
        self.assertIn("كلمة المرور", body)
        self.assertNotIn("alice", body)
        self.assertIn("default-src 'none'", hd["Content-Security-Policy"])
        self.assertEqual(hd["X-Frame-Options"], "DENY")
        self.assertEqual(self.req("GET", "/export.csv")[0], 303)               # no data without a session
        self.assertEqual(self.req("POST", "/act", {"uid": "2", "act": "ap"})[0], 403)

    def test_wrong_token_then_rate_limit(self):
        for _ in range(5):
            self.assertEqual(self.req("POST", "/login", {"token": "nope"})[0], 401)
        self.assertEqual(self.req("POST", "/login", {"token": TOKEN})[0], 429)   # even the right one is refused for a while

    def test_cookie_flags_and_logout(self):
        _, hd, _ = self.req("POST", "/login", {"token": TOKEN})
        self.assertIn("HttpOnly", hd["Set-Cookie"])
        self.assertIn("SameSite=Strict", hd["Set-Cookie"])
        cookie = hd["Set-Cookie"].split(";")[0]
        csrf = self.csrf(cookie)
        self.req("POST", "/logout", {"csrf": csrf}, cookie=cookie)
        self.assertIn("كلمة المرور", self.req("GET", "/", cookie=cookie)[2])

    def test_foreign_host_header_refused_when_bound_to_loopback(self):
        self.assertEqual(self.req("GET", "/", host="evil.example.com")[0], 403)
        self.assertEqual(self.req("GET", "/", host="localhost:1234")[0], 200)

    def test_config_requires_token_when_enabled(self):
        base = dict(telegram_token="t", api_key="k")
        self.assertEqual(Config(**base).validate(), [])
        self.assertTrue(any("WEB_PANEL_TOKEN" in p for p in Config(**base, web_panel_port=8080).validate()))
        self.assertEqual(Config(**base, web_panel_port=8080, web_panel_token="x" * 12).validate(), [])


class Dashboard(PanelBase):
    def test_lists_users_and_escapes_html(self):
        page = self.req("GET", "/", cookie=self.login())[2]
        self.assertIn("alice", page)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)

    def test_filter_search_sort(self):
        c = self.login()
        pend = self.req("GET", "/?f=pending", cookie=c)[2]
        self.assertIn("&lt;script&gt;", pend)
        self.assertNotIn("alice", pend)
        self.assertIn("alice", self.req("GET", "/?q=ALI", cookie=c)[2])
        self.assertNotIn("alice", self.req("GET", "/?q=zzz", cookie=c)[2])
        self.assertEqual(self.req("GET", "/?s=bogus&o=zz&p=abc&f=x", cookie=c)[0], 200)   # junk input never breaks it
        self.assertEqual(self.req("GET", "/?q=%27%20OR%201%3D1--", cookie=c)[0], 200)

    def test_pagination(self):
        for i in range(100, 160):
            self.db.upsert_user(i, f"u{i}", f"N{i}")
        c = self.login()
        self.assertIn("صفحة 1 من 3", self.req("GET", "/", cookie=c)[2])
        rows, total = self.db.search_users(limit=25, offset=50)
        self.assertEqual((len(rows), total), (13, 63))

    def test_csv_export_is_formula_safe(self):
        st, hd, body = self.req("GET", "/export.csv", cookie=self.login())
        self.assertEqual(st, 200)
        self.assertIn("text/csv", hd["Content-Type"])
        self.assertIn("'=cmd", body)
        self.assertIn("'=HYPERLINK(1)", body)
        self.assertNotIn(",=cmd", body)


class Actions(PanelBase):
    def act(self, cookie, **form):
        return self.req("POST", "/act", {"csrf": self.csrf(cookie), **form}, cookie=cookie)

    def test_csrf_is_required(self):
        c = self.login()
        self.assertEqual(self.req("POST", "/act", {"uid": "3", "act": "ap", "csrf": "wrong"}, cookie=c)[0], 403)
        self.assertEqual(self.db.get_user(3)["allowed"], 0)

    def test_approve_gives_100_limit_and_notifies(self):
        c = self.login()
        ti.CALLS.clear()
        self.assertEqual(self.act(c, uid="3", act="ap")[0], 303)
        u = self.db.get_user(3)
        self.assertEqual((u["allowed"], u["requested_at"], u["limit_override"]), (1, 0, 100))
        self.assertTrue(any(p.get("chat_id") == 3 for m, p in ti.CALLS if m == "sendMessage"))
        self.assertIn("web_ap", [a["action"] for a in self.db.list_audit(10)])

    def test_approve_7_days_ban_unban_reject_revoke_limit(self):
        c = self.login()
        self.act(c, uid="2", act="ap7")
        u = self.db.get_user(2)
        self.assertEqual(u["allowed"], 1)
        self.assertGreater(u["expires_at"], time.time() + 6 * 86400)
        self.act(c, uid="2", act="ban")
        self.assertEqual(self.db.get_user(2)["banned"], 1)
        self.act(c, uid="2", act="ap")                                        # banned users cannot be approved
        self.act(c, uid="2", act="ub")
        self.assertEqual(self.db.get_user(2)["banned"], 0)
        self.act(c, uid="2", act="lim", value="250")
        self.assertEqual(self.db.get_user(2)["limit_override"], 100)          # 250 is not an offered choice: refused
        self.act(c, uid="2", act="lim", value="500")
        self.assertEqual(self.db.get_user(2)["limit_override"], 500)
        self.act(c, uid="2", act="lim", value="0")
        self.assertEqual(self.db.get_user(2)["limit_override"], 0)
        self.act(c, uid="2", act="lim", value="d")
        self.assertEqual(self.db.get_user(2)["limit_override"], -1)
        self.act(c, uid="2", act="da")
        self.assertEqual(self.db.get_user(2)["allowed"], 0)
        self.act(c, uid="4", act="rj")
        self.assertLess(self.db.get_user(4)["requested_at"], 0)

    def test_invalid_limit_value_rejected(self):
        c = self.login()
        self.act(c, uid="2", act="lim", value="999999")
        self.assertEqual(self.db.get_user(2)["limit_override"], -1)

    def test_admins_mods_and_junk_ids_are_untouchable(self):
        self.db.upsert_user(1, "boss", "Boss")
        self.db.upsert_user(9, "mod", "Mod")
        self.db.set_user(9, role="mod")
        c = self.login()
        for uid in ("1", "9", "-5", "0", "abc", "99999"):
            self.act(c, uid=uid, act="ban")
        self.assertEqual((self.db.get_user(1)["banned"], self.db.get_user(9)["banned"]), (0, 0))
        self.assertFalse(self.panel.apply("ban", 1)[0])
        self.assertFalse(self.panel.apply("nope", 2)[0])

    def test_notify_failure_does_not_lose_the_change(self):
        self.app.notify_user_decision = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("telegram down"))
        ok, _ = self.panel.apply("ap", 3)
        self.assertTrue(ok)
        self.assertEqual(self.db.get_user(3)["allowed"], 1)

    def test_approved_user_can_chat_afterwards(self):
        from tests.test_ui import message
        self.act(self.login(), uid="2", act="ap")
        ti.CALLS.clear()
        self.app.on_message(message(2, "explain what XSS is in two sentences"))
        self.assertIn("Echo:", "\n".join(p.get("text", "") for m, p in ti.CALLS if m in ("sendMessage", "editMessageText")))


if __name__ == "__main__":
    unittest.main()


class AdminButton(PanelBase):
    def _buttons(self):
        kbd = self.app.admin_kb("ar", True, 0)
        return [b for row in kbd["inline_keyboard"] for b in row]

    def test_no_button_without_url(self):
        self.assertFalse(any("web_app" in b or "laplace" in b.get("url", "") for b in self._buttons()))

    def test_button_opens_configured_url_for_admin_only(self):
        self.app.cfg = dataclasses.replace(self.app.cfg, web_panel_url="https://laplace.fadehost.com")
        urls = [b["url"] for b in self._buttons() if "url" in b]
        self.assertIn("https://laplace.fadehost.com", urls)
        mod = [b for row in self.app.admin_kb("ar", False, 0)["inline_keyboard"] for b in row]
        self.assertFalse(any("url" in b for b in mod))

    def test_url_host_is_accepted_and_others_refused(self):
        self.app.cfg = dataclasses.replace(self.app.cfg, web_panel_url="https://laplace.fadehost.com")
        self.panel.cfg = self.app.cfg                      # the panel keeps its own reference to the config
        self.assertEqual(self.req("GET", "/", host="laplace.fadehost.com")[0], 200)
        self.assertEqual(self.req("GET", "/", host="evil.example.com")[0], 403)

    def test_url_validation(self):
        base = dict(telegram_token="t", api_key="k")
        self.assertEqual(Config(**base, web_panel_url="https://laplace.fadehost.com").validate(), [])
        self.assertTrue(Config(**base, web_panel_url="javascript:alert(1)").validate())
        self.assertTrue(Config(**base, web_panel_url="https://u:p@x.com").validate())

    def test_behind_proxy_cookie_secure_and_per_client_rate_limit(self):
        self.app.cfg = dataclasses.replace(self.app.cfg, web_panel_url="https://laplace.fadehost.com")
        self.panel.cfg = self.app.cfg
        _, hd, _ = self.req("POST", "/login", {"token": TOKEN})
        self.assertIn("Secure", hd["Set-Cookie"])
        def attempt(ip, tok):
            c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
            c.request("POST", "/login", urlencode({"token": tok}),
                      {"Host": "laplace.fadehost.com", "X-Forwarded-For": "6.6.6.6, " + ip,
                       "Content-Type": "application/x-www-form-urlencoded"})
            r = c.getresponse(); r.read(); c.close()
            return r.status
        for _ in range(5):
            self.assertEqual(attempt("1.1.1.1", "bad"), 401)
        self.assertEqual(attempt("1.1.1.1", TOKEN), 429)      # the attacker is locked out
        self.assertEqual(attempt("2.2.2.2", TOKEN), 303)      # the real admin is not
