"""The AI chat is a standalone website (bot/webchat.py): own port, own password, own cookie, independent of the admin panel."""
import dataclasses
import http.client
import json
import re
import unittest
from unittest import mock
from urllib.parse import urlencode

from bot.ai_client import APIError
from bot.config import Config, derive_chat_password, derive_panel_password
from bot.webchat import ChatSite
from bot.webpanel import WebPanel
from tests.test_v34 import Harness

PASSWORD = "chat-pass-1234"


class ChatBase(Harness):
    __test__ = True
    public = False

    def setUp(self):
        super().setUp()
        self.app.cfg = dataclasses.replace(self.app.cfg, web_chat_port=0, web_chat_password=PASSWORD, web_chat_public=self.public,
                                           web_chat_daily=0)
        self.site = ChatSite(self.app)
        self.site.start()
        self.port = self.site.port

    def tearDown(self):
        self.site.stop()
        super().tearDown()

    def req(self, method, path, body=None, cookie="", csrf="", raw=None, host=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Host": host or f"127.0.0.1:{self.port}", **(headers or {})}
        if cookie:
            h["Cookie"] = cookie
        data = raw
        if isinstance(body, dict) and raw is None:
            if path == "/login":
                data, h["Content-Type"] = urlencode(body), "application/x-www-form-urlencoded"
            else:
                data, h["Content-Type"] = json.dumps(body), "application/json"
        if csrf:
            h["X-CSRF"] = csrf
        c.request(method, path, data, h)
        r = c.getresponse()
        out = (r.status, dict(r.getheaders()), r.read().decode("utf-8", "replace"))
        c.close()
        return out

    def login(self):
        st, hd, _ = self.req("POST", "/login", {"password": PASSWORD})
        self.assertEqual(st, 303)
        cookie = hd["Set-Cookie"].split(";")[0]
        page = self.req("GET", "/", cookie=cookie)[2]
        return cookie, re.search(r'data-csrf="([^"]+)"', page).group(1)


class PasswordMode(ChatBase):
    def test_login_page_and_headers(self):
        st, hd, body = self.req("GET", "/")
        self.assertEqual(st, 200)
        self.assertIn("كلمة المرور", body)
        self.assertNotIn("<script", body)
        self.assertEqual(hd["X-Frame-Options"], "DENY")
        self.assertEqual(self.req("POST", "/api/chat", {"msg": "hi"})[0], 401)

    def test_wrong_password_locks_out(self):
        for _ in range(5):
            self.assertEqual(self.req("POST", "/login", {"password": "nope"})[0], 401)
        self.assertEqual(self.req("POST", "/login", {"password": PASSWORD})[0], 429)

    def test_cookie_flags_and_csp_nonce(self):
        st, hd, _ = self.req("POST", "/login", {"password": PASSWORD})
        self.assertIn("HttpOnly", hd["Set-Cookie"])
        self.assertIn("SameSite=Strict", hd["Set-Cookie"])
        cookie = hd["Set-Cookie"].split(";")[0]
        _, hd, page = self.req("GET", "/", cookie=cookie)
        nonce = re.search(r"script-src 'nonce-([^']+)'", hd["Content-Security-Policy"]).group(1)
        self.assertIn(f'<script nonce="{nonce}">', page)
        self.assertNotIn("innerHTML", page)
        self.assertNotRegex(hd["Content-Security-Policy"], r"script-src[^;]*unsafe")

    def test_round_trip_clear_and_escaping(self):
        cookie, csrf = self.login()
        with mock.patch.object(self.app.ai, "chat", return_value=("مرحباً <b>بك</b>", {"prompt_tokens": 3, "completion_tokens": 2})) as m:
            st, _, body = self.req("POST", "/api/chat", {"msg": "hello <i>x</i>", "persona": "soc"}, cookie=cookie, csrf=csrf)
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(body)["reply"], "مرحباً <b>بك</b>")           # JSON; the page renders it with text nodes
        sent = m.call_args[0][0]
        self.assertEqual(sent[0]["role"], "system")
        self.assertIn("SOC", sent[0]["content"])
        page = self.req("GET", "/", cookie=cookie)[2]
        init = re.search(r'id="init">(.*?)</script>', page, re.S).group(1)
        self.assertNotIn("<", init)                                                 # cannot break out of the JSON block
        self.assertEqual(json.loads(init)[0]["content"], "hello <i>x</i>")
        self.assertEqual(self.req("POST", "/api/clear", {}, cookie=cookie, csrf=csrf)[0], 200)
        self.assertEqual(json.loads(re.search(r'id="init">(.*?)</script>', self.req("GET", "/", cookie=cookie)[2], re.S).group(1)), [])

    def test_csrf_required(self):
        cookie, csrf = self.login()
        self.assertEqual(self.req("POST", "/api/chat", {"msg": "x"}, cookie=cookie)[0], 403)
        self.assertEqual(self.req("POST", "/api/chat", {"msg": "x"}, cookie=cookie, csrf="wrong")[0], 403)

    def test_history_capped_and_unknown_persona(self):
        cookie, csrf = self.login()
        with mock.patch.object(self.app.ai, "chat", return_value=("ok", {})) as m:
            for i in range(3):
                self.req("POST", "/api/chat", {"msg": f"q{i}", "persona": "../../etc"}, cookie=cookie, csrf=csrf)
        self.assertEqual([x["role"] for x in m.call_args[0][0]], ["system", "user", "assistant", "user", "assistant", "user"])
        self.assertIn("DARWIN", m.call_args[0][0][0]["content"])

    def test_rate_limit_per_session(self):
        cookie, csrf = self.login()
        with mock.patch.object(self.app.ai, "chat", return_value=("ok", {})) as m:
            codes = [self.req("POST", "/api/chat", {"msg": f"m{i}"}, cookie=cookie, csrf=csrf)[0] for i in range(14)]
        self.assertEqual(m.call_count, 12)
        self.assertEqual(codes[-1], 429)

    def test_api_error_is_reported_and_not_stored(self):
        cookie, csrf = self.login()
        with mock.patch.object(self.app.ai, "chat", side_effect=APIError(401, "revoked")):
            st, _, body = self.req("POST", "/api/chat", {"msg": "hi"}, cookie=cookie, csrf=csrf)
        self.assertEqual(st, 502)
        self.assertIn("error", json.loads(body))
        init = re.search(r'id="init">(.*?)</script>', self.req("GET", "/", cookie=cookie)[2], re.S).group(1)
        self.assertEqual(json.loads(init), [])                                       # a failed answer leaves no half-turn in the history
        self.assertFalse(self.site.sessions[cookie.split("=", 1)[1]]["busy"])

    def test_bad_json_and_oversize(self):
        cookie, csrf = self.login()
        self.assertEqual(self.req("POST", "/api/chat", raw="{not json", cookie=cookie, csrf=csrf)[0], 400)
        self.assertEqual(self.req("POST", "/api/chat", raw="[1]", cookie=cookie, csrf=csrf)[0], 400)
        self.assertEqual(self.req("POST", "/api/chat", raw="x" * 70000, cookie=cookie, csrf=csrf)[0], 413)
        self.assertEqual(self.req("POST", "/api/chat", {"msg": "   "}, cookie=cookie, csrf=csrf)[0], 400)

    def test_foreign_host_is_refused(self):
        self.assertEqual(self.req("GET", "/", host="evil.example")[0], 403)
        self.assertEqual(self.req("GET", "/healthz", host="evil.example")[0], 200)

    def test_logout_ends_session(self):
        cookie, csrf = self.login()
        self.req("POST", "/logout", {}, cookie=cookie, csrf=csrf)
        self.assertEqual(self.req("POST", "/api/chat", {"msg": "x"}, cookie=cookie, csrf=csrf)[0], 401)

    def test_admin_panel_has_no_chat_any_more(self):
        self.assertEqual(self.req("GET", "/chat")[0], 404)
        panel_routes = open("bot/webpanel.py", encoding="utf-8").read()
        self.assertNotIn("/chat", panel_routes)
        self.assertFalse(hasattr(WebPanel, "chat_send"))


class PublicMode(ChatBase):
    public = True

    def test_open_without_password_but_still_csrf_and_limits(self):
        st, hd, page = self.req("GET", "/")
        self.assertEqual(st, 200)
        cookie = hd["Set-Cookie"].split(";")[0]
        csrf = re.search(r'data-csrf="([^"]+)"', page).group(1)
        self.assertNotIn('id="out"', page)
        with mock.patch.object(self.app.ai, "chat", return_value=("hello", {})):
            self.assertEqual(self.req("POST", "/api/chat", {"msg": "x"}, cookie=cookie, csrf=csrf)[0], 200)
            self.assertEqual(self.req("POST", "/api/chat", {"msg": "x"}, cookie=cookie)[0], 403)

    def test_daily_cap(self):
        self.app.cfg = self.site.cfg = dataclasses.replace(self.app.cfg, web_chat_daily=2)
        st, hd, page = self.req("GET", "/")
        cookie, csrf = hd["Set-Cookie"].split(";")[0], re.search(r'data-csrf="([^"]+)"', page).group(1)
        with mock.patch.object(self.app.ai, "chat", return_value=("ok", {})) as m:
            codes = [self.req("POST", "/api/chat", {"msg": f"m{i}"}, cookie=cookie, csrf=csrf)[0] for i in range(4)]
        self.assertEqual(codes, [200, 200, 429, 429])
        self.assertEqual(m.call_count, 2)


class ConfigAndBot(unittest.TestCase):
    def test_passwords_differ_and_are_stable(self):
        tok = "123456789:ABCdefGHIjklMNOpqrsTUVwxyz0123456789"
        self.assertNotEqual(derive_chat_password(tok), derive_panel_password(tok))
        self.assertEqual(derive_chat_password(tok), derive_chat_password(tok))
        self.assertGreaterEqual(len(derive_chat_password(tok)), 16)

    def test_env_defaults_and_validation(self):
        env = {"TELEGRAM_TOKEN": "123456789:ABCdefGHIjklMNOpqrsTUVwxyz0123456789", "API_KEY": "k" * 20}
        with mock.patch.dict("os.environ", env, clear=True):
            cfg = Config.from_env()
        self.assertEqual(cfg.web_chat_port, 0)
        self.assertFalse(cfg.web_chat_public)
        self.assertEqual(cfg.web_chat_host, "127.0.0.1")
        self.assertEqual(cfg.validate(), [])
        same = dataclasses.replace(cfg, web_chat_port=8080, web_panel_port=8080, web_panel_token="x" * 12)
        self.assertTrue(any("WEB_CHAT_PORT" in p for p in same.validate()))
        self.assertNotIn(cfg.web_chat_password, cfg.all_keys())                  # site off: nothing extra to redact
        on = dataclasses.replace(cfg, web_chat_port=8090)
        self.assertIn(on.web_chat_password, on.all_keys())                       # site on: the password is scrubbed from logs


if __name__ == "__main__":
    unittest.main()


class AuditRegressions(ChatBase):
    def test_parallel_requests_in_one_session_run_one_at_a_time(self):
        import threading
        cookie, csrf = self.login()
        sess = self.site.sessions[cookie.split("=", 1)[1]]
        gate, started = threading.Event(), threading.Event()

        def slow(*a, **k):
            started.set()
            gate.wait(5)
            return "ok", {}
        res = []
        with mock.patch.object(self.app.ai, "chat", side_effect=slow) as m:
            t = threading.Thread(target=lambda: res.append(self.req("POST", "/api/chat", {"msg": "a"}, cookie=cookie, csrf=csrf)[0]))
            t.start()
            self.assertTrue(started.wait(5))
            self.assertEqual(self.req("POST", "/api/chat", {"msg": "b"}, cookie=cookie, csrf=csrf)[0], 409)
            # the check-and-set itself is atomic: a direct call while busy is refused too
            self.assertEqual(self.site.chat(sess, "default", "c", "127.0.0.1")[0], 409)
            gate.set()
            t.join(5)
        self.assertEqual(res, [200])
        self.assertEqual(m.call_count, 1)

    def test_clear_during_inflight_answer_is_not_resurrected(self):
        import threading
        cookie, csrf = self.login()
        gate, started = threading.Event(), threading.Event()

        def slow(*a, **k):
            started.set()
            gate.wait(5)
            return "late", {}
        with mock.patch.object(self.app.ai, "chat", side_effect=slow):
            t = threading.Thread(target=lambda: self.req("POST", "/api/chat", {"msg": "q"}, cookie=cookie, csrf=csrf))
            t.start()
            self.assertTrue(started.wait(5))
            self.assertEqual(self.req("POST", "/api/clear", {}, cookie=cookie, csrf=csrf)[0], 200)
            gate.set()
            t.join(5)
        self.assertEqual(self.site.sessions[cookie.split("=", 1)[1]]["chat"], [])

    def test_rejected_host_closes_the_connection(self):
        st, hd, _ = self.req("POST", "/api/chat", {"msg": "x"}, host="evil.example")
        self.assertEqual(st, 403)
        self.assertEqual(hd.get("Connection", "").lower(), "close")
