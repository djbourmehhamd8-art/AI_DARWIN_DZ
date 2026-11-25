"""v4.5.0: extra tools, AI chat / tools / audit / system pages in the web panel, menu buttons."""
import re
import unittest
from unittest import mock

from bot import proutils as P
from bot.ai_client import APIError
from bot.utildata import UTIL_KINDS
from bot.webext import WEB_TOOLS, run_web_tool
from tests import test_integration as ti
from tests.test_v34 import Harness
from tests.test_v440 import PanelBase
from tests.test_ui import cb, message


class PureTools(unittest.TestCase):
    def test_calc(self):
        self.assertEqual(P.calc("2^10 + sqrt(16)*3"), 1036)
        self.assertEqual(P.calc("10/4"), 2.5)
        self.assertEqual(P.calc("(12+8)*3"), 60)

    def test_calc_rejects_code(self):
        for bad in ("__import__('os').system('id')", "9**9**9", "1/0", "open('x')", "a", "[1]*10**9", "(lambda:1)()", ""):
            with self.assertRaises(ValueError, msg=bad):
                P.calc(bad)

    def test_units_percent(self):
        self.assertAlmostEqual(P.convert_units("10 km to mi")["result"], 6.21371192, places=6)
        self.assertEqual(P.convert_units("100 c to f")["result"], 212.0)
        self.assertEqual(P.percent("15% of 200")["text"], "15% of 200 = 30")
        with self.assertRaises(ValueError):
            P.convert_units("10 kg to km")

    def test_json_regex_color(self):
        self.assertEqual(P.json_pretty('{"a":[1,2]}')["type"], "dict")
        with self.assertRaises(ValueError):
            P.json_pretty("{bad")
        self.assertEqual(P.regex_test(r"\d+ :: a12b345")["count"], 2)
        for evil in ("(a+)+$ :: aaaa", "(a|aa)+ :: aaaa"):
            with self.assertRaises(ValueError):
                P.regex_test(evil)
        self.assertEqual(P.color_convert("#1f6feb")["rgb"], "rgb(31, 111, 235)")
        self.assertEqual(P.color_convert("#fff")["hex"], "#ffffff")

    def test_generators(self):
        pw = P.make_password(24)
        self.assertEqual(len(pw), 24)
        self.assertTrue(any(c.isdigit() for c in pw) and any(c.isupper() for c in pw))
        self.assertEqual(len(P.make_uuids(99)), 10)
        self.assertEqual(len(P.rand_roll("3d6")["rolls"]), 3)
        self.assertTrue(1 <= P.rand_roll("6")["result"] <= 6)
        self.assertEqual(P.slugify("Hello, World!"), "hello-world")
        self.assertEqual(P.b64("hello")["result"], "aGVsbG8=")
        self.assertEqual(P.b64("aGVsbG8=")["result"], "hello")
        self.assertEqual(P.dedupe_sort("b\na\nb\n")["unique"], 2)

    def test_every_web_tool_runs(self):
        samples = {"calc": "1+1", "unit": "1 km to m", "pct": "10% of 50", "json": "[1]", "regex": r"\d :: a1", "textstat": "a b c",
                   "uniq": "x\nx", "b64": "hi", "urlenc": "a b", "color": "#000", "caseconv": "foo bar", "slug": "A b",
                   "roll": "6", "uuid": "2", "genpass": "16",
                   "hash": "hello", "pass": "abc12345", "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.x",
                   "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "decode": "aGVsbG8=", "ts": "1700000000",
                   "ioc": "http://evil.com 1.2.3.4",
                   "csp": "script-src 'self'", "cookie": "a=b; Secure", "secheaders": "X-Frame-Options: DENY",
                   "subnet": "10.0.0.0/24", "cron": "* * * * *",
                   "spf": "v=spf1 -all", "dmarc": "v=DMARC1; p=reject", "secrets": "x=1", "sri": "a", "chmod": "755",
                   "cidrmatch": "1.1.1.1 in 1.0.0.0/8", "ipconv": "1.1.1.1", "useragent": "curl/8.0", "diff": "a\n---\nb", "date": "2026-01-01",
                   # v5.4.0 (bot/moretools.py)
                   "entropy": "Zk3$9qLx!pW2vN7e", "homoglyph": "example.com", "urlparse": "https://example.com/a?b=1", "base": "255",
                   "totp": "JBSWY3DPEHPK3PXP", "port": "443", "httpstatus": "404", "hmac": "k :: m", "hexdump": "hi"}
        self.assertEqual(set(samples), {k for k, _ in WEB_TOOLS})
        for k, v in samples.items():
            self.assertTrue(run_web_tool(k, v), k)


class BotButtons(Harness):
    __test__ = True

    def setUp(self):
        super().setUp()
        self.db.upsert_user(1, "admin", "Admin")

    def test_main_menu_has_new_buttons(self):
        self.app.on_message(message(1, "/menu"))
        btns = self.buttons()
        self.assertIn("h:home", btns)                      # the hub replaced the flat tool buttons on the main menu
        self.app.on_callback(cb(1, "h:home"))
        for b in ("m:tools", "m:utils", "m:wc", "m:toolkit"):
            self.assertIn(b, self.buttons())

    def test_utils_menu_lists_every_tool(self):
        self.app.on_callback(cb(1, "m:utils"))
        btns = self.buttons()
        for k in UTIL_KINDS:
            self.assertIn(f"t:{k}", btns)

    def test_calc_command_and_button_flow(self):
        self.app.on_message(message(1, "/calc 2+3*4"))
        self.assertIn("14", self.texts())
        ti.CALLS.clear()
        self.app.on_callback(cb(1, "t:calc"))
        self.app.on_message(message(1, "(1+2)*5"))
        self.assertIn("15", self.texts())

    def test_bad_input_shows_hint_not_crash(self):
        self.app.on_message(message(1, "/calc __import__('os')"))
        self.assertIn("🧮", self.texts())
        self.app.on_message(message(1, "/regex (a+)+$ :: aaaa"))
        self.assertIn("⚠️", self.texts())

    def test_webchat_button_url_only_for_admin(self):
        import dataclasses
        self.app.cfg = dataclasses.replace(self.app.cfg, web_chat_port=8090, web_chat_url="https://chat.example.org", web_chat_public=True)
        self.app.on_callback(cb(1, "m:wc"))
        urls = [b.get("url") for p in self.calls("sendMessage", "editMessageText")
                for row in (p.get("reply_markup") or {}).get("inline_keyboard", []) for b in row]
        self.assertIn("https://chat.example.org", urls)

    def test_webchat_without_panel_explains(self):
        self.app.on_message(message(1, "/webchat"))
        self.assertIn("WEB_CHAT_PORT", self.texts())


class WebPages(PanelBase):
    def get(self, cookie, path):
        return self.req("GET", path, cookie=cookie)

    def test_pages_need_login(self):
        for path in ("/tools", "/audit", "/system"):
            self.assertEqual(self.req("GET", path)[0], 303, path)
        for path in ("/tools/run",):
            self.assertEqual(self.req("POST", path, {"msg": "x"})[0], 403, path)

    def test_nav_and_pages_render(self):
        c = self.login()
        for path in ("/", "/tools", "/audit", "/system"):
            st, _, body = self.get(c, path)
            self.assertEqual(st, 200, path)
            self.assertNotIn('href="/chat"', body)             # the AI chat is its own website now
        self.assertIn("حالة النظام", self.get(c, "/system")[2])





    def test_tools_run(self):
        c = self.login()
        csrf = self.csrf(c)
        self.req("POST", "/tools/run", {"csrf": csrf, "tool": "calc", "text": "6*7"}, cookie=c)
        self.assertIn("= 42", self.get(c, "/tools")[2])
        self.req("POST", "/tools/run", {"csrf": csrf, "tool": "calc", "text": "__import__('os')"}, cookie=c)
        self.assertIn("⚠️", self.get(c, "/tools")[2])
        self.req("POST", "/tools/run", {"csrf": csrf, "tool": "rm -rf", "text": "x"}, cookie=c)
        self.assertIn("أداة غير معروفة", self.get(c, "/tools")[2])

    def test_audit_page_escapes(self):
        self.db.add_audit(0, "<script>x</script>", "d")
        c = self.login()
        body = self.get(c, "/audit")[2]
        self.assertNotIn("<script>x</script>", body)
        self.assertIn("&lt;script&gt;", body)



if __name__ == "__main__":
    unittest.main()
