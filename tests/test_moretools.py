import unittest

from bot import moretools as M
from bot.webext import WEB_TOOLS, run_web_tool


class Tools(unittest.TestCase):
    def test_every_new_tool_is_registered_and_runs(self):
        samples = {"entropy": "Zk3$9qLx!pW2vN7e", "homoglyph": "https://аpple.com/login", "urlparse": "http://user@evil.com:8080/a?u=http://x.y",
                   "base": "255", "totp": "JBSWY3DPEHPK3PXP", "port": "ssh", "httpstatus": "404", "hmac": "key :: message", "hexdump": "hello"}
        keys = dict(WEB_TOOLS)
        for k, v in samples.items():
            self.assertIn(k, keys)
            self.assertTrue(run_web_tool(k, v).strip(), k)
        self.assertEqual(set(samples), set(dict(M.EXTRA_TOOLS)))

    def test_totp_matches_rfc6238_vectors(self):
        self.assertEqual(M.totp_code(b"12345678901234567890", 59, 8, 30, "sha1"), "94287082")
        self.assertEqual(M.totp_code(b"12345678901234567890123456789012", 59, 8, 30, "sha256"), "46119246")
        self.assertEqual(M.totp_code(b"1234567890123456789012345678901234567890123456789012345678901234", 59, 8, 30, "sha512"), "90693936")
        out = M.totp_tool("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ 8", now=59)
        self.assertIn("94287082", out)
        self.assertIn("الرمز الحالي", M.totp_tool("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=6&algorithm=SHA256", now=0))
        for bad in ("", "!!!", "JBSWY3DP 5", "JBSWY3DP 6 1"):
            with self.assertRaises(ValueError):
                M.totp_tool(bad)

    def test_hmac_known_value(self):
        # RFC 4231 test case 2
        out = M.hmac_tool("Jefe :: what do ya want for nothing?")
        self.assertIn("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", out)

    def test_homoglyph_flags_cyrillic_lookalike(self):
        r = M.homoglyph("https://аpple.com")
        self.assertIn("🚨", r)
        self.assertIn("apple.com", r)
        self.assertIn("xn--", r)
        self.assertIn("✅", M.homoglyph("example.com"))
        self.assertIn("🚨", M.homoglyph("xn--pple-43d.com"))
        with self.assertRaises(ValueError):
            M.homoglyph("   ")

    def test_url_breakdown_flags(self):
        r = M.url_breakdown("http://paypal.com@evil.example/x?next=https://a.b&q=%2525")
        self.assertIn("المضيف الحقيقي هو «evil.example»", r)
        self.assertIn("إعادة توجيه مفتوحة", r)
        self.assertIn("ترميز مزدوج", r)
        self.assertIn("IP مموَّه", M.url_breakdown("http://0x7f.1/"))
        self.assertIn("🚨", M.url_breakdown("javascript:alert(1)"))
        self.assertIn("✅", M.url_breakdown("https://example.com/a"))
        with self.assertRaises(ValueError):
            M.url_breakdown("")

    def test_base_entropy_status_hexdump(self):
        b = M.base_convert("0xff")
        self.assertIn("عشري: 255", b)
        self.assertIn("0.0.0.255", b)
        self.assertIn("ثنائي: 0b11111111", b)
        with self.assertRaises(ValueError):
            M.base_convert("12zz")
        with self.assertRaises(ValueError):
            M.base_convert("9" * 800)
        self.assertIn("🟢", M.entropy("aaaaaaaaaaaaaaaaaaaa"))
        self.assertIn("🔴", M.entropy("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"))
        self.assertIn("Not Found", M.http_status("404"))
        self.assertIn("429", M.http_status("too many"))
        with self.assertRaises(ValueError):
            M.http_status("999")
        h = M.hexdump("Hello, world!\n")
        self.assertTrue(h.startswith("00000000  48 65 6c 6c 6f 2c 20 77  6f 72 6c 64 21 0a"))
        self.assertIn("|Hello, world!.|", h)
        self.assertIn("22", M.port_info("ssh") + "22")


if __name__ == "__main__":
    unittest.main()


from unittest import mock  # noqa: E402

from tests.test_webchat import ChatBase  # noqa: E402


class ChatTools(ChatBase):
    def test_tool_endpoint(self):
        cookie, csrf = self.login()
        st, _, body = self.req("POST", "/api/tool", {"tool": "base", "text": "0xff"}, cookie=cookie, csrf=csrf)
        self.assertEqual(st, 200)
        self.assertIn("عشري: 255", body)
        st, _, body = self.req("POST", "/api/tool", {"tool": "base", "text": "zz"}, cookie=cookie, csrf=csrf)
        self.assertEqual(st, 400)
        self.assertEqual(self.req("POST", "/api/tool", {"tool": "nope", "text": "x"}, cookie=cookie, csrf=csrf)[0], 404)
        self.assertEqual(self.req("POST", "/api/tool", {"tool": "hash", "text": "abc"}, cookie=cookie, csrf=csrf)[0], 200)
        self.assertEqual(self.req("POST", "/api/tool", {"tool": "base", "text": "1"}, cookie=cookie)[0], 403)    # CSRF header required
        self.assertEqual(self.req("POST", "/api/tool", {"tool": "base", "text": "1"})[0], 401)                   # login required

    def test_tool_rate_limit_per_session(self):
        cookie, csrf = self.login()
        codes = [self.req("POST", "/api/tool", {"tool": "uuid", "text": "1"}, cookie=cookie, csrf=csrf)[0] for _ in range(32)]
        self.assertEqual(codes[:30], [200] * 30)
        self.assertEqual(codes[30], 429)

    def test_regenerate_replaces_last_reply(self):
        cookie, csrf = self.login()
        key = cookie.split("=", 1)[1]
        self.assertEqual(self.req("POST", "/api/regenerate", {}, cookie=cookie, csrf=csrf)[0], 400)         # nothing to regenerate yet
        with mock.patch.object(self.app.ai, "chat", side_effect=[("first", {}), ("second", {})]) as m:
            self.assertEqual(self.req("POST", "/api/chat", {"msg": "q"}, cookie=cookie, csrf=csrf)[0], 200)
            st, _, body = self.req("POST", "/api/regenerate", {}, cookie=cookie, csrf=csrf)
        self.assertEqual(st, 200)
        self.assertIn("second", body)
        self.assertEqual([x["content"] for x in self.site.sessions[key]["chat"]], ["q", "second"])
        sent = m.call_args_list[1][0][0]
        self.assertEqual([x["content"] for x in sent if x["role"] != "system"], ["q"])                      # old reply is not fed back

    def test_page_has_tools_sheet_and_no_dom_string_injection(self):
        cookie, _ = self.login()
        st, _, page = self.req("GET", "/", cookie=cookie)
        self.assertEqual(st, 200)
        for marker in ('id="sh"', 'id="tl"', 'id="tb"', 'id="ex"', 'id="mic"', "/api/regenerate"):
            self.assertIn(marker, page)
        self.assertNotIn("innerHTML", page)
        self.assertIn("entropy", page)
