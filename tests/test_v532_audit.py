"""Regressions for the deep audit (formatting placeholder forgery)."""
import unittest

from bot import formatting as F


class PlaceholderForgery(unittest.TestCase):
    def test_nul_placeholder_in_text_cannot_crash_or_swap_code(self):
        self.assertNotIn("\x00", F.to_html("hello \x005\x00 world"))
        out = F.to_html("`real` and \x000\x00 fake")
        self.assertEqual(out.count("<code>"), 1)

    def test_normal_markup_still_renders(self):
        self.assertIn("<b>x</b>", F.to_html("**x**"))
        self.assertIn("<code>a</code>", F.to_html("use `a` here"))


if __name__ == "__main__":
    unittest.main()


import dataclasses  # noqa: E402

from tests.test_v34 import Harness  # noqa: E402


class WebchatButton(Harness):
    __test__ = True

    def _send(self, **cfg):
        self.app.cfg = dataclasses.replace(self.app.cfg, web_chat_port=8090, web_chat_password="pw-12345678", **cfg)
        user = self.app._user({"id": 1, "first_name": "A"})
        self.app.show_webchat(1, user)
        return self.calls("sendMessage")[-1]

    def test_local_address_is_text_not_a_url_button(self):
        p = self._send(web_chat_url="")
        self.assertIn("http://127.0.0.1:8090", p["text"])
        self.assertNotIn("127.0.0.1:8090", str(p.get("reply_markup", {})))     # Telegram refuses localhost URL buttons

    def test_public_https_address_keeps_the_button(self):
        p = self._send(web_chat_url="https://chat.example.com")
        self.assertIn("https://chat.example.com", str(p.get("reply_markup", {})))


import http.client  # noqa: E402
import socket  # noqa: E402
import threading  # noqa: E402

from bot.hardening import LimitedHTTPServer, cross_site  # noqa: E402
from bot.proutils import regex_test  # noqa: E402
from tests.test_webchat import ChatBase  # noqa: E402


class ServerLimits(unittest.TestCase):
    def test_connection_cap_answers_503_and_recovers(self):
        from http.server import BaseHTTPRequestHandler

        class H(BaseHTTPRequestHandler):
            timeout = 5

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

        class Tiny(LimitedHTTPServer):
            max_connections = 2

        srv = Tiny(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        port = srv.server_address[1]
        idle = [socket.create_connection(("127.0.0.1", port)) for _ in range(2)]   # two idle sockets hold both slots
        try:
            import time
            time.sleep(0.3)
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", "/")
            self.assertEqual(c.getresponse().status, 503)
            c.close()
            for s in idle:
                s.close()
            time.sleep(0.5)
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", "/")
            self.assertEqual(c.getresponse().status, 200)
            c.close()
        finally:
            srv.shutdown()
            srv.server_close()

    def test_cross_site_header_logic(self):
        self.assertFalse(cross_site({}))
        self.assertFalse(cross_site({"Sec-Fetch-Site": "same-origin"}))
        self.assertFalse(cross_site({"Sec-Fetch-Site": "none"}))
        self.assertTrue(cross_site({"Sec-Fetch-Site": "cross-site"}))
        self.assertTrue(cross_site({"Sec-Fetch-Site": "same-site"}))

    def test_regex_sandbox_still_works_with_limits(self):
        self.assertEqual(regex_test(r"(\d+)-(\d+) :: a 12-34 b")["count"], 1)


class WebchatCrossSite(ChatBase):
    def test_cross_site_post_is_refused_but_same_origin_works(self):
        cookie, csrf = self.login()
        st, hd, _ = self.req("POST", "/api/clear", {}, cookie=cookie, csrf=csrf, headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(st, 403)
        self.assertEqual(hd.get("Connection", "").lower(), "close")
        st, _, _ = self.req("POST", "/api/clear", {}, cookie=cookie, csrf=csrf, headers={"Sec-Fetch-Site": "same-origin"})
        self.assertEqual(st, 200)
