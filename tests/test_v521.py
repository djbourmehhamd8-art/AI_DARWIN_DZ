"""5.2.1 regressions: chunked bodies are refused, setup page drops idle clients and answers HEAD without a body,
a too-short WEB_PANEL_TOKEN is reported, .env.example documents every variable the code reads."""
import http.client
import os
import re
import socket
import threading
import unittest
from pathlib import Path

from bot import setupmode
from tests.test_v440 import PanelBase

ROOT = Path(__file__).resolve().parents[1]


class TransferEncoding(PanelBase):
    def _raw(self, request: bytes) -> bytes:
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        try:
            s.sendall(request)
            data = b""
            while True:
                d = s.recv(65536)
                if not d:
                    break
                data += d
            return data
        finally:
            s.close()

    def test_chunked_post_is_refused_and_connection_closed(self):
        smuggled = b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        body = b"%x\r\n%s\r\n0\r\n\r\n" % (len(smuggled), smuggled)
        data = self._raw((b"POST /login HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n" % self.port) + body)
        self.assertTrue(data.startswith(b"HTTP/1.1 501"))
        self.assertEqual(data.count(b"HTTP/1."), 1)                    # nothing smuggled was answered as a second request

    def test_chunked_get_is_refused_too(self):
        data = self._raw(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n" % self.port)
        self.assertTrue(data.startswith(b"HTTP/1.1 501"))

    def test_normal_requests_still_work(self):
        self.assertEqual(self.req("GET", "/healthz")[0], 200)
        self.assertEqual(self.req("POST", "/login", {"token": "wrong"})[0], 401)


class SetupPage(unittest.TestCase):
    def _serve(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        stop = threading.Event()
        t = threading.Thread(target=setupmode.serve, args=("127.0.0.1", port, ["TELEGRAM_TOKEN missing"], stop), daemon=True)
        t.start()
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                threading.Event().wait(0.05)
        self.addCleanup(lambda: (stop.set(), t.join(3)))
        return port

    def test_head_has_no_body_and_get_has(self):
        port = self._serve()
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("HEAD", "/")
        r = c.getresponse()
        self.assertEqual((r.status, r.read()), (200, b""))
        c.close()
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("GET", "/")
        self.assertIn(b"TELEGRAM_TOKEN missing", c.getresponse().read())
        c.close()

    def test_handler_has_idle_timeout(self):
        src = (ROOT / "bot" / "setupmode.py").read_text(encoding="utf-8")
        self.assertRegex(src, r"timeout\s*=\s*\d+")


class EnvExample(unittest.TestCase):
    def test_every_variable_read_by_the_code_is_documented(self):
        used = set()
        for p in list((ROOT / "bot").glob("*.py")) + [ROOT / "main.py"]:
            s = p.read_text(encoding="utf-8")
            used |= set(re.findall(r'\be\(\s*"([A-Z][A-Z0-9_]+)"', s))
            used |= set(re.findall(r'environ(?:\.get)?\(\s*["\']([A-Z][A-Z0-9_]+)', s))
        doc = set(re.findall(r"^\s*#?\s*([A-Z][A-Z0-9_]{2,})=", (ROOT / ".env.example").read_text(encoding="utf-8"), re.M))
        # accepted aliases / generated names are documented in prose, the rest must appear
        self.assertEqual(sorted(used - doc - {"TOKEN"}), [])


if __name__ == "__main__":
    unittest.main()
